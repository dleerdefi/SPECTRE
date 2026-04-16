"""Hashcat cracking engine wrapper."""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import List, Optional, Tuple

from wifi_launchpad.app.settings import get_settings
from wifi_launchpad.domain.capture import CrackResult

logger = logging.getLogger(__name__)


class HashcatProvider:
    """Crack WPA/WPA2 hashes using hashcat."""

    def __init__(self, output_dir: Optional[Path] = None):
        self.output_dir = Path(output_dir or get_settings().crack_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def is_available() -> bool:
        """Return whether hashcat is installed."""
        return bool(shutil.which("hashcat"))

    def crack(
        self,
        hash_file: str,
        wordlists: List[str],
        *,
        rules: Optional[str] = None,
        attack_mode: int = 0,
        timeout: Optional[int] = None,
    ) -> CrackResult:
        """Run hashcat against a hash file with the given wordlists.

        Args:
            hash_file: Path to .22000 hash file
            wordlists: Paths to wordlist files
            rules: Optional hashcat rule file path
            attack_mode: 0=dictionary, 3=brute-force, 6=hybrid-wordlist+mask
            timeout: Max seconds to run (None = unlimited)

        Returns:
            CrackResult with cracked status and password if found
        """
        if not self.is_available():
            return CrackResult(cracked=False, hash_file=hash_file, method="unavailable")

        if not Path(hash_file).exists():
            logger.error("Hash file does not exist: %s", hash_file)
            return CrackResult(cracked=False, hash_file=hash_file)

        valid_wordlists = [w for w in wordlists if Path(w).exists()]
        if not valid_wordlists and attack_mode == 0:
            logger.error("No valid wordlists provided")
            return CrackResult(cracked=False, hash_file=hash_file)

        outfile = self.output_dir / f"cracked_{Path(hash_file).stem}.txt"

        cmd = [
            "hashcat",
            "-m", "22000",
            "-a", str(attack_mode),
            hash_file,
            *valid_wordlists,
            "--potfile-disable",
            "-o", str(outfile),
            "--quiet",
        ]

        if rules and Path(rules).exists():
            cmd.extend(["-r", rules])

        logger.info("Running hashcat: %s", " ".join(cmd))
        started = time.time()

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            logger.warning("Hashcat timeout after %ds", timeout)
            elapsed = time.time() - started
            return CrackResult(
                cracked=False,
                hash_file=hash_file,
                crack_time=elapsed,
                method="timeout",
            )
        except Exception as exc:
            logger.error("Hashcat error: %s", exc)
            return CrackResult(cracked=False, hash_file=hash_file)

        elapsed = time.time() - started

        # hashcat exit codes: 0=cracked, 1=exhausted, 255=error, -1/other=various
        password = self._read_cracked_password(outfile)
        if password:
            logger.info("Password cracked in %.1fs", elapsed)
            method = "dictionary"
            if rules:
                method = "rules"
            if attack_mode == 3:
                method = "brute-force"
            elif attack_mode == 6:
                method = "hybrid"

            return CrackResult(
                cracked=True,
                password=password,
                hash_file=hash_file,
                wordlist_used=valid_wordlists[0] if valid_wordlists else None,
                crack_time=elapsed,
                method=method,
            )

        logger.info("Hashcat exhausted wordlists in %.1fs (no crack)", elapsed)
        return CrackResult(
            cracked=False,
            hash_file=hash_file,
            wordlist_used=valid_wordlists[0] if valid_wordlists else None,
            crack_time=elapsed,
            method="exhausted",
        )

    def _read_cracked_password(self, outfile: Path) -> Optional[str]:
        """Parse hashcat output file for the cracked password."""
        if not outfile.exists() or outfile.stat().st_size == 0:
            return None
        try:
            # hashcat -o format: hash:password (one per line)
            for line in outfile.read_text(encoding="utf-8", errors="replace").splitlines():
                if ":" in line:
                    return line.rsplit(":", 1)[-1]
        except Exception as exc:
            logger.debug("Failed to read cracked password: %s", exc)
        return None

    def show_status(self, hash_file: str) -> Optional[str]:
        """Check if a hash was previously cracked in hashcat's potfile."""
        try:
            result = subprocess.run(
                ["hashcat", "-m", "22000", hash_file, "--show", "--quiet"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.stdout.strip():
                return result.stdout.strip().rsplit(":", 1)[-1]
        except Exception:
            pass
        return None
