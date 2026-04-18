"""Cracking orchestration service."""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from wifi_launchpad.app.settings import get_settings
from wifi_launchpad.domain.capture import CrackResult, Handshake
from wifi_launchpad.domain.evidence import EvidenceArtifact
from wifi_launchpad.domain.jobs import JobRecord, JobStatus, JobType
from wifi_launchpad.providers.external.hashcat import HashcatProvider
from wifi_launchpad.providers.native.capture.validation import HandshakeValidator

logger = logging.getLogger(__name__)


class CrackService:
    """Orchestrates the capture-to-crack pipeline."""

    def __init__(self, output_dir: Optional[Path] = None):
        self.settings = get_settings()
        self.output_dir = Path(output_dir or self.settings.capture_dir)
        self.hashcat = HashcatProvider(output_dir=self.output_dir)
        self.validator = HandshakeValidator()

    def crack_hash(
        self,
        hash_file: str,
        wordlists: Optional[List[str]] = None,
        rules: Optional[str] = None,
        timeout: Optional[int] = None,
        extra_flags: Optional[List[str]] = None,
        remote: Optional[bool] = None,
    ) -> CrackResult:
        """Crack a .22000 hash file locally or on a remote GPU host.

        When *remote* is True (or None with ``CRACK_HOST`` set), the hash
        file and wordlists are SCP'd to the remote machine and hashcat
        runs there via SSH.
        """
        if wordlists is None:
            wordlists = self._build_wordlist_chain()

        use_remote = remote if remote is not None else bool(self.settings.crack.remote_host)

        if use_remote:
            host = self.settings.crack.remote_host
            if not host:
                logger.error("Remote cracking requested but CRACK_HOST not set")
                return CrackResult(cracked=False, hash_file=hash_file)
            from wifi_launchpad.providers.external.hashcat_remote import remote_crack
            return remote_crack(
                hash_file=hash_file,
                wordlists=wordlists,
                host=host,
                hashcat_bin=self.settings.crack.remote_hashcat,
                remote_dir=self.settings.crack.remote_temp_dir,
                rules=rules,
                timeout=timeout,
                extra_flags=extra_flags,
            )

        return self.hashcat.crack(
            hash_file=hash_file,
            wordlists=wordlists,
            rules=rules,
            timeout=timeout,
            extra_flags=extra_flags,
        )

    def crack_handshake(
        self,
        handshake: Handshake,
        wordlists: Optional[List[str]] = None,
        rules: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> CrackResult:
        """Crack a captured handshake — exports to hc22000 first if needed."""
        # If capture came from HCX, a .22000 file may already exist alongside the pcap
        hash_file = self._find_or_export_hash(handshake)
        if not hash_file:
            logger.error("Could not produce hash file for cracking")
            return CrackResult(cracked=False, method="export-failed")

        result = self.crack_hash(
            hash_file=hash_file,
            wordlists=wordlists,
            rules=rules,
            timeout=timeout,
        )

        if result.cracked:
            handshake.cracked = True
            handshake.password = result.password
            handshake.crack_time = result.crack_time
            handshake.crack_method = result.method

        return result

    def auto_crack_directory(
        self,
        directory: Optional[str] = None,
        timeout_per_file: Optional[int] = None,
    ) -> List[CrackResult]:
        """Find all .22000 files in a directory and crack them."""
        timeout_per_file = timeout_per_file or self.settings.crack.timeout_per_file
        search_dir = Path(directory or self.settings.capture_dir)
        hash_files = sorted(search_dir.glob("*.22000"))

        if not hash_files:
            logger.info("No .22000 files found in %s", search_dir)
            return []

        results = []
        for hf in hash_files:
            logger.info("Cracking %s", hf.name)
            result = self.crack_hash(str(hf), timeout=timeout_per_file)
            results.append(result)

        return results

    def build_job_record(self, result: CrackResult) -> JobRecord:
        """Create a JobRecord for a cracking operation."""
        return JobRecord(
            job_type=JobType.CRACK,
            status=JobStatus.COMPLETED if result.cracked else JobStatus.FAILED,
            started_at=datetime.now(),
            finished_at=datetime.now(),
            provider="hashcat",
            target=result.hash_file,
            details=result.to_dict(),
        )

    def build_artifact(self, result: CrackResult) -> Optional[EvidenceArtifact]:
        """Create an EvidenceArtifact if cracking succeeded."""
        if not result.cracked:
            return None
        return EvidenceArtifact(
            artifact_id=f"crack-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            kind="crack-result",
            source_tool="hashcat",
            created_at=datetime.now(),
            immutable=True,
            path=result.hash_file,
            validation_status="complete",
            metadata={
                "password": result.password,
                "method": result.method,
                "crack_time": result.crack_time,
                "wordlist": result.wordlist_used,
            },
        )

    def _find_or_export_hash(self, handshake: Handshake) -> Optional[str]:
        """Find an existing .22000 file or export from pcap."""
        pcap = Path(handshake.pcap_file)

        # Check for existing .22000 alongside pcap (HCX captures produce these)
        hash_candidates = [
            pcap.with_suffix(".22000"),
            pcap.parent / f"{pcap.stem}.22000",
        ]
        for candidate in hash_candidates:
            if candidate.exists() and candidate.stat().st_size > 0:
                return str(candidate)

        # Export from pcap using hcxpcapngtool
        hash_file = str(pcap.with_suffix(".22000"))
        if self.validator.export_for_cracking(str(pcap), hash_file, format="hc22000"):
            return hash_file

        return None

    def _build_wordlist_chain(self) -> List[str]:
        """Build a prioritized list of wordlist paths."""
        wordlists = []
        wl_dir = self.settings.wordlist_dir

        # Master wordlist first (deduplicated union of all categories)
        master = wl_dir / "master-wifi-wordlist.txt"
        if master.exists():
            wordlists.append(str(master))

        # Then category directories by priority
        for category in ["targeted", "default-passwords", "isp-specific", "generated"]:
            cat_dir = wl_dir / category
            if cat_dir.is_dir():
                for wl in sorted(cat_dir.glob("*.txt")):
                    path = str(wl)
                    if path not in wordlists:
                        wordlists.append(path)

        return wordlists
