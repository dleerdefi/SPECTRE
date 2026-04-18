"""Remote hashcat cracking via SSH."""

from __future__ import annotations

import logging
import subprocess
import time
from pathlib import Path
from typing import List, Optional, Tuple

from wifi_launchpad.domain.capture import CrackResult

logger = logging.getLogger(__name__)


def check_remote(host: str, hashcat_bin: str = "hashcat") -> Tuple[bool, str]:
    """Verify SSH connectivity and hashcat availability on remote host."""
    try:
        result = subprocess.run(
            ["ssh", "-o", "ConnectTimeout=10", "-o", "BatchMode=yes",
             host, f"which {hashcat_bin} && {hashcat_bin} --version && {hashcat_bin} -I 2>&1"],
            capture_output=True, text=True, timeout=20,
        )
        if result.returncode != 0:
            return False, f"SSH or hashcat check failed: {result.stderr.strip()}"
        return True, result.stdout.strip()
    except subprocess.TimeoutExpired:
        return False, "SSH connection timed out"
    except Exception as exc:
        return False, str(exc)


def remote_crack(
    hash_file: str,
    wordlists: List[str],
    host: str,
    *,
    hashcat_bin: str = "hashcat",
    remote_dir: str = "/tmp/spectre-crack",
    rules: Optional[str] = None,
    attack_mode: int = 0,
    timeout: Optional[int] = None,
    extra_flags: Optional[List[str]] = None,
) -> CrackResult:
    """Crack a hash file on a remote machine via SSH."""
    if not Path(hash_file).exists():
        return CrackResult(cracked=False, hash_file=hash_file)

    valid_wordlists = [w for w in wordlists if Path(w).exists()]
    if not valid_wordlists and attack_mode == 0:
        return CrackResult(cracked=False, hash_file=hash_file)

    subprocess.run(["ssh", host, f"mkdir -p {remote_dir}"], capture_output=True, timeout=10)

    remote_hash = f"{remote_dir}/{Path(hash_file).name}"
    subprocess.run(["scp", "-q", hash_file, f"{host}:{remote_hash}"], capture_output=True, timeout=30)

    remote_wl_paths = []
    for wl in valid_wordlists:
        remote_wl = f"{remote_dir}/{Path(wl).name}"
        subprocess.run(["scp", "-q", wl, f"{host}:{remote_wl}"], capture_output=True, timeout=120)
        remote_wl_paths.append(remote_wl)

    remote_outfile = f"{remote_dir}/cracked_{Path(hash_file).stem}.txt"
    cmd_parts = [
        hashcat_bin, "-m", "22000", "-a", str(attack_mode),
        remote_hash, *remote_wl_paths,
        "--potfile-disable", "-o", remote_outfile,
    ]
    if rules and Path(rules).exists():
        remote_rules = f"{remote_dir}/{Path(rules).name}"
        subprocess.run(["scp", "-q", rules, f"{host}:{remote_rules}"], capture_output=True, timeout=30)
        cmd_parts.extend(["-r", remote_rules])
    if extra_flags:
        cmd_parts.extend(extra_flags)

    remote_cmd = " ".join(cmd_parts)
    logger.info("Remote hashcat on %s: %s", host, remote_cmd)

    started = time.time()
    try:
        subprocess.run(["ssh", host, remote_cmd], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return CrackResult(cracked=False, hash_file=hash_file, crack_time=time.time() - started, method="timeout")
    except Exception as exc:
        logger.error("Remote hashcat error: %s", exc)
        return CrackResult(cracked=False, hash_file=hash_file)

    elapsed = time.time() - started

    password = None
    try:
        cat = subprocess.run(
            ["ssh", host, f"cat {remote_outfile} 2>/dev/null"],
            capture_output=True, text=True, timeout=10,
        )
        for line in cat.stdout.strip().splitlines():
            if ":" in line:
                password = line.rsplit(":", 1)[-1]
                break
    except Exception:
        pass

    subprocess.run(["ssh", host, f"rm -rf {remote_dir}"], capture_output=True, timeout=10)

    if password:
        logger.info("Remote crack successful in %.1fs", elapsed)
        method = "remote-rules" if rules else "remote-dictionary"
        return CrackResult(
            cracked=True, password=password, hash_file=hash_file,
            wordlist_used=valid_wordlists[0] if valid_wordlists else None,
            crack_time=elapsed, method=method,
        )

    return CrackResult(
        cracked=False, hash_file=hash_file,
        wordlist_used=valid_wordlists[0] if valid_wordlists else None,
        crack_time=elapsed, method="remote-exhausted",
    )
