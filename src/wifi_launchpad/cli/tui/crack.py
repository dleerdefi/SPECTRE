"""SPECTRE TUI — Crack Hashes menu."""

import os
from pathlib import Path

from wifi_launchpad.cli.common import console
from wifi_launchpad.cli.tui.helpers import prompt, pause, divider, info, warn, error, success

_profiles = {
    "a": {"label": "CPU only",   "flags": ["--force", "-D", "1", "-w", "1"]},
    "b": {"label": "GPU",        "flags": ["-D", "2", "-w", "3"]},
}
_current_profile = "b"
_remote_mode = False
_remote_host = ""


def crack_menu():
    global _remote_mode, _remote_host

    from wifi_launchpad.app.settings import get_settings
    settings = get_settings()

    if settings.crack.remote_host and not _remote_host:
        _remote_host = settings.crack.remote_host
        _remote_mode = True

    while True:
        divider("CRACK HASHES")
        prof = _profiles[_current_profile]["label"]
        if _remote_mode and _remote_host:
            loc = f"[green]Remote ({_remote_host})[/green]"
        else:
            loc = "[yellow]Local[/yellow]"
        console.print(
            f"  [green][1][/green] Crack specific hash file\n"
            f"  [green][2][/green] Auto-crack all in capture dir\n"
            f"  [green][3][/green] Hardware profile  [dim]({prof})[/dim]\n"
            f"  [green][4][/green] Crack location    {loc}\n"
            f"  [green][5][/green] Back\n"
        )
        choice = prompt("spectre/crack")

        if choice == "1":
            path = prompt("Path to .22000 hash file")
            if path and Path(path).exists():
                _run_crack(path)
            else:
                error(f"File not found: {path}")
        elif choice == "2":
            _run_auto_crack()
        elif choice == "3":
            _profile_menu()
        elif choice == "4":
            _location_menu()
        elif choice == "5":
            return
        else:
            warn("Invalid choice.")


def _run_crack(hash_file: str):
    prof = _profiles[_current_profile]
    location = f"remote ({_remote_host})" if _remote_mode else "local"
    info(f"Cracking ({location}) with profile: {prof['label']}")

    if _remote_mode:
        _preflight_remote()

    from wifi_launchpad.services.crack_service import CrackService
    service = CrackService()

    try:
        result = service.crack_hash(
            hash_file,
            extra_flags=prof["flags"],
            remote=_remote_mode,
        )
        if result.cracked:
            success(f"Password found: {result.password}")
            console.print(f"  [dim]Method: {result.method} | Time: {result.crack_time:.1f}s[/dim]")
        else:
            warn(f"Crack finished. Method: {result.method} | Time: {result.crack_time:.1f}s")
    except Exception as exc:
        error(f"Crack failed: {exc}")
    pause()


def _run_auto_crack():
    from wifi_launchpad.services.crack_service import CrackService
    service = CrackService()
    flags = _profiles[_current_profile]["flags"]

    search_dir = Path(service.settings.capture_dir)
    hash_files = sorted(search_dir.glob("*.22000"))

    if not hash_files:
        warn(f"No .22000 files found in {search_dir}")
        pause()
        return

    info(f"Found {len(hash_files)} hash file(s)")
    for hf in hash_files:
        info(f"Cracking {hf.name}...")
        try:
            result = service.crack_hash(str(hf), extra_flags=flags, remote=_remote_mode)
            if result.cracked:
                success(f"  {hf.name}: {result.password}")
            else:
                warn(f"  {hf.name}: {result.method}")
        except Exception as exc:
            error(f"  {hf.name}: {exc}")
    pause()


def _preflight_remote():
    from wifi_launchpad.providers.external.hashcat_remote import check_remote

    info(f"Checking remote host {_remote_host}...")
    ok, msg = check_remote(_remote_host)
    if ok:
        success("Remote hashcat available")
        _show_gpu_info(msg)
    else:
        error(f"Remote check failed: {msg}")
        _show_ssh_help()
        raise RuntimeError(f"Remote host not ready: {msg}")


def _show_gpu_info(check_output: str):
    """Parse and display GPU device info from hashcat -I output."""
    lines = check_output.splitlines()
    for line in lines:
        stripped = line.strip()
        if any(k in stripped.lower() for k in ("device #", "type", "name", "memory", "cuda", "opencl")):
            console.print(f"  [dim]{stripped}[/dim]")


def _show_ssh_help():
    """Display troubleshooting help when SSH connection fails."""
    console.print(
        "\n[yellow]SSH connection failed. Possible causes:[/yellow]\n"
        "  1. Host is unreachable — check network / VPN\n"
        "  2. Tailscale auth required — visit the auth URL in your browser\n"
        "  3. SSH key not configured — run: ssh-copy-id user@host\n"
        "  4. Wrong hostname — verify with: ssh user@host 'echo connected'\n"
        "  5. hashcat not installed on remote — run: sudo apt install hashcat\n"
    )


def _profile_menu():
    global _current_profile

    divider("HARDWARE PROFILES")
    console.print(
        "  [green][a][/green] CPU only       [dim](--force -D 1 -w 1)[/dim]\n"
        "  [green][b][/green] GPU            [dim](-D 2 -w 3, uses all detected GPUs)[/dim]\n"
        "  [green][c][/green] Custom\n"
    )

    if _remote_mode and _remote_host:
        console.print(f"\n  [dim]Tip: run 'ssh {_remote_host} hashcat -I' to see available devices[/dim]")

    choice = prompt("Profile").lower()
    if choice in ("a", "b"):
        _current_profile = choice
        success(f"Profile set: {_profiles[choice]['label']}")
    elif choice == "c":
        device = prompt("Device type (-D) [2]") or "2"
        workload = prompt("Workload (-w) [3]") or "3"
        extra = prompt("Extra flags (optional, e.g. -O)")
        flags = ["-D", device, "-w", workload]
        if extra:
            flags.extend(extra.split())
        _profiles["c"] = {"label": "Custom", "flags": flags}
        _current_profile = "c"
        success(f"Custom profile saved: {' '.join(flags)}")
    else:
        warn("Invalid profile.")


def _location_menu():
    global _remote_mode, _remote_host

    divider("CRACK LOCATION")
    current = f"Remote ({_remote_host})" if _remote_mode and _remote_host else "Local"
    console.print(f"  Current: [bold]{current}[/bold]\n")
    console.print(
        "  [green][1][/green] Local (this machine)\n"
        "  [green][2][/green] Remote via SSH\n"
        "  [green][3][/green] Back\n"
    )
    choice = prompt("Location")

    if choice == "1":
        _remote_mode = False
        success("Crack location: Local")
    elif choice == "2":
        host = _remote_host
        if not host:
            host = prompt("Remote host (e.g. user@gpu-server)")
            if not host:
                warn("No host specified.")
                return
            console.print(f"[dim]  Set CRACK_HOST={host} in .env to persist[/dim]")

        from wifi_launchpad.providers.external.hashcat_remote import check_remote
        info(f"Testing connection to {host}...")
        ok, msg = check_remote(host)
        if not ok:
            warn(f"Non-interactive SSH failed: {msg}")
            info("Attempting interactive SSH (you may need to authenticate)...")
            import os
            ret = os.system(f"ssh -o ConnectTimeout=15 {host} echo 'SSH connection established'")
            if ret == 0:
                ok, msg = check_remote(host)
        if ok:
            _remote_mode = True
            _remote_host = host
            success(f"Remote cracking enabled: {host}")
            _show_gpu_info(msg)
        else:
            error(f"Cannot reach remote host: {msg}")
            _show_ssh_help()
    elif choice == "3":
        return
