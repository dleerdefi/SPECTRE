"""SPECTRE TUI — Connection management for DB, LLM, and remote cracking."""

from __future__ import annotations

import os
import subprocess

from wifi_launchpad.cli.common import console
from wifi_launchpad.cli.tui.helpers import prompt, pause, divider, info, warn, error, success


def connections_menu():
    """Test and configure external service connections."""
    while True:
        db_status, llm_status, crack_status = _check_all()

        divider("CONNECTIONS")
        console.print(
            f"  [green][1][/green] Database        {db_status}\n"
            f"  [green][2][/green] LLM Server      {llm_status}\n"
            f"  [green][3][/green] Remote Crack     {crack_status}\n"
            f"  [green][4][/green] Back\n"
        )
        choice = prompt("spectre/connections")

        if choice == "1":
            _db_setup()
        elif choice == "2":
            _llm_setup()
        elif choice == "3":
            _crack_setup()
        elif choice == "4":
            return
        else:
            warn("Invalid choice.")


def _check_all():
    """Quick status check for all connections."""
    # DB
    try:
        from wifi_launchpad.app.settings import get_settings
        cfg = get_settings().db
        if not cfg.password:
            db_status = "[dim]— not configured[/dim]"
        else:
            from wifi_launchpad.services.db import DatabaseService
            db = DatabaseService()
            if db.connect():
                db.disconnect()
                db_status = f"[green]■ {cfg.host}:{cfg.port}[/green]"
            else:
                db_status = f"[red]■ {cfg.host}:{cfg.port} (failed)[/red]"
    except Exception:
        db_status = "[dim]— error[/dim]"

    # LLM
    try:
        from wifi_launchpad.app.settings import get_settings
        cfg = get_settings().llm
        import requests
        r = requests.get(f"{cfg.url}/v1/models", timeout=3)
        if r.status_code == 200:
            models = r.json().get("data", [])
            name = models[0]["id"][:30] if models else "no model loaded"
            llm_status = f"[green]■ {name}[/green]"
        else:
            llm_status = f"[yellow]■ {cfg.url} (no models)[/yellow]"
    except Exception:
        try:
            llm_status = f"[red]■ {cfg.url} (unreachable)[/red]"
        except Exception:
            llm_status = "[dim]— not configured[/dim]"

    # Crack
    try:
        from wifi_launchpad.app.settings import get_settings
        host = get_settings().crack.remote_host
        if host:
            crack_status = f"[dim]■ {host} (not tested)[/dim]"
        else:
            crack_status = "[dim]— local (default)[/dim]"
    except Exception:
        crack_status = "[dim]— local (default)[/dim]"

    return db_status, llm_status, crack_status


def _db_setup():
    """Test and configure database connection."""
    divider("DATABASE CONNECTION")
    from wifi_launchpad.app.settings import get_settings
    cfg = get_settings().db

    console.print(f"  Host: {cfg.host}:{cfg.port}")
    console.print(f"  DB:   {cfg.dbname}")
    console.print(f"  User: {cfg.user}")
    console.print(f"  Pass: {'***' if cfg.password else '[red]NOT SET[/red]'}\n")

    if not cfg.password:
        warn("DB_PASSWORD not set. Add it to your .env file:")
        console.print(f"  [dim]DB_HOST={cfg.host}[/dim]")
        console.print(f"  [dim]DB_PORT={cfg.port}[/dim]")
        console.print(f"  [dim]DB_USER={cfg.user}[/dim]")
        console.print(f"  [dim]DB_PASSWORD=your-password-here[/dim]")
        console.print(f"  [dim]DB_NAME={cfg.dbname}[/dim]")
        pause()
        return

    info("Testing connection...")
    try:
        from wifi_launchpad.services.db import DatabaseService
        db = DatabaseService()
        if db.connect():
            success(f"Connected to {cfg.host}:{cfg.port}/{cfg.dbname}")
            # Check tables
            try:
                cur = db._conn.execute(
                    "SELECT COUNT(*) FROM information_schema.tables "
                    "WHERE table_schema = 'public'"
                )
                table_count = cur.fetchone()[0]
                console.print(f"  [dim]{table_count} tables found[/dim]")
            except Exception:
                pass
            db.disconnect()
        else:
            error("Connection failed")
            _db_troubleshoot(cfg)
    except Exception as exc:
        error(f"Connection error: {exc}")
        _db_troubleshoot(cfg)
    pause()


def _db_troubleshoot(cfg):
    """Show DB troubleshooting steps."""
    console.print(
        "\n[yellow]Troubleshooting:[/yellow]\n"
        f"  1. Is the DB container running? Check: docker ps\n"
        f"  2. Is {cfg.host}:{cfg.port} reachable? Check: pg_isready -h {cfg.host} -p {cfg.port}\n"
        f"  3. Correct credentials? Check your .env file\n"
        f"  4. Firewall? Ensure port {cfg.port} is open\n"
    )


def _llm_setup():
    """Test and configure LLM connection."""
    divider("LLM CONNECTION")
    from wifi_launchpad.app.settings import get_settings
    cfg = get_settings().llm

    console.print(f"  URL:   {cfg.url}")
    console.print(f"  Model: {cfg.model or '(auto-detect)'}\n")

    info("Testing connection...")
    try:
        import requests
        r = requests.get(f"{cfg.url}/v1/models", timeout=5)
        if r.status_code == 200:
            models = r.json().get("data", [])
            if models:
                success(f"Connected — {len(models)} model(s) loaded:")
                for m in models[:5]:
                    console.print(f"    [dim]{m['id']}[/dim]")
            else:
                warn("Server reachable but no models loaded. Load a model in LM Studio.")
        else:
            error(f"Server returned {r.status_code}")
    except Exception as exc:
        error(f"Cannot reach {cfg.url}: {exc}")
        console.print(
            "\n[yellow]Troubleshooting:[/yellow]\n"
            "  1. Is LM Studio / Ollama running?\n"
            f"  2. Is the server on {cfg.url}?\n"
            "  3. SSH tunnel needed? Run: ssh -N -L 1234:localhost:1234 user@llm-server\n"
            "  4. Set LLM_URL in .env if using a different endpoint\n"
        )
    pause()


def _crack_setup():
    """Test and configure remote cracking connection."""
    divider("REMOTE CRACKING")
    from wifi_launchpad.app.settings import get_settings
    host = get_settings().crack.remote_host

    if host:
        console.print(f"  Configured host: {host}\n")
    else:
        console.print("  Currently: local cracking (default)\n")

    console.print(
        "  [green][1][/green] Test current connection\n"
        "  [green][2][/green] Set remote host\n"
        "  [green][3][/green] Back\n"
    )
    choice = prompt("spectre/connections/crack")

    if choice == "1":
        if not host:
            info("No remote host configured. Using local hashcat.")
            # Test local hashcat
            try:
                result = subprocess.run(
                    ["hashcat", "--version"], capture_output=True, text=True, timeout=5,
                )
                success(f"Local hashcat: {result.stdout.strip()}")
            except Exception:
                error("hashcat not found locally")
        else:
            info(f"Testing SSH to {host}...")
            ret = os.system(f"ssh -o ConnectTimeout=15 {host} echo 'SSH OK'")
            if ret == 0:
                from wifi_launchpad.providers.external.hashcat_remote import check_remote
                ok, msg = check_remote(host)
                if ok:
                    success(f"Remote cracking ready: {host}")
                else:
                    error(f"SSH works but hashcat check failed: {msg}")
            else:
                error("SSH connection failed")
    elif choice == "2":
        new_host = prompt("Remote host (e.g., user@gpu-server)")
        if new_host:
            console.print(f"  [dim]Set CRACK_HOST={new_host} in .env to persist[/dim]")
            info(f"Testing connection to {new_host}...")
            ret = os.system(f"ssh -o ConnectTimeout=15 {new_host} echo 'SSH OK'")
            if ret == 0:
                success(f"Connection established: {new_host}")
            else:
                error("Connection failed — check host and auth")
    pause()