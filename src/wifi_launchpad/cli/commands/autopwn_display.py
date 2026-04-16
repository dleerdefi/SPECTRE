"""Display helpers for the autopwn campaign command."""

from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree
from rich.markup import escape as rich_escape

from wifi_launchpad.cli.common import console
from wifi_launchpad.domain.recon import ReconReport


def print_recon_summary(recon: ReconReport, crackable_count: int) -> None:
    """Print the survey summary panel."""

    console.print(Panel(
        f"Networks: [bold]{recon.total_networks}[/bold]  |  "
        f"Clients: [bold]{recon.total_clients}[/bold]  |  "
        f"Crackable: [bold green]{crackable_count}[/bold green]  |  "
        f"WPA3: [dim]{recon.wpa3_count}[/dim]  |  "
        f"Open: [dim]{recon.open_count}[/dim]  |  "
        f"Enterprise: [dim]{recon.enterprise_count}[/dim]  |  "
        f"Hidden: [dim]{recon.hidden_count}[/dim]",
        title="[bold]Survey Summary[/bold]",
        border_style="cyan",
    ))


def print_target_table(recon: ReconReport) -> None:
    """Print the target priority table with intelligence."""

    table = Table(title="[bold cyan]TARGET PRIORITIES[/bold cyan]",
                  show_header=True, header_style="bold cyan")
    table.add_column("#", width=3)
    table.add_column("SSID", style="yellow")
    table.add_column("Ch", width=3)
    table.add_column("Signal")
    table.add_column("Clients")
    table.add_column("Technique", style="bold")
    table.add_column("Difficulty")
    table.add_column("Vectors")

    for i, intel in enumerate(recon.targets[:20], 1):
        diff_color = {"HIGH": "green", "MED": "yellow", "LOW": "red"}[intel.difficulty]
        client_str = str(len(intel.clients))
        if intel.best_client:
            pkts = intel.best_client.packets_sent
            if pkts > 10000:
                client_str += f" ({pkts // 1000}k)"
            elif pkts > 0:
                client_str += f" ({pkts})"

        table.add_row(
            str(i),
            rich_escape(intel.network.ssid),
            str(intel.network.channel),
            f"{intel.network.signal_strength} dBm",
            client_str,
            intel.recommended_technique,
            f"[{diff_color}]{intel.difficulty}[/{diff_color}]",
            ", ".join(intel.attack_vectors[:3]),
        )

    console.print(table)


def print_client_map(recon: ReconReport) -> None:
    """Print the client-AP relationship tree."""

    targets_with_clients = [t for t in recon.targets if t.clients]
    if not targets_with_clients:
        return

    console.print()
    tree = Tree("[bold cyan]CLIENT-AP MAP[/bold cyan]")
    for intel in targets_with_clients[:10]:
        net_node = tree.add(
            f"[yellow]{rich_escape(intel.network.ssid)}[/yellow] "
            f"({intel.network.bssid})"
        )
        for client in sorted(intel.clients, key=lambda c: c.packets_sent, reverse=True)[:5]:
            mfr = client.manufacturer or "Unknown"
            pkts = client.packets_sent
            pkt_str = f"{pkts // 1000}k" if pkts > 1000 else str(pkts)
            net_node.add(
                f"{client.mac_address}  [dim]{pkt_str} pkts  {mfr}  "
                f"{client.signal_strength} dBm[/dim]"
            )
    console.print(tree)


def print_attack_vectors(recon: ReconReport) -> None:
    """Print the attack vectors summary panel."""

    lines = []
    wps_targets = [t for t in recon.targets if "wps-unlocked" in t.attack_vectors]
    if wps_targets:
        lines.append(
            f"[green]WPS Unlocked:[/green] "
            f"{', '.join(rich_escape(t.network.ssid) for t in wps_targets)} (Pixie-Dust first)"
        )
    high_traffic = [t for t in recon.targets if "high-traffic-client" in t.attack_vectors]
    if high_traffic:
        lines.append(
            f"[green]High-traffic clients:[/green] "
            f"{', '.join(rich_escape(t.network.ssid) for t in high_traffic)} (guaranteed handshake)"
        )
    multi_client = [t for t in recon.targets if "multiple-clients" in t.attack_vectors]
    if multi_client:
        lines.append(
            f"[yellow]Multiple clients:[/yellow] "
            f"{', '.join(rich_escape(t.network.ssid) for t in multi_client)}"
        )
    pmkid_only = [t for t in recon.targets if t.recommended_technique == "pmkid"]
    if pmkid_only:
        lines.append(
            f"[dim]PMKID-only (no clients):[/dim] "
            f"{', '.join(rich_escape(t.network.ssid) for t in pmkid_only)}"
        )
    if recon.probe_leaks:
        top_probes = sorted(recon.probe_leaks.items(), key=lambda x: len(x[1]), reverse=True)[:3]
        for ssid, macs in top_probes:
            lines.append(f"[dim]Probe leak:[/dim] {rich_escape(ssid)} (from {len(macs)} device(s))")

    if lines:
        console.print(Panel(
            "\n".join(lines),
            title="[bold cyan]ATTACK VECTORS[/bold cyan]",
            border_style="cyan",
        ))


def print_campaign_summary(results) -> None:
    """Display campaign summary table."""

    console.print(f"\n{'=' * 60}")
    console.print(f"[bold cyan]CAMPAIGN SUMMARY[/bold cyan]")
    console.print(f"{'=' * 60}\n")

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("#", width=3)
    table.add_column("SSID", style="yellow")
    table.add_column("Result")
    table.add_column("Technique")
    table.add_column("Password", style="green")
    table.add_column("Time")

    captured = 0
    cracked = 0
    for i, r in enumerate(results, 1):
        if r.captured:
            captured += 1
            status = "[bold green]CAPTURED[/bold green]"
            technique = r.handshake.capture_method if r.handshake else "?"
        elif r.skipped:
            status = f"[dim]SKIP ({r.skip_reason})[/dim]"
            technique = "-"
        else:
            status = "[red]FAILED[/red]"
            technique = ", ".join(r.techniques_tried) if r.techniques_tried else "-"

        pw = ""
        if r.crack_result and r.crack_result.cracked:
            cracked += 1
            pw = r.crack_result.password or ""

        table.add_row(
            str(i),
            rich_escape(r.network_ssid),
            status,
            technique,
            pw,
            f"{r.total_time:.0f}s",
        )

    console.print(table)
    console.print(
        f"\n[bold]{captured}/{len(results)} captured, {cracked}/{captured or 1} cracked[/bold]"
    )
