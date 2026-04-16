"""Case and report commands."""

from datetime import datetime
from pathlib import Path

import click
from rich.panel import Panel
from rich.table import Table

from wifi_launchpad.cli.common import console, emit_json
from wifi_launchpad.services.cases import get_case_store
from wifi_launchpad.services.reports import generate_case_report
from wifi_launchpad.storage.artifacts import build_artifact


@click.group()
def cases():
    """Manage case files and evidence provenance."""


@cases.command("init")
@click.argument("name")
@click.option("--notes", default="", help="Initial case notes")
@click.option("--tags", default="", help="Comma-separated case tags")
@click.option("--json-output", "--json", "json_output", is_flag=True, help="Emit JSON instead of rich text")
def cases_init(name, notes, tags, json_output):
    """Create a new case directory."""

    store = get_case_store()
    tag_list = [tag.strip() for tag in tags.split(",") if tag.strip()]
    record = store.create_case(name=name, notes=notes, tags=tag_list)
    payload = record.to_dict()
    payload["path"] = str(store.base_path / record.case_id)

    if json_output:
        emit_json(payload)
        return

    console.print(f"[green]Created case[/green] [yellow]{record.case_id}[/yellow]")
    console.print(f"[cyan]Path:[/cyan] {store.base_path / record.case_id}")


@cases.command("list")
@click.option("--json-output", "--json", "json_output", is_flag=True, help="Emit JSON instead of rich text")
def cases_list(json_output):
    """List available cases."""

    records = get_case_store().list_cases()
    if json_output:
        emit_json({"cases": [record.to_dict() for record in records]})
        return

    if not records:
        console.print("[yellow]No cases found[/yellow]")
        return

    table = Table(title="Cases", show_header=True, header_style="bold cyan")
    table.add_column("Case ID", style="yellow")
    table.add_column("Name", style="green")
    table.add_column("Created")
    table.add_column("Jobs")
    table.add_column("Artifacts")

    for record in records:
        table.add_row(
            record.case_id,
            record.name,
            record.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            str(len(record.jobs)),
            str(len(record.artifacts)),
        )

    console.print(table)


@cases.command("show")
@click.argument("case_id")
@click.option("--json-output", "--json", "json_output", is_flag=True, help="Emit JSON instead of rich text")
def cases_show(case_id, json_output):
    """Show details for a single case."""

    store = get_case_store()
    try:
        payload = store.summarize_case(case_id)
    except FileNotFoundError as exc:
        raise click.ClickException(str(exc)) from exc

    if json_output:
        emit_json(payload)
        return

    case = payload["case"]
    stats = payload["stats"]
    console.print(
        Panel(
            f"[bold cyan]{case['name']}[/bold cyan]\n\n"
            f"Case ID: [yellow]{case['case_id']}[/yellow]\n"
            f"Created: [yellow]{case['created_at']}[/yellow]\n"
            f"Jobs: [yellow]{stats['job_count']}[/yellow]\n"
            f"Artifacts: [yellow]{stats['artifact_count']}[/yellow]",
            border_style="cyan",
        )
    )
    if stats["artifact_kinds"]:
        console.print("[cyan]Artifacts by kind:[/cyan]")
        for kind, count in stats["artifact_kinds"].items():
            console.print(f"  {kind}: [yellow]{count}[/yellow]")


@cases.command("add-artifact")
@click.argument("case_id")
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("--kind", required=True, help="Artifact kind, e.g. pcapng, 22000, report")
@click.option("--source-tool", required=True, help="Tool that produced the artifact")
@click.option("--artifact-id", help="Explicit artifact id")
@click.option("--derived-from", multiple=True, help="Artifact IDs this item was derived from")
@click.option("--validation-status", default="unknown", help="Validation state for this artifact")
@click.option("--json-output", "--json", "json_output", is_flag=True, help="Emit JSON instead of rich text")
def cases_add_artifact(case_id, path, kind, source_tool, artifact_id, derived_from, validation_status, json_output):
    """Attach an artifact to an existing case with provenance metadata."""

    store = get_case_store()
    artifact = build_artifact(
        kind=kind,
        source_tool=source_tool,
        path=path,
        artifact_id=artifact_id,
        derived_from=derived_from,
        validation_status=validation_status,
        created_at=datetime.now(),
    )

    try:
        store.add_artifact(case_id, artifact)
    except FileNotFoundError as exc:
        raise click.ClickException(str(exc)) from exc

    if json_output:
        emit_json(artifact.to_dict())
        return

    console.print(f"[green]Added artifact[/green] [yellow]{artifact.artifact_id}[/yellow] to case [yellow]{case_id}[/yellow]")
    if artifact.derived_from:
        console.print(f"[cyan]Derived from:[/cyan] {', '.join(artifact.derived_from)}")


def register_case_commands(cli):
    """Register the case group and report command on the root CLI."""

    cli.add_command(cases)

    @cli.command()
    @click.argument("case_id")
    @click.option("--json-output", "--json", "json_output", is_flag=True, help="Emit JSON instead of rich text")
    def report(case_id, json_output):
        """Generate and persist a case summary report."""

        store = get_case_store()
        try:
            summary, artifact = generate_case_report(store, case_id)
        except FileNotFoundError as exc:
            raise click.ClickException(str(exc)) from exc

        payload = {"case_id": case_id, "summary": summary, "artifact": artifact.to_dict()}
        if json_output:
            emit_json(payload)
            return

        stats = summary["stats"]
        console.print(f"[green]Report written[/green] [yellow]{artifact.path}[/yellow]")
        console.print(
            f"[cyan]Summary:[/cyan] {stats['job_count']} jobs, "
            f"{stats['artifact_count']} artifacts across {len(stats['artifact_kinds'])} kinds"
        )
