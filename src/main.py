"""
Main CLI entry point for the GainForest Archival Pipeline
"""
import click
import sys
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich import print as rprint

from src.config import get_settings, setup_logging
from src.core.database import DatabaseManager, ProcessingStatusEnum
from src.core.models import ProcessingStatus

console = Console()

DEFAULT_ECOCERT_IDS = [
    "42220-0x16bA53B74c234C870c61EFC04cD418B8f2865959-31305977756726338638630463883722675453952",
    "42220-0x16bA53B74c234C870c61EFC04cD418B8f2865959-31646260123647277102093838491154443665408",
    "42220-0x16bA53B74c234C870c61EFC04cD418B8f2865959-31986542490568215565557213098586211876864",
    "42220-0x16bA53B74c234C870c61EFC04cD418B8f2865959-42875578232038246396385200536402794643456",
    "42220-0x16bA53B74c234C870c61EFC04cD418B8f2865959-32326824857489154029020587706017980088320",
    "42220-0x16bA53B74c234C870c61EFC04cD418B8f2865959-32667107224410092492483962313449748299776",
    "42220-0x16bA53B74c234C870c61EFC04cD418B8f2865959-33007389591331030955947336920881516511232",
    "42220-0x16bA53B74c234C870c61EFC04cD418B8f2865959-33687954325172907882874086135745052934144",
    "42220-0x16bA53B74c234C870c61EFC04cD418B8f2865959-35389366159777600200190959172903893991424"
]


@click.group()
@click.option('--debug', is_flag=True, help='Enable debug logging')
@click.option('--config', type=click.Path(), help='Path to configuration file')
@click.pass_context
def cli(ctx, debug, config):
    """
    GainForest Archival Pipeline - Immutable Proof of Impact Storage System

    This tool archives external content from GainForest ecocerts to IPFS,
    ensuring permanent and immutable storage of environmental impact data.
    """
    settings = get_settings()
    log_level = "DEBUG" if debug else settings.LOG_LEVEL

    logger = setup_logging(
        log_level=log_level,
        log_dir=settings.LOGS_DIR,
        app_name="gainforest-archival"
    )

    ctx.ensure_object(dict)
    ctx.obj['settings'] = settings
    ctx.obj['logger'] = logger
    ctx.obj['debug'] = debug

    if ctx.invoked_subcommand is None:
        console.print(Panel.fit(
            "[bold green]GainForest Archival Pipeline[/bold green]\n"
            f"Version: {settings.APP_VERSION}\n"
            "Use --help for available commands",
            title="Welcome",
            border_style="green"
        ))


@cli.command()
@click.pass_context
def init(ctx):
    """Initialize the database and create necessary directories"""
    settings = ctx.obj['settings']
    logger = ctx.obj['logger']

    with console.status("[bold green]Initializing system...") as status:
        try:
            status.update("Creating directories...")
            settings.create_directories()
            console.print(f"✓ Created data directory: {settings.DATA_DIR}")
            console.print(f"✓ Created logs directory: {settings.LOGS_DIR}")

            status.update("Initializing database...")
            db = DatabaseManager(str(settings.DATA_DIR / "archive.db"))
            console.print(f"✓ Database initialized: {settings.DATA_DIR / 'archive.db'}")

            console.print("\n[bold]Current Configuration:[/bold]")
            config_table = Table(show_header=True, header_style="bold cyan")
            config_table.add_column("Setting", style="cyan")
            config_table.add_column("Value", style="white")

            for key, value in settings.to_dict().items():
                if not key.endswith("_KEY"):
                    config_table.add_row(key, str(value))

            console.print(config_table)

            console.print("\n[bold green]✓ System initialized successfully![/bold green]")

        except Exception as e:
            console.print(f"[bold red]✗ Initialization failed: {e}[/bold red]")
            logger.error(f"Initialization failed: {e}", exc_info=True)
            sys.exit(1)


@cli.command()
@click.option(
    '--ecocert-ids',
    multiple=True,
    help='Specific ecocert IDs to process'
)
@click.option(
    '--use-defaults',
    is_flag=True,
    help='Use the default 9 ecocert IDs'
)
@click.option(
    '--dry-run',
    is_flag=True,
    help='Perform a dry run without actual archival'
)
@click.pass_context
def archive(ctx, ecocert_ids, use_defaults, dry_run):
    """Archive external content from ecocerts to IPFS"""
    settings = ctx.obj['settings']
    logger = ctx.obj['logger']

    if use_defaults:
        ids_to_process = DEFAULT_ECOCERT_IDS
        console.print(f"[bold]Processing {len(ids_to_process)} default ecocert IDs[/bold]")
    elif ecocert_ids:
        ids_to_process = list(ecocert_ids)
        console.print(f"[bold]Processing {len(ids_to_process)} specified ecocert IDs[/bold]")
    else:
        console.print("[bold red]Error: No ecocert IDs specified![/bold red]")
        console.print("Use --use-defaults or provide --ecocert-ids")
        sys.exit(1)

    if dry_run:
        console.print("[bold yellow]DRY RUN MODE - No actual archival will be performed[/bold yellow]")

    db = DatabaseManager(str(settings.DATA_DIR / "archive.db"))

    with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
    ) as progress:

        main_task = progress.add_task(
            f"[green]Processing {len(ids_to_process)} ecocerts...",
            total=len(ids_to_process)
        )

        for ecocert_id in ids_to_process:
            progress.update(
                main_task,
                description=f"[green]Processing ecocert: {ecocert_id[:20]}..."
            )

            try:
                db.update_processing_status(
                    ecocert_id=ecocert_id,
                    status=ProcessingStatusEnum.PROCESSING
                )

                if not dry_run:
                    # TODO: Implement actual archival logic
                    console.print(f"[dim]Would process: {ecocert_id}[/dim]")
                else:
                    console.print(f"[dim]Dry run for: {ecocert_id}[/dim]")

                db.update_processing_status(
                    ecocert_id=ecocert_id,
                    status=ProcessingStatusEnum.COMPLETED
                )

            except Exception as e:
                logger.error(f"Failed to process {ecocert_id}: {e}")
                db.update_processing_status(
                    ecocert_id=ecocert_id,
                    status=ProcessingStatusEnum.FAILED,
                    error_message=str(e)
                )
                db.log_error(
                    error_type="processing_error",
                    error_message=str(e),
                    ecocert_id=ecocert_id
                )

            progress.advance(main_task)

    console.print("\n[bold green]✓ Archival process completed![/bold green]")


@cli.command()
@click.option(
    '--ecocert-id',
    help='Show status for specific ecocert'
)
@click.pass_context
def status(ctx, ecocert_id):
    """Display processing status and statistics"""
    settings = ctx.obj['settings']
    db = DatabaseManager(str(settings.DATA_DIR / "archive.db"))

    if ecocert_id:
        status = db.get_processing_status(ecocert_id)
        if status:
            console.print(f"\n[bold]Status for ecocert: {ecocert_id}[/bold]")

            status_table = Table(show_header=False, box=None)
            status_table.add_column("Field", style="cyan")
            status_table.add_column("Value", style="white")

            for key, value in status.items():
                if key != "id":
                    status_table.add_row(key.replace("_", " ").title(), str(value))

            console.print(status_table)

            content = db.get_archived_content(ecocert_id=ecocert_id)
            if content:
                console.print(f"\n[bold]Archived Content ({len(content)} items):[/bold]")
                for item in content:
                    console.print(f"  • {item['original_url'][:50]}... → {item['ipfs_hash'][:20]}...")
        else:
            console.print(f"[yellow]No status found for ecocert: {ecocert_id}[/yellow]")

    else:
        stats = db.get_statistics()

        console.print("\n[bold]Overall Statistics:[/bold]")

        stats_table = Table(show_header=True, header_style="bold cyan")
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Value", style="white", justify="right")

        stats_table.add_row("Total Archived Content", str(stats['total_archived_content']))
        stats_table.add_row(
            "Total File Size",
            f"{stats['total_file_size_bytes'] / (1024 ** 2):.2f} MB"
        )
        stats_table.add_row("Recent Errors (24h)", str(stats['recent_errors_24h']))

        console.print(stats_table)

        if stats['processing_status_summary']:
            console.print("\n[bold]Processing Status Summary:[/bold]")
            for status, count in stats['processing_status_summary'].items():
                emoji = {
                    'completed': '✓',
                    'processing': '⟳',
                    'pending': '○',
                    'failed': '✗'
                }.get(status, '•')
                console.print(f"  {emoji} {status.title()}: {count}")

        if stats['content_by_type']:
            console.print("\n[bold]Content by Type:[/bold]")
            for content_type, count in stats['content_by_type'].items():
                console.print(f"  • {content_type}: {count}")


@cli.command()
@click.pass_context
def test(ctx):
    """Run system tests to verify setup"""
    settings = ctx.obj['settings']
    logger = ctx.obj['logger']

    console.print("[bold]Running system tests...[/bold]\n")

    test_results = []

    # Test 1: Database connection
    try:
        db = DatabaseManager(str(settings.DATA_DIR / "archive.db"))
        db.get_statistics()
        test_results.append(("Database Connection", True, "Connected successfully"))
    except Exception as e:
        test_results.append(("Database Connection", False, str(e)))

    # Test 2: Directory permissions
    try:
        test_file = settings.DATA_DIR / ".test"
        test_file.write_text("test")
        test_file.unlink()
        test_results.append(("Directory Permissions", True, "Read/write access confirmed"))
    except Exception as e:
        test_results.append(("Directory Permissions", False, str(e)))

    # Test 3: Configuration loading
    try:
        assert settings.DATABASE_URL
        assert settings.EAS_SCHEMA_UID
        test_results.append(("Configuration", True, "All required settings loaded"))
    except Exception as e:
        test_results.append(("Configuration", False, "Missing required settings"))

    # Test 4: Logging
    try:
        logger.debug("Test debug message")
        logger.info("Test info message")
        test_results.append(("Logging System", True, "Logging operational"))
    except Exception as e:
        test_results.append(("Logging System", False, str(e)))

    results_table = Table(show_header=True, header_style="bold cyan")
    results_table.add_column("Test", style="cyan")
    results_table.add_column("Status", justify="center")
    results_table.add_column("Details", style="dim")

    all_passed = True
    for test_name, passed, details in test_results:
        status = "[green]✓ PASS[/green]" if passed else "[red]✗ FAIL[/red]"
        results_table.add_row(test_name, status, details)
        if not passed:
            all_passed = False

    console.print(results_table)

    if all_passed:
        console.print("\n[bold green]All tests passed! System is ready.[/bold green]")
    else:
        console.print("\n[bold red]Some tests failed. Please check configuration.[/bold red]")
        sys.exit(1)


if __name__ == "__main__":
    cli()
