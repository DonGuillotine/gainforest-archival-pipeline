"""
Main CLI entry point for the GainForest Archival Pipeline
"""
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from src.config import get_settings, setup_logging
from src.core.database import DatabaseManager, ProcessingStatusEnum

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
    "42220-0x16bA53B74c234C870c61EFC04cD418B8f2865959-35389366159777600200190959172903893991424",
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


@cli.command()
@click.option(
    '--ecocert-id',
    help='Specific ecocert ID to query'
)
@click.option(
    '--test-all',
    is_flag=True,
    help='Test with all default ecocert IDs'
)
@click.pass_context
def query(ctx, ecocert_id, test_all):
    """Query ecocert data and extract external links"""
    from src.core.graphql_client import EcocertQueryService
    from src.security.validator import URLValidator
    from rich.tree import Tree

    settings = ctx.obj['settings']
    logger = ctx.obj['logger']

    # Initialize services
    query_service = EcocertQueryService()
    url_validator = URLValidator()

    # Determine which ecocerts to query
    if test_all:
        ecocert_ids = DEFAULT_ECOCERT_IDS
        console.print(f"[bold]Testing query with {len(ecocert_ids)} ecocerts[/bold]")
    elif ecocert_id:
        ecocert_ids = [ecocert_id]
    else:
        console.print("[bold red]Error: Specify --ecocert-id or use --test-all[/bold red]")
        return

    # Query each ecocert
    with console.status("[bold green]Querying ecocerts...") as status:
        for eco_id in ecocert_ids:
            status.update(f"Querying {eco_id[:40]}...")

            try:
                # Query ecocert data
                ecocert_data = query_service.query_ecocert(eco_id)

                if ecocert_data:
                    # Display results
                    console.print(f"\n[bold green]SUCCESS Ecocert: {eco_id}[/bold green]")
                    console.print(f"  Attestation UID: {ecocert_data.attestation_uid}")
                    console.print(f"  Total Links: {ecocert_data.total_links}")

                    if ecocert_data.external_links:
                        # Create tree view of links
                        tree = Tree(f"[bold]External Links ({len(ecocert_data.external_links)})[/bold]")

                        for link in ecocert_data.external_links:
                            # Validate URL
                            is_valid, error = url_validator.validate_url(link.url)

                            # Create link node
                            link_text = f"{link.url[:60]}..." if len(link.url) > 60 else link.url
                            status_emoji = "✓" if is_valid else "✗"
                            color = "green" if is_valid else "red"

                            link_node = tree.add(f"[{color}]{status_emoji}[/{color}] {link_text}")

                            # Add details
                            if link.link_type:
                                link_node.add(f"Type: {link.link_type}")
                            if link.description:
                                link_node.add(f"Description: {link.description}")
                            if not is_valid and error:
                                link_node.add(f"[red]Error: {error}[/red]")

                            # Add resource info
                            resource_info = url_validator.extract_resource_id(link.url)
                            if resource_info:
                                link_node.add(f"Resource: {resource_info['type']} ({resource_info['id'][:20]}...)")

                        console.print(tree)
                    else:
                        console.print("  [yellow]No external links found[/yellow]")

                    # Show metadata summary
                    if ecocert_data.metadata.get("hypercert"):
                        hypercert = ecocert_data.metadata["hypercert"]
                        console.print(f"\n  [dim]Hypercert ID: {hypercert.get('id')}[/dim]")
                        if hypercert.get("metadata"):
                            meta = hypercert["metadata"]
                            if isinstance(meta, dict):
                                console.print(f"  [dim]Name: {meta.get('name', 'N/A')}[/dim]")

                else:
                    console.print(f"[yellow]⚠ No data found for: {eco_id}[/yellow]")

            except Exception as e:
                console.print(f"[red]✗ Failed to query {eco_id}: {e}[/red]")
                logger.error(f"Query failed for {eco_id}: {e}", exc_info=True)

    console.print("\n[bold green]Query testing completed![/bold green]")


@cli.command()
@click.option(
    '--url',
    multiple=True,
    help='URLs to validate'
)
@click.option(
    '--file',
    type=click.Path(exists=True),
    help='File containing URLs (one per line)'
)
@click.pass_context
def validate_urls(ctx, url, file):
    """Validate URLs against security rules"""
    from src.security.validator import URLValidator

    logger = ctx.obj['logger']

    # Collect URLs
    urls_to_validate = list(url)

    if file:
        with open(file, 'r') as f:
            urls_to_validate.extend([line.strip() for line in f if line.strip()])

    if not urls_to_validate:
        console.print("[bold red]Error: No URLs provided[/bold red]")
        console.print("Use --url or --file option")
        return

    # Initialize validator
    validator = URLValidator()

    console.print(f"[bold]Validating {len(urls_to_validate)} URLs[/bold]\n")

    # Validate URLs
    results = validator.batch_validate_urls(urls_to_validate)

    # Display results
    valid_count = 0
    invalid_count = 0

    for url, result in results.items():
        if result["is_valid"]:
            valid_count += 1
            console.print(f"[green]✓[/green] {url}")

            if result.get("resource"):
                resource = result["resource"]
                console.print(f"  └─ {resource['type']}: {resource['id']}")

            if not result.get("is_accessible", True):
                console.print(f"  [yellow]⚠ Warning: {result.get('accessibility_error')}[/yellow]")
        else:
            invalid_count += 1
            console.print(f"[red]✗[/red] {url}")
            console.print(f"  └─ [red]{result['error']}[/red]")

    # Summary
    console.print(f"\n[bold]Summary:[/bold]")
    console.print(f"  Valid URLs: [green]{valid_count}[/green]")
    console.print(f"  Invalid URLs: [red]{invalid_count}[/red]")


@cli.command()
@click.option(
    '--url',
    multiple=True,
    help='URLs to download'
)
@click.option(
    '--google-drive-test',
    is_flag=True,
    help='Test with sample Google Drive URL'
)
@click.option(
    '--youtube-test',
    is_flag=True,
    help='Test with sample YouTube URL'
)
@click.pass_context
def download(ctx, url, google_drive_test, youtube_test):
    """Test content download handlers"""
    from src.handlers.download_manager import DownloadManager
    from src.handlers.base import DownloadProgress
    from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn

    settings = ctx.obj['settings']
    logger = ctx.obj['logger']

    # Collect URLs to download
    urls_to_download = list(url)

    if google_drive_test:
        test_url = "https://drive.google.com/file/d/1dPhRO-X6FC8Kv1s3ExfDyNdXkBrd5QTG/view?usp=sharing"
        urls_to_download.append(test_url)
        console.print("[yellow]Added test Google Drive URL[/yellow]")

    if youtube_test:
        # Add a short test YouTube video
        test_url = "https://www.youtube.com/watch?v=jNQXAC9IVRw"
        urls_to_download.append(test_url)
        console.print("[yellow]Added test YouTube URL[/yellow]")

    if not urls_to_download:
        console.print("[bold red]Error: No URLs specified[/bold red]")
        console.print("Use --url, --google-drive-test, or --youtube-test")
        return

    # Initialize download manager
    manager = DownloadManager()

    console.print(f"\n[bold]Downloading {len(urls_to_download)} files[/bold]")

    # Process each URL
    for url in urls_to_download:
        console.print(f"\n[cyan]Downloading: {url}[/cyan]")

        with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeRemainingColumn(),
                console=console
        ) as progress:

            download_task = progress.add_task("Downloading...", total=None)

            def progress_callback(dl_progress: DownloadProgress):
                # Format size display
                downloaded_mb = dl_progress.downloaded_bytes / (1024 * 1024)
                
                if dl_progress.total_bytes > 0:
                    # We know the total size - show proper progress bar
                    total_mb = dl_progress.total_bytes / (1024 * 1024)
                    progress.update(download_task, total=dl_progress.total_bytes)
                    progress.update(
                        download_task,
                        completed=dl_progress.downloaded_bytes,
                        description=f"{dl_progress.status}: {downloaded_mb:.1f}MB / {total_mb:.1f}MB"
                    )
                else:
                    # Unknown total size - show indeterminate progress
                    progress.update(
                        download_task,
                        description=f"{dl_progress.status}: {downloaded_mb:.1f}MB"
                    )

            # Download the content
            result = manager.download_content(url, progress_callback)

            if result.success:
                console.print(f"[green]✓ Success![/green]")
                console.print(f"  File: {result.file_path}")
                console.print(f"  Size: {result.file_size / (1024 * 1024):.2f} MB")
                console.print(f"  Type: {result.mime_type}")
                console.print(f"  Hash: {result.checksum[:16]}...")
                console.print(f"  Time: {result.download_time:.2f}s")

                if result.metadata:
                    console.print("  Metadata:")
                    for key, value in result.metadata.items():
                        if key != 'original_url':  # Skip long URLs
                            console.print(f"    {key}: {value}")
            else:
                console.print(f"[red]✗ Failed: {result.error}[/red]")

    # Cleanup
    manager.cleanup_temp_files()
    console.print("\n[bold green]Download testing complete![/bold green]")


@cli.command()
@click.option(
    '--file',
    type=click.Path(exists=True),
    help='File to upload to IPFS'
)
@click.option(
    '--test-auth',
    is_flag=True,
    help='Test Pinata authentication'
)
@click.pass_context
def ipfs(ctx, file, test_auth):
    """Test IPFS/Pinata integration"""
    from src.storage.ipfs_client import PinataClient

    settings = ctx.obj['settings']
    logger = ctx.obj['logger']

    # Initialize Pinata client
    pinata = PinataClient()

    if test_auth:
        console.print("[bold]Testing Pinata Authentication[/bold]")

        if pinata.test_authentication():
            console.print("[green]✓ Authentication successful![/green]")

            # Get usage stats
            stats = pinata.get_usage_stats()
            if stats:
                console.print(f"Pin Count: {stats.get('pin_count', 0)}")
                console.print(f"Total Size: {stats.get('pin_size_total', 0) / (1024 * 1024):.2f} MB")
        else:
            console.print("[red]✗ Authentication failed![/red]")
            console.print("Please check your PINATA_API_KEY and PINATA_SECRET_API_KEY in .env")
        return

    if file:
        file_path = Path(file)
        console.print(f"[bold]Uploading to IPFS: {file_path.name}[/bold]")

        # Upload file
        with console.status("[green]Uploading...") as status:
            response = pinata.pin_file_to_ipfs(
                file_path=file_path,
                pin_name=file_path.stem,
                metadata={"test_upload": "true"}
            )

            if response.success:
                console.print(f"[green]✓ Upload successful![/green]")
                console.print(f"IPFS Hash: {response.ipfs_hash}")
                console.print(f"Pin Size: {response.pin_size} bytes")
                console.print(f"Gateway URL: {response.gateway_url}")

                # Verify pin
                if pinata.verify_pin(response.ipfs_hash):
                    console.print("[green]✓ Pin verified![/green]")
            else:
                console.print(f"[red]✗ Upload failed: {response.error}[/red]")
    else:
        console.print("Use --test-auth to test authentication or --file to upload a file")


@cli.command()
@click.option(
    '--ecocert-id',
    help='Process specific ecocert ID'
)
@click.option(
    '--test-pipeline',
    is_flag=True,
    help='Test complete pipeline with sample data'
)
@click.pass_context
def archive_to_ipfs(ctx, ecocert_id, test_pipeline):
    """Complete archival pipeline: Query → Download → IPFS → Database"""
    from src.core.graphql_client import EcocertQueryService
    from src.storage.archive_manager import ArchiveManager
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.panel import Panel

    settings = ctx.obj['settings']
    logger = ctx.obj['logger']

    if test_pipeline:
        # Use first default ecocert for testing
        ecocert_id = DEFAULT_ECOCERT_IDS[1]
        console.print("[yellow]Testing pipeline with first default ecocert[/yellow]")

    if not ecocert_id:
        console.print("[red]Error: Specify --ecocert-id or use --test-pipeline[/red]")
        return

    console.print(Panel.fit(
        f"[bold cyan]Archiving Ecocert to IPFS[/bold cyan]\n"
        f"ID: {ecocert_id[:50]}...",
        title="Archive Pipeline",
        border_style="cyan"
    ))

    # Initialize services
    query_service = EcocertQueryService()
    archive_manager = ArchiveManager()

    with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
    ) as progress:

        # Step 1: Query ecocert
        task = progress.add_task("Querying ecocert data...")
        ecocert_data = query_service.query_ecocert(ecocert_id)

        if not ecocert_data:
            console.print("[red]✗ Failed to query ecocert data[/red]")
            return

        console.print(f"[green]✓ Found {len(ecocert_data.external_links)} external links[/green]")

        # Step 2: Archive links
        task = progress.add_task("Archiving links to IPFS...")

        results = archive_manager.archive_ecocert_links(
            ecocert_id=ecocert_data.ecocert_id,
            attestation_uid=ecocert_data.attestation_uid,
            links=ecocert_data.external_links
        )

    # Display results
    console.print("\n[bold]Archive Results:[/bold]")
    console.print(f"Total Links: {results['total_links']}")
    console.print(f"[green]Successful: {results['successful']}[/green]")
    console.print(f"[red]Failed: {results['failed']}[/red]")

    if results['archived_content']:
        console.print("\n[bold]Archived Content:[/bold]")
        for content in results['archived_content']:
            console.print(f"  • {content['url'][:50]}...")
            console.print(f"    IPFS: {content['ipfs_hash']}")
            console.print(f"    Gateway: {settings.IPFS_GATEWAY_URL}{content['ipfs_hash']}")

    # Show statistics
    stats = archive_manager.get_archive_statistics()
    console.print(f"\n[bold]Database Statistics:[/bold]")
    console.print(f"Total Archived: {stats['total_archived_content']}")
    console.print(f"Total Size: {stats['total_file_size_bytes'] / (1024 * 1024):.2f} MB")

    if 'ipfs_usage' in stats:
        console.print(f"\n[bold]IPFS Statistics:[/bold]")
        console.print(f"Total Pins: {stats['ipfs_usage']['pin_count']}")
        console.print(f"Total Size: {stats['ipfs_usage']['pin_size_total_mb']:.2f} MB")


if __name__ == "__main__":
    cli()
