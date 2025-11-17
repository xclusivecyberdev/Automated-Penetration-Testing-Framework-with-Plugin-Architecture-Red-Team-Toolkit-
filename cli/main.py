"""
Command-line interface for the penetration testing framework
"""

import click
import asyncio
import sys
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.framework import PentestFramework
from core.config import Config, Target
from core.logger import Logger
from reporting.report_engine import ReportEngine


console = Console()


@click.group()
@click.version_option(version="1.0.0")
def cli():
    """
    🔒 RedTeam Penetration Testing Framework

    An automated penetration testing framework with modular plugin architecture
    for comprehensive security assessments.
    """
    pass


@cli.command()
@click.option('-c', '--config', type=click.Path(exists=True), help='Configuration file path')
@click.option('-t', '--target', help='Target URL or IP address')
@click.option('-m', '--mode', type=click.Choice(['safe', 'normal', 'aggressive', 'stealth']),
              default='normal', help='Scan mode')
@click.option('-o', '--output', default='output', help='Output directory')
@click.option('--resume', help='Resume session ID')
@click.option('--name', help='Session name')
def scan(config, target, mode, output, resume, name):
    """Run a penetration test scan"""

    try:
        console.print("[bold cyan]Initializing Penetration Testing Framework...[/bold cyan]")

        # Load configuration
        if config:
            cfg = Config(config_file=config)
        else:
            cfg = Config()
            cfg.set_scan_mode(mode)
            cfg.output_dir = Path(output)

            if target:
                # Parse target
                target_type = 'url' if target.startswith('http') else 'host'
                cfg.add_target(Target(
                    name=target,
                    type=target_type,
                    value=target
                ))

        # Create logger
        logger = Logger()

        # Create framework
        framework = PentestFramework(config=cfg, logger=logger, session_name=name)
        framework.initialize()

        # Run scan
        console.print("\n[bold green]Starting scan...[/bold green]\n")
        asyncio.run(framework.run(resume_session_id=resume))

        # Generate report
        console.print("\n[bold cyan]Generating report...[/bold cyan]")
        report_engine = ReportEngine(output_dir=str(cfg.output_dir))

        session_data = framework.session_manager.get_session_state()
        vulnerabilities = framework.get_vulnerabilities()
        statistics = framework.get_statistics()

        # Generate HTML report
        html_report = report_engine.generate_report(
            session_data=session_data,
            vulnerabilities=vulnerabilities,
            statistics=statistics,
            output_format='html'
        )

        # Generate JSON report
        json_report = report_engine.generate_report(
            session_data=session_data,
            vulnerabilities=vulnerabilities,
            statistics=statistics,
            output_format='json'
        )

        console.print(f"\n[bold green]✓ Scan completed successfully![/bold green]")
        console.print(f"[cyan]HTML Report:[/cyan] {html_report}")
        console.print(f"[cyan]JSON Report:[/cyan] {json_report}")

        # Display summary
        display_summary(statistics)

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red]Error:[/bold red] {e}")
        sys.exit(1)


@cli.command()
def list_plugins():
    """List all available plugins"""

    from core.plugin_loader import PluginLoader
    from core.logger import Logger

    logger = Logger()
    loader = PluginLoader(logger=logger)

    console.print("[bold cyan]Discovering plugins...[/bold cyan]\n")
    count = loader.discover_plugins()

    if count == 0:
        console.print("[yellow]No plugins found[/yellow]")
        return

    # Load plugins
    loader.load_all_plugins()
    plugins_info = loader.get_plugin_info()

    # Group by category
    by_category = {}
    for plugin in plugins_info:
        category = plugin['category']
        if category not in by_category:
            by_category[category] = []
        by_category[category].append(plugin)

    # Display
    for category, plugins in by_category.items():
        table = Table(title=f"\n{category.upper()}")
        table.add_column("Plugin", style="cyan")
        table.add_column("Description", style="white")
        table.add_column("Version", style="green")
        table.add_column("Status", style="yellow")

        for plugin in plugins:
            status = "✓ Enabled" if plugin['enabled'] else "✗ Disabled"
            table.add_row(
                plugin['name'],
                plugin['description'],
                plugin['version'],
                status
            )

        console.print(table)


@cli.command()
@click.option('--limit', default=10, help='Number of sessions to show')
def list_sessions(limit):
    """List previous scan sessions"""

    from core.session import SessionManager

    manager = SessionManager()
    sessions = manager.list_sessions()

    if not sessions:
        console.print("[yellow]No sessions found[/yellow]")
        return

    table = Table(title="Scan Sessions")
    table.add_column("Session ID", style="cyan")
    table.add_column("Name", style="white")
    table.add_column("Status", style="yellow")
    table.add_column("Created", style="green")
    table.add_column("Vulnerabilities", style="red")

    for session in sessions[:limit]:
        table.add_row(
            session['session_id'],
            session.get('name', 'N/A'),
            session['status'],
            session['created_at'],
            str(session.get('total_vulnerabilities', 0))
        )

    console.print(table)


@cli.command()
@click.argument('session_id')
def show_session(session_id):
    """Show details of a specific session"""

    from core.session import SessionManager

    manager = SessionManager()
    session = manager.load_session(session_id)

    if not session:
        console.print(f"[red]Session not found: {session_id}[/red]")
        return

    # Display session details
    console.print(f"\n[bold cyan]Session: {session.name}[/bold cyan]")
    console.print(f"ID: {session.session_id}")
    console.print(f"Status: {session.status.value}")
    console.print(f"Created: {session.created_at}")
    console.print(f"Vulnerabilities: {session.total_vulnerabilities}")
    console.print(f"Completed plugins: {len(session.completed_plugins)}")
    console.print(f"Failed plugins: {len(session.failed_plugins)}")


@cli.command()
@click.option('-t', '--target', required=True, help='Target URL or host')
@click.option('-o', '--output', default='targets.yaml', help='Output config file')
def create_config(target, output):
    """Create a sample configuration file"""

    import yaml

    config = {
        'scan_mode': 'normal',
        'targets': [
            {
                'name': 'target1',
                'type': 'url' if target.startswith('http') else 'host',
                'value': target,
                'priority': 5
            }
        ],
        'max_threads': 10,
        'output_dir': 'output'
    }

    with open(output, 'w') as f:
        yaml.dump(config, f, default_flow_style=False)

    console.print(f"[green]✓ Configuration file created: {output}[/green]")


def display_summary(statistics: dict):
    """Display scan summary"""

    table = Table(title="\nScan Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Targets Scanned", str(statistics['total_targets']))
    table.add_row("Plugins Executed", str(statistics['completed_plugins']))
    table.add_row("Total Vulnerabilities", str(statistics['total_vulnerabilities']))
    table.add_row("Critical", str(statistics['severity_counts']['critical']))
    table.add_row("High", str(statistics['severity_counts']['high']))
    table.add_row("Medium", str(statistics['severity_counts']['medium']))
    table.add_row("Low", str(statistics['severity_counts']['low']))

    console.print(table)


if __name__ == '__main__':
    cli()
