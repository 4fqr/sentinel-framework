"""
Sentinel Framework - Command Line Interface
Sleek CLI with real-time telemetry and rich formatting
"""

import sys
import click
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.layout import Layout
from rich import box
from rich.text import Text

from sentinel.core.sandbox import SandboxEngine
from sentinel.core.monitor import BehaviorMonitor
from sentinel.core.events import BehaviorEvent, EventSeverity
from sentinel.core.analyzer import MalwareAnalyzer
from sentinel.core.reporter import ReportGenerator
from sentinel.utils.logger import SentinelLogger, get_logger
from sentinel.config import config
from sentinel import __version__


# Initialize Rich console with safe encoding for Windows
console = Console(legacy_windows=True, force_terminal=False)
logger = get_logger(__name__)


def print_banner():
    """Print Sentinel Framework banner"""
    banner = """
+=================================================================+
|                                                                 |
|   SENTINEL FRAMEWORK                                            |
|   Malware Analysis Sandbox - Version {}                        |
|   Open-Source | Behavioral Monitoring | Automated              |
|                                                                 |
+=================================================================+
    """.format(__version__)
    
    console.print(banner, style="bold cyan")


class LiveMonitor:
    """Real-time event monitor display"""
    
    def __init__(self):
        self.events_count = 0
        self.events_by_severity = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        self.recent_events = []
        self.max_recent = 5
    
    def update_event(self, event: BehaviorEvent):
        """Update with new event"""
        self.events_count += 1
        severity = event.severity.value
        self.events_by_severity[severity] = self.events_by_severity.get(severity, 0) + 1
        
        # Add to recent events
        self.recent_events.insert(0, event)
        if len(self.recent_events) > self.max_recent:
            self.recent_events.pop()
    
    def generate_display(self) -> Layout:
        """Generate live display layout"""
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3)
        )
        
        # Header
        header_text = Text("[SENTINEL FRAMEWORK - LIVE ANALYSIS]", style="bold white on blue", justify="center")
        layout["header"].update(Panel(header_text))
        
        # Body - split into stats and events
        layout["body"].split_row(
            Layout(name="stats", ratio=1),
            Layout(name="events", ratio=2)
        )
        
        # Stats panel
        stats_table = Table(show_header=False, box=box.SIMPLE)
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Value", style="yellow")
        
        stats_table.add_row("Total Events", str(self.events_count))
        stats_table.add_row("🔴 Critical", str(self.events_by_severity['critical']))
        stats_table.add_row("🟠 High", str(self.events_by_severity['high']))
        stats_table.add_row("🟡 Medium", str(self.events_by_severity['medium']))
        stats_table.add_row("🔵 Low", str(self.events_by_severity['low']))
        
        layout["stats"].update(Panel(stats_table, title="[bold]Statistics[/bold]", border_style="green"))
        
        # Recent events panel
        events_table = Table(show_header=True, box=box.SIMPLE_HEAD)
        events_table.add_column("Type", style="cyan")
        events_table.add_column("Description", style="white")
        events_table.add_column("Severity", justify="right")
        
        for event in self.recent_events[:5]:
            severity_style = {
                'critical': 'bold red',
                'high': 'bold yellow',
                'medium': 'yellow',
                'low': 'cyan',
                'info': 'white'
            }.get(event.severity.value, 'white')
            
            events_table.add_row(
                event.event_type.value,
                event.description[:50],
                f"[{severity_style}]{event.severity.value.upper()}[/{severity_style}]"
            )
        
        layout["events"].update(Panel(events_table, title="[bold]Recent Events[/bold]", border_style="blue"))
        
        # Footer
        footer_text = Text("Press Ctrl+C to stop analysis", style="dim", justify="center")
        layout["footer"].update(Panel(footer_text))
        
        return layout


@click.group()
@click.version_option(version=__version__)
def cli():
    """
    SENTINEL FRAMEWORK - Malware Analysis Sandbox
    
    Advanced open-source platform for automated malware analysis
    with behavioral monitoring and threat detection.
    """
    SentinelLogger.setup()


@cli.command()
@click.argument('sample', type=click.Path(exists=True))
@click.option('--timeout', '-t', default=None, type=int, help='Analysis timeout in seconds')
@click.option('--no-static', is_flag=True, help='Disable static analysis')
@click.option('--no-dynamic', is_flag=True, help='Disable dynamic analysis')
@click.option('--format', '-f', type=click.Choice(['html', 'json', 'markdown']), help='Report format')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--live', is_flag=True, help='Show live analysis telemetry')
def analyze(sample, timeout, no_static, no_dynamic, format, output, live):
    """
    Analyze a malware sample
    
    SAMPLE: Path to the sample file to analyze
    """
    print_banner()
    
    sample_path = Path(sample)
    
    console.print(f"\n[bold cyan]=== Analysis Target ===[/bold cyan]")
    console.print(f"Sample: [yellow]{sample_path}[/yellow]")
    console.print(f"Size: [yellow]{sample_path.stat().st_size:,}[/yellow] bytes\n")
    
    try:
        analyzer = MalwareAnalyzer()
        
        if live:
            # Live monitoring mode
            live_monitor = LiveMonitor()
            
            # Register callback for live updates
            analyzer.monitor.register_callback(live_monitor.update_event)
            
            with Live(live_monitor.generate_display(), refresh_per_second=2, console=console) as live_display:
                # Run analysis
                result = analyzer.analyze(
                    str(sample_path),
                    enable_static=not no_static,
                    enable_dynamic=not no_dynamic,
                    timeout=timeout
                )
                
                # Update display one last time
                live_display.update(live_monitor.generate_display())
        else:
            # Standard mode with progress bar
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeElapsedColumn(),
                console=console
            ) as progress:
                task = progress.add_task("[cyan]Analyzing sample...", total=None)
                
                result = analyzer.analyze(
                    str(sample_path),
                    enable_static=not no_static,
                    enable_dynamic=not no_dynamic,
                    timeout=timeout
                )
                
                progress.update(task, completed=True)
        
        # Display results
        display_results(result)
        
        # Generate report
        if format or output:
            reporter = ReportGenerator()
            report_path = reporter.generate(result, format=format, output_file=output)
            console.print(f"\n[bold green]SUCCESS[/bold green] Report generated: [cyan]{report_path}[/cyan]")
        
        # Cleanup
        analyzer.cleanup()
        
    except KeyboardInterrupt:
        console.print("\n[bold yellow][WARNING][/bold yellow] Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[bold red]✗ Analysis failed:[/bold red] {e}")
        logger.error(f"Analysis failed: {e}", exc_info=True)
        sys.exit(1)


def display_results(result):
    """Display analysis results in a beautiful format"""
    console.print(f"\n[bold cyan]=== Analysis Complete ===[/bold cyan]\n")
    
    # Verdict panel
    verdict_color = {
        'Malicious': 'red',
        'Suspicious': 'yellow',
        'Potentially Unwanted': 'yellow',
        'Clean': 'green',
        'Unknown': 'white'
    }.get(result.verdict, 'white')
    
    verdict_panel = Panel(
        f"[bold {verdict_color}]{result.verdict}[/bold {verdict_color}]\n\n"
        f"Risk Score: [bold]{result.risk_score}/100[/bold]\n"
        f"Analysis Time: {result.analysis_time:.2f}s",
        title="[bold]Verdict[/bold]",
        border_style=verdict_color,
        expand=False
    )
    console.print(verdict_panel)
    
    # Threat detections
    if result.threat_detections:
        console.print(f"\n[bold red][!] Threat Detections ({len(result.threat_detections)}):[/bold red]")
        
        detections_table = Table(show_header=True, box=box.ROUNDED)
        detections_table.add_column("Type", style="cyan")
        detections_table.add_column("Technique", style="yellow")
        detections_table.add_column("Confidence", justify="right", style="magenta")
        detections_table.add_column("Severity", justify="center")
        
        for detection in result.threat_detections:
            severity_style = {
                'critical': 'bold red',
                'high': 'bold yellow',
                'medium': 'yellow',
                'low': 'cyan'
            }.get(detection['severity'], 'white')
            
            detections_table.add_row(
                detection['threat_type'],
                detection['technique'],
                f"{detection['confidence']}%",
                f"[{severity_style}]{detection['severity'].upper()}[/{severity_style}]"
            )
        
        console.print(detections_table)
    
    # Event summary
    if result.behavioral_events:
        console.print(f"\n[bold cyan]📊 Behavioral Events:[/bold cyan] {len(result.behavioral_events)} captured")


@cli.command()
@click.argument('report_file', type=click.Path(exists=True))
def view(report_file):
    """View an existing analysis report"""
    print_banner()
    
    report_path = Path(report_file)
    
    if report_path.suffix == '.json':
        import json
        with open(report_path, 'r') as f:
            data = json.load(f)
        
        console.print(f"\n[bold cyan]Report:[/bold cyan] {report_path}")
        console.print_json(json.dumps(data, indent=2))
    else:
        console.print(f"\n[bold yellow][WARNING][/bold yellow] Viewing {report_path.suffix} reports not yet supported")


@cli.command()
def info():
    """Display Sentinel Framework information"""
    print_banner()
    
    info_table = Table(show_header=False, box=box.ROUNDED)
    info_table.add_column("Property", style="cyan")
    info_table.add_column("Value", style="yellow")
    
    info_table.add_row("Version", __version__)
    info_table.add_row("Sandbox Type", config.get('sandbox.type', 'docker'))
    info_table.add_row("Default Timeout", f"{config.get('sandbox.timeout', 300)}s")
    info_table.add_row("Report Format", config.get('reporting.format', 'html'))
    info_table.add_row("Output Directory", config.get('reporting.output_dir', 'reports'))
    
    console.print(info_table)
    
    console.print(f"\n[bold cyan]Enabled Monitors:[/bold cyan]")
    monitors = []
    if config.get('monitoring.file_system.enabled', True):
        monitors.append("[OK] File System")
    if config.get('monitoring.process.enabled', True):
        monitors.append("[OK] Process")
    if config.get('monitoring.registry.enabled', True):
        monitors.append("[OK] Registry")
    if config.get('monitoring.network.enabled', True):
        monitors.append("[OK] Network")
    
    for monitor in monitors:
        console.print(f"  {monitor}")


def main():
    """Main entry point"""
    try:
        cli()
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
