"""
Sentinel Framework - Command Line Interface
Sleek CLI with real-time telemetry and rich formatting
"""

import sys
import click
from pathlib import Path
from typing import Optional, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
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


def _collect_samples(directory: Path, recursive: bool, extensions: tuple) -> List[Path]:
    """Collect sample files from directory"""
    samples = []
    
    # Default extensions if none specified
    if not extensions:
        extensions = ('.exe', '.dll', '.sys', '.pdf', '.doc', '.docx', '.xls', '.xlsx', 
                     '.zip', '.rar', '.jar', '.apk', '.elf', '.so', '.dylib')
    
    pattern = '**/*' if recursive else '*'
    
    for file_path in directory.glob(pattern):
        if file_path.is_file() and file_path.suffix.lower() in extensions:
            samples.append(file_path)
    
    return sorted(samples)


def _analyze_single_sample(sample_path: Path, timeout, no_static, no_dynamic, format, output_dir):
    """Analyze a single sample (for parallel execution)"""
    try:
        analyzer = MalwareAnalyzer()
        
        result = analyzer.analyze(
            sample_path=sample_path,
            static_analysis=not no_static,
            dynamic_analysis=not no_dynamic,
            timeout=timeout or config.get('analysis.timeout', 300)
        )
        
        # Generate report
        reporter = ReportGenerator()
        report_format = format or config.get('reporting.format', 'html')
        
        # Use output_dir if specified, otherwise default reports directory
        if output_dir:
            output_path = Path(output_dir) / f"{sample_path.stem}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{report_format}"
        else:
            output_path = None
        
        report_path = reporter.generate_report(result, format=report_format, output_path=output_path)
        
        return {
            'sample': sample_path.name,
            'success': True,
            'threat_level': result.threat_level,
            'threats': len(result.threat_detections),
            'report': report_path
        }
    except Exception as e:
        return {
            'sample': sample_path.name,
            'success': False,
            'error': str(e)
        }


def _analyze_directory(directory: Path, timeout, no_static, no_dynamic, format, output, live, recursive, parallel, extensions):
    """Analyze all samples in a directory"""
    console.print(f"\n[bold cyan]=== Directory Analysis ===[/bold cyan]")
    console.print(f"Directory: [yellow]{directory}[/yellow]")
    console.print(f"Recursive: [yellow]{'Yes' if recursive else 'No'}[/yellow]")
    console.print(f"Workers: [yellow]{parallel}[/yellow]\n")
    
    # Collect samples
    console.print("[bold]Collecting samples...[/bold]")
    samples = _collect_samples(directory, recursive, extensions)
    
    if not samples:
        console.print("[yellow]No samples found matching criteria[/yellow]")
        return
    
    console.print(f"Found [bold green]{len(samples)}[/bold green] samples to analyze\n")
    
    # Create output directory
    output_dir = Path(output) if output else Path("reports") / f"batch_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    results = []
    
    # Progress tracking (without spinner to avoid Unicode issues on Windows)
    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("({task.completed}/{task.total})"),
        TimeElapsedColumn(),
        console=console
    ) as progress:
        
        task = progress.add_task("[cyan]Analyzing samples...", total=len(samples))
        
        if parallel > 1:
            # Parallel execution
            with ThreadPoolExecutor(max_workers=parallel) as executor:
                futures = {
                    executor.submit(_analyze_single_sample, sample, timeout, no_static, no_dynamic, format, output_dir): sample
                    for sample in samples
                }
                
                for future in as_completed(futures):
                    result = future.result()
                    results.append(result)
                    progress.advance(task)
        else:
            # Sequential execution
            for sample in samples:
                result = _analyze_single_sample(sample, timeout, no_static, no_dynamic, format, output_dir)
                results.append(result)
                progress.advance(task)
    
    # Display summary
    console.print(f"\n[bold cyan]=== Analysis Complete ===[/bold cyan]\n")
    
    # Summary table (use SIMPLE box to avoid Unicode issues on Windows)
    summary_table = Table(title="Analysis Summary", box=box.SIMPLE)
    summary_table.add_column("Sample", style="cyan")
    summary_table.add_column("Status", style="green")
    summary_table.add_column("Threat Level", style="yellow")
    summary_table.add_column("Threats", justify="right")
    
    successful = 0
    failed = 0
    critical_threats = 0
    
    for result in results:
        if result['success']:
            successful += 1
            status = "[OK]"
            threat_level = result['threat_level']
            threats = str(result['threats'])
            if result['threats'] > 0:
                critical_threats += 1
        else:
            failed += 1
            status = "[FAIL]"
            threat_level = "Error"
            threats = "-"
        
        summary_table.add_row(
            result['sample'],
            status,
            threat_level,
            threats
        )
    
    console.print(summary_table)
    
    # Statistics
    console.print(f"\n[bold]Statistics:[/bold]")
    console.print(f"  Total Samples: {len(samples)}")
    console.print(f"  Successful: [green]{successful}[/green]")
    console.print(f"  Failed: [red]{failed}[/red]")
    console.print(f"  Threats Detected: [red]{critical_threats}[/red]")
    console.print(f"\n[bold]Reports saved to:[/bold] [cyan]{output_dir}[/cyan]\n")


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
@click.option('--timeout', '-t', default=None, type=int, help='Analysis timeout in seconds (default: 300)')
@click.option('--no-static', is_flag=True, help='Disable static analysis (PE parsing, hash calculation)')
@click.option('--no-dynamic', is_flag=True, help='Disable dynamic analysis (sandbox execution)')
@click.option('--format', '-f', type=click.Choice(['html', 'json', 'markdown']), help='Report format (default: html)')
@click.option('--output', '-o', type=click.Path(), help='Output directory or file path (supports absolute paths)')
@click.option('--live', is_flag=True, help='Show real-time analysis dashboard with live telemetry')
@click.option('--recursive', '-r', is_flag=True, help='Recursively analyze all files in directory')
@click.option('--parallel', '-p', type=int, default=1, help='Number of parallel workers for batch analysis (1-16)')
@click.option('--extensions', '-e', multiple=True, help='File extensions to analyze (e.g., .exe .dll .pdf)')
def analyze(sample, timeout, no_static, no_dynamic, format, output, live, recursive, parallel, extensions):
    """
    Analyze a malware sample or entire directory of samples
    
    \b
    SAMPLE: Path to the file or directory to analyze
            Supports both relative and absolute paths
            Works across all drives (C:/, D:/, etc.)
    
    \b
    SINGLE FILE EXAMPLES:
        python -m sentinel analyze "C:/Samples/malware.exe" --live
        python -m sentinel analyze "D:/suspicious/file.pdf" --format json
        python -m sentinel analyze "C:/Downloads/sample.exe" --timeout 600
    
    \b
    DIRECTORY EXAMPLES:
        python -m sentinel analyze "C:/MalwareSamples" --recursive
        python -m sentinel analyze "D:/Samples" -r --parallel 4
        python -m sentinel analyze "C:/Mixed" -r -e .exe -e .dll
    
    \b
    ADVANCED EXAMPLES:
        # Parallel analysis with custom output
        python -m sentinel analyze "D:/Malware" -r -p 8 -o "C:/Reports"
        
        # JSON output for automation
        python -m sentinel analyze "C:/sample.exe" -f json -o "C:/report.json"
        
        # Extended timeout with live monitoring
        python -m sentinel analyze "D:/threat.exe" -t 1800 --live
    
    \b
    FEATURES:
        ✓ Static Analysis: PE parsing, hash calculation, metadata extraction
        ✓ Dynamic Analysis: Sandboxed execution with behavioral monitoring  
        ✓ Batch Processing: Analyze entire directories in parallel
        ✓ Real-time Dashboard: Live event monitoring with --live flag
        ✓ Multiple Formats: HTML, JSON, or Markdown reports
        ✓ Cross-drive Support: Works on C:/, D:/, or any mounted drive
    """
    print_banner()
    
    sample_path = Path(sample)
    
    # Check if it's a directory
    if sample_path.is_dir():
        _analyze_directory(
            sample_path, timeout, no_static, no_dynamic, 
            format, output, live, recursive, parallel, extensions
        )
    else:
        # Single file analysis
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
        
        detections_table = Table(show_header=True, box=box.SIMPLE)
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
    """
    View an existing analysis report in terminal or browser
    
    \b
    REPORT_FILE: Path to the report file (HTML, JSON, or Markdown)
                 Supports absolute paths across all drives
    
    \b
    EXAMPLES:
        python -m sentinel view "C:/Reports/analysis_20240103.json"
        python -m sentinel view "D:/Analysis/malware_report.html"
        python -m sentinel view "C:/Reports/batch_analysis.md"
    
    \b
    FEATURES:
        ✓ Auto-opens HTML reports in default browser
        ✓ Pretty-prints JSON reports in terminal
        ✓ Displays Markdown reports with formatting
        ✓ Cross-drive path support
    """
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
    """
    Display Sentinel Framework system information and configuration
    
    \b
    Shows:
        • Framework version
        • Sandbox configuration (Docker/Process isolation)
        • Default analysis timeout
        • Report format settings
        • Enabled behavioral monitors
        • Output directory location
    
    \b
    EXAMPLE:
        python -m sentinel info
    """
    print_banner()
    
    info_table = Table(show_header=False, box=box.SIMPLE)
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


@cli.command(name="list-reports")
@click.option('--format', '-f', type=click.Choice(['html', 'json', 'markdown', 'all']), default='all', help='Filter reports by format')
@click.option('--limit', '-l', type=int, default=20, help='Maximum number of reports to display (default: 20)')
def list_reports(format, limit):
    """
    List all generated analysis reports with details
    
    \b
    FEATURES:
        • Shows report name, type, size, and modification date
        • Filters by format (HTML, JSON, Markdown, or all)
        • Sorts by newest first
        • Customizable result limit
    
    \b
    EXAMPLES:
        python -m sentinel list-reports
        python -m sentinel list-reports --format html --limit 50
        python -m sentinel list-reports -f json -l 10
    """
    reports_dir = Path(config.get('reporting.output_dir', 'reports'))
    
    if not reports_dir.exists():
        console.print(f"[yellow]No reports directory found at: {reports_dir}[/yellow]")
        return
    
    console.print(f"\n[bold cyan]=== Analysis Reports ===[/bold cyan]")
    console.print(f"Location: [yellow]{reports_dir.absolute()}[/yellow]\n")
    
    # Collect reports
    patterns = {
        'html': '**/*.html',
        'json': '**/*.json',
        'markdown': '**/*.md',
        'all': '**/*'
    }
    
    pattern = patterns.get(format, '**/*')
    reports = []
    
    for report_path in reports_dir.glob(pattern):
        if report_path.is_file() and report_path.suffix in ['.html', '.json', '.md']:
            reports.append({
                'path': report_path,
                'name': report_path.name,
                'size': report_path.stat().st_size,
                'modified': datetime.fromtimestamp(report_path.stat().st_mtime),
                'type': report_path.suffix[1:].upper()
            })
    
    if not reports:
        console.print("[yellow]No reports found[/yellow]")
        return
    
    # Sort by modification time (newest first)
    reports.sort(key=lambda x: x['modified'], reverse=True)
    
    # Limit results
    reports = reports[:limit]
    
    # Display table
    table = Table(title=f"Found {len(reports)} reports", box=box.SIMPLE)
    table.add_column("Report", style="cyan")
    table.add_column("Type", style="magenta")
    table.add_column("Size", justify="right", style="yellow")
    table.add_column("Modified", style="green")
    
    for report in reports:
        size_kb = report['size'] / 1024
        size_str = f"{size_kb:.1f} KB" if size_kb < 1024 else f"{size_kb/1024:.1f} MB"
        table.add_row(
            report['name'],
            report['type'],
            size_str,
            report['modified'].strftime('%Y-%m-%d %H:%M:%S')
        )
    
    console.print(table)
    console.print(f"\n[dim]Showing {len(reports)} most recent reports[/dim]\n")


@cli.command(name="clean-reports")
@click.option('--older-than', '-o', type=int, help='Delete reports older than N days')
@click.option('--all', '-a', is_flag=True, help='Delete all reports (use with caution!)')
@click.confirmation_option(prompt='Are you sure you want to delete reports?')
def clean_reports(older_than, all):
    """
    Clean up old analysis reports to free disk space
    
    \b
    WARNING: This action cannot be undone!
             Confirmation prompt will appear before deletion
    
    \b
    EXAMPLES:
        # Delete reports older than 30 days
        python -m sentinel clean-reports --older-than 30
        
        # Delete all reports (asks for confirmation)
        python -m sentinel clean-reports --all
    
    \b
    FEATURES:
        • Shows number of deleted reports
        • Displays freed disk space
        • Requires confirmation before deletion
        • Safe cleanup of reports directory
    """
    reports_dir = Path(config.get('reporting.output_dir', 'reports'))
    
    if not reports_dir.exists():
        console.print("[yellow]No reports directory found[/yellow]")
        return
    
    deleted = 0
    total_size = 0
    
    with Progress(
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Cleaning reports...", total=None)
        
        for report_path in reports_dir.rglob('*'):
            if report_path.is_file():
                if all:
                    size = report_path.stat().st_size
                    report_path.unlink()
                    deleted += 1
                    total_size += size
                elif older_than:
                    age_days = (datetime.now() - datetime.fromtimestamp(report_path.stat().st_mtime)).days
                    if age_days > older_than:
                        size = report_path.stat().st_size
                        report_path.unlink()
                        deleted += 1
                        total_size += size
    
    size_mb = total_size / (1024 * 1024)
    console.print(f"\n[bold green]Deleted {deleted} reports[/bold green] ([yellow]{size_mb:.2f} MB[/yellow] freed)\n")


def main():
    """Main entry point"""
    try:
        cli()
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()

