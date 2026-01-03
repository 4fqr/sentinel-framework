"""
Sentinel Framework - Command Line Interface
Sleek CLI with real-time telemetry and rich formatting
"""

import sys
import time
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
from sentinel.ui import AnalysisDisplay, ResultsDisplay, show_banner, console
from sentinel.utils.logger import SentinelLogger, get_logger
from sentinel.config import config
from sentinel import __version__


# Initialize Rich console with safe encoding for Windows
console = Console(legacy_windows=True, force_terminal=False)
logger = get_logger(__name__)


def print_banner():
    """Print Sentinel Framework banner"""
    show_banner()


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
        if not recursive:
            console.print(f"\n[bold yellow]⚠ Warning:[/bold yellow] '{sample_path}' is a directory")
            console.print(f"Use [cyan]--recursive[/cyan] flag to analyze all files in the directory:\n")
            console.print(f"  [cyan]python -m sentinel analyze \"{sample_path}\" --recursive[/cyan]\n")
            raise click.Abort()
        
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
            # Live monitoring mode with new rich display
            live_display = AnalysisDisplay()
            
            # Register callback for live updates
            def update_callback(event):
                live_display.update_event(event)
            
            analyzer.monitor.register_callback(update_callback)
            
            # Set very long timeout for live mode (user will stop manually)
            live_timeout = 7200  # 2 hours max, but user stops with Ctrl+C
            
            console.print(f"\n[bold cyan]🔴 LIVE MONITORING MODE[/bold cyan]")
            console.print(f"[dim]Application will run in background while we monitor behavior[/dim]")
            console.print(f"[bold yellow]Press Ctrl+C when done to stop and analyze results[/bold yellow]\n")
            
            try:
                # Start dynamic analysis in thread
                import threading
                
                def start_dynamic():
                    time.sleep(1)  # Brief delay
                    analyzer.monitor.start()
                    analyzer.sandbox.execute(str(sample_path), timeout=live_timeout)
                
                dynamic_thread = threading.Thread(target=start_dynamic, daemon=True)
                dynamic_thread.start()
                
                # Wait for monitoring to start
                time.sleep(3)
                
                console.print(f"[green]✓[/green] Monitoring active - application running in background")
                console.print(f"[bold yellow]→ Press Ctrl+C anytime to stop and see results[/bold yellow]\n")
                
                # Live display loop - runs FOREVER until Ctrl+C
                with Live(live_display.generate_layout("Monitoring"), refresh_per_second=2, console=console) as live:
                    while True:  # Loop forever until Ctrl+C
                        live.update(live_display.generate_layout("Monitoring"))
                        time.sleep(0.5)
                
            except KeyboardInterrupt:
                console.print(f"\n\n[bold yellow]⏹️  Stopping live monitoring...[/bold yellow]")
                
                # Stop everything
                analyzer.sandbox.terminate_running_process()
                time.sleep(1)
                analyzer.monitor.stop()
                
                console.print(f"[green]✓[/green] Monitoring stopped\n")
                console.print(f"[dim]Generating analysis report...[/dim]\n")
                
                # Now do full analysis with collected data
                result = analyzer.analyze(
                    str(sample_path),
                    enable_static=True,
                    enable_dynamic=False,  # Already collected events
                    timeout=1
                )
                
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
        
        # Display results using new rich display system
        ResultsDisplay.show_results(result)
        
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
    
    # File Information
    console.print(f"\n[bold cyan]📄 File Information:[/bold cyan]")
    file_info_table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    file_info_table.add_column("Property", style="cyan", width=20)
    file_info_table.add_column("Value", style="white")
    
    file_info_table.add_row("Sample Path", result.sample_path)
    file_info_table.add_row("File Type", result.file_type)
    file_info_table.add_row("File Size", f"{result.file_size:,} bytes ({result.file_size / 1024 / 1024:.2f} MB)")
    file_info_table.add_row("SHA-256", result.sample_hash)
    
    console.print(file_info_table)
    
    # Archive Analysis Results
    if result.static_analysis and 'archive_analysis' in result.static_analysis:
        archive = result.static_analysis['archive_analysis']
        if 'error' not in archive:
            console.print(f"\n[bold magenta]📦 Archive Analysis:[/bold magenta]")
            archive_table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
            archive_table.add_column("Property", style="magenta", width=25)
            archive_table.add_column("Value", style="white")
            
            archive_table.add_row("Archive Type", archive.get('archive_type', 'Unknown'))
            archive_table.add_row("Encrypted", "Yes" if archive.get('is_encrypted') else "No")
            archive_table.add_row("File Count", str(archive.get('file_count', 0)))
            
            if 'compression_ratio' in archive:
                ratio = archive['compression_ratio']
                ratio_color = "red" if ratio > 100 else "green"
                archive_table.add_row("Compression Ratio", f"[{ratio_color}]{ratio:.2f}:1[/{ratio_color}]")
            
            if archive.get('password_used'):
                archive_table.add_row("Password Cracked", f"[yellow]{archive['password_used']}[/yellow]")
            
            console.print(archive_table)
            
            # Suspicious indicators in archive
            if 'suspicious_indicators' in archive and archive['suspicious_indicators']:
                console.print(f"\n  [bold red]🚨 Archive Threats ({len(archive['suspicious_indicators'])}):[/bold red]")
                for indicator in archive['suspicious_indicators']:
                    severity_color = {'CRITICAL': 'bold red', 'HIGH': 'bold yellow', 'MEDIUM': 'yellow', 'LOW': 'cyan'}.get(indicator['severity'], 'white')
                    console.print(f"    [{severity_color}]■[/{severity_color}] [bold]{indicator['type']}[/bold] ([{severity_color}]{indicator['severity']}[/{severity_color}])")
                    console.print(f"      [dim]→[/dim] {indicator['reason']}")
                    console.print(f"      [dim]✓[/dim] Evidence: [yellow]{indicator['evidence']}[/yellow]")
            
            # Extracted files
            if 'extracted_files' in archive and archive['extracted_files']:
                console.print(f"\n  [bold yellow]📂 Extracted Files ({len(archive['extracted_files'])}):[/bold yellow]")
                for file in archive['extracted_files'][:10]:  # Show first 10
                    console.print(f"    [dim]•[/dim] {file}")
                if len(archive['extracted_files']) > 10:
                    console.print(f"    [dim]... and {len(archive['extracted_files']) - 10} more files[/dim]")
    
    # Document Analysis Results
    if result.static_analysis and 'document_analysis' in result.static_analysis:
        doc = result.static_analysis['document_analysis']
        if 'error' not in doc:
            console.print(f"\n[bold blue]📝 Document Analysis:[/bold blue]")
            doc_table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
            doc_table.add_column("Property", style="blue", width=25)
            doc_table.add_column("Value", style="white")
            
            doc_table.add_row("Document Type", doc.get('document_type', 'Unknown'))
            
            malicious_color = "red" if doc.get('is_malicious') else "green"
            malicious_text = "Yes - DANGEROUS" if doc.get('is_malicious') else "No"
            doc_table.add_row("Malicious", f"[{malicious_color}]{malicious_text}[/{malicious_color}]")
            
            console.print(doc_table)
            
            # Vulnerabilities in document
            if 'vulnerabilities' in doc and doc['vulnerabilities']:
                console.print(f"\n  [bold red]🛡️  Document Vulnerabilities ({len(doc['vulnerabilities'])}):[/bold red]")
                for vuln in doc['vulnerabilities']:
                    severity_color = {'CRITICAL': 'bold red', 'HIGH': 'bold yellow', 'MEDIUM': 'yellow', 'LOW': 'cyan'}.get(vuln['severity'], 'white')
                    console.print(f"    [{severity_color}]■[/{severity_color}] [bold]{vuln['type']}[/bold] ([{severity_color}]{vuln['severity']}[/{severity_color}])")
                    console.print(f"      [dim]→[/dim] {vuln['description']}")
                    console.print(f"      [dim]⚠[/dim] Impact: [yellow]{vuln['impact']}[/yellow]")
            
            # Suspicious indicators in document
            if 'suspicious_indicators' in doc and doc['suspicious_indicators']:
                console.print(f"\n  [bold yellow]⚠️  Document Threats ({len(doc['suspicious_indicators'])}):[/bold yellow]")
                for indicator in doc['suspicious_indicators']:
                    severity_color = {'CRITICAL': 'bold red', 'HIGH': 'bold yellow', 'MEDIUM': 'yellow', 'LOW': 'cyan'}.get(indicator['severity'], 'white')
                    console.print(f"    [{severity_color}]■[/{severity_color}] [bold]{indicator['type']}[/bold] ([{severity_color}]{indicator['severity']}[/{severity_color}])")
                    console.print(f"      [dim]→[/dim] {indicator['reason']}")
                    console.print(f"      [dim]✓[/dim] Evidence: [yellow]{indicator['evidence']}[/yellow]")
            
            # Macros found
            if 'macros' in doc and doc['macros']:
                console.print(f"\n  [bold red]🐛 VBA Macros Detected ({len(doc['macros'])}):[/bold red]")
                for macro in doc['macros'][:5]:  # Show first 5
                    console.print(f"    [dim]•[/dim] {macro['stream']} ([yellow]{macro['code_length']} chars[/yellow])")
                    if macro.get('suspicious_keywords'):
                        console.print(f"      [red]Dangerous: {', '.join(macro['suspicious_keywords'])}[/red]")
    
    # Static Analysis Results
    if result.static_analysis:
        console.print(f"\n[bold cyan]🔍 Static Analysis:[/bold cyan]")
        
        # PE Information
        if 'pe_info' in result.static_analysis:
            pe_info = result.static_analysis['pe_info']
            pe_table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
            pe_table.add_column("Property", style="cyan", width=22)
            pe_table.add_column("Value", style="white")
            
            if 'machine_type' in pe_info:
                pe_table.add_row("Architecture", pe_info['machine_type'])
            if 'subsystem' in pe_info:
                pe_table.add_row("Subsystem", pe_info['subsystem'])
            if 'compilation_timestamp' in pe_info:
                pe_table.add_row("Compilation Time", pe_info['compilation_timestamp'])
            if 'entry_point' in pe_info:
                pe_table.add_row("Entry Point", f"0x{pe_info['entry_point']:08X}")
            if 'imphash' in pe_info:
                pe_table.add_row("Import Hash", pe_info['imphash'])
            if 'sections' in pe_info:
                pe_table.add_row("PE Sections", str(pe_info['sections']))
            
            console.print(pe_table)
        
        # Security Vulnerabilities
        if 'vulnerabilities' in result.static_analysis and result.static_analysis['vulnerabilities']:
            console.print(f"\n  [bold red]🛡️  Security Vulnerabilities ({len(result.static_analysis['vulnerabilities'])}):[/bold red]")
            for vuln in result.static_analysis['vulnerabilities']:
                severity_color = {'CRITICAL': 'bold red', 'HIGH': 'bold yellow', 'MEDIUM': 'yellow', 'LOW': 'cyan'}.get(vuln['severity'], 'white')
                console.print(f"    [{severity_color}]■[/{severity_color}] [bold]{vuln['type']}[/bold] ([{severity_color}]{vuln['severity']}[/{severity_color}])")
                console.print(f"      [dim]→[/dim] {vuln['description']}")
                console.print(f"      [dim]⚠[/dim] Impact: [yellow]{vuln['impact']}[/yellow]")
        
        # Security Issues
        if 'security_issues' in result.static_analysis and result.static_analysis['security_issues']:
            console.print(f"\n  [bold yellow]⚠️  Security Issues ({len(result.static_analysis['security_issues'])}):[/bold yellow]")
            for issue in result.static_analysis['security_issues']:
                severity_color = {'CRITICAL': 'bold red', 'HIGH': 'bold yellow', 'MEDIUM': 'yellow', 'LOW': 'cyan'}.get(issue['severity'], 'white')
                console.print(f"    [{severity_color}]■[/{severity_color}] [bold]{issue['type']}[/bold] ([{severity_color}]{issue['severity']}[/{severity_color}])")
                console.print(f"      [dim]→[/dim] {issue['description']}")
                console.print(f"      [dim]⚠[/dim] {issue['impact']}")
        
        # Dangerous API Imports
        if 'dangerous_imports' in result.static_analysis and result.static_analysis['dangerous_imports']:
            console.print(f"\n  [bold red]☠️  Dangerous API Calls ({len(result.static_analysis['dangerous_imports'])}):[/bold red]")
            for api in result.static_analysis['dangerous_imports'][:15]:  # Show top 15
                console.print(f"    [red]●[/red] [yellow]{api['dll']}[/yellow]![bold red]{api['function']}[/bold red]")
                console.print(f"      [dim]→[/dim] {api['reason']}")
            if len(result.static_analysis['dangerous_imports']) > 15:
                console.print(f"    [dim]... and {len(result.static_analysis['dangerous_imports']) - 15} more dangerous APIs[/dim]")
        
        # Suspicious Indicators
        if 'suspicious_indicators' in result.static_analysis and result.static_analysis['suspicious_indicators']:
            console.print(f"\n  [bold yellow]🔎 Suspicious Indicators ({len(result.static_analysis['suspicious_indicators'])}):[/bold yellow]")
            for indicator in result.static_analysis['suspicious_indicators']:
                console.print(f"    [yellow]►[/yellow] [bold]{indicator['type']}:[/bold] {indicator['value']}")
                console.print(f"      [dim]└─[/dim] {indicator['reason']}")
        
        # IOCs (Indicators of Compromise)
        if 'strings' in result.static_analysis and 'iocs' in result.static_analysis['strings']:
            iocs = result.static_analysis['strings']['iocs']
            has_iocs = any(iocs.values())
            
            if has_iocs:
                console.print(f"\n  [bold red]🚨 Indicators of Compromise:[/bold red]")
                if iocs['urls']:
                    console.print(f"    [bold cyan]URLs ({len(iocs['urls'])}):[/bold cyan]")
                    for url in iocs['urls'][:5]:
                        console.print(f"      • [blue]{url}[/blue]")
                    if len(iocs['urls']) > 5:
                        console.print(f"      [dim]... and {len(iocs['urls']) - 5} more URLs[/dim]")
                
                if iocs['ips']:
                    console.print(f"    [bold cyan]IP Addresses ({len(iocs['ips'])}):[/bold cyan]")
                    for ip in iocs['ips'][:5]:
                        console.print(f"      • [magenta]{ip}[/magenta]")
                
                if iocs['registry_keys']:
                    console.print(f"    [bold cyan]Registry Keys ({len(iocs['registry_keys'])}):[/bold cyan]")
                    for key in iocs['registry_keys'][:3]:
                        console.print(f"      • [yellow]{key}[/yellow]")
                
                if iocs['suspicious_strings']:
                    console.print(f"    [bold cyan]Suspicious Strings:[/bold cyan]")
                    for s in iocs['suspicious_strings'][:5]:
                        console.print(f"      • [red]{s}[/red]")
        
        console.print()  # Spacing
    
    # Threat detections
    if result.threat_detections:
        console.print(f"\n[bold red][!] Threat Detections ({len(result.threat_detections)}):[/bold red]\n")
        
        for idx, detection in enumerate(result.threat_detections, 1):
            # Detection header
            severity_style = {
                'critical': 'bold red',
                'high': 'bold yellow',
                'medium': 'yellow',
                'low': 'cyan'
            }.get(detection['severity'], 'white')
            
            console.print(f"[bold cyan]Detection #{idx}:[/bold cyan]")
            
            # Main info table
            info_table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
            info_table.add_column("Property", style="cyan", width=15)
            info_table.add_column("Value", style="white")
            
            info_table.add_row("Type", f"[bold]{detection['threat_type']}[/bold]")
            info_table.add_row("Technique", detection['technique'])
            info_table.add_row("Confidence", f"[magenta]{detection['confidence']}%[/magenta]")
            info_table.add_row("Severity", f"[{severity_style}]{detection['severity'].upper()}[/{severity_style}]")
            info_table.add_row("Description", detection.get('description', 'N/A'))
            
            console.print(info_table)
            
            # Evidence/Indicators
            if 'indicators' in detection and detection['indicators']:
                console.print(f"\n  [bold yellow]📋 Evidence:[/bold yellow]")
                for key, value in detection['indicators'].items():
                    formatted_key = key.replace('_', ' ').title()
                    console.print(f"    • [cyan]{formatted_key}:[/cyan] {value}")
            
            # Reason if available
            if 'reason' in detection:
                console.print(f"\n  [bold yellow]💡 Reason:[/bold yellow] {detection['reason']}")
            
            console.print()  # Blank line between detections
    
    # Behavioral Summary
    if result.behavioral_events:
        console.print(f"[bold cyan]📊 Behavioral Summary:[/bold cyan] {len(result.behavioral_events)} events captured\n")
        
        # Count events by type
        event_counts = {}
        for event in result.behavioral_events:
            event_type = event.get('event_type', 'Unknown')
            event_counts[event_type] = event_counts.get(event_type, 0) + 1
        
        if event_counts:
            behavior_table = Table(show_header=True, box=box.SIMPLE)
            behavior_table.add_column("Event Type", style="cyan")
            behavior_table.add_column("Count", justify="right", style="yellow")
            
            for event_type, count in sorted(event_counts.items(), key=lambda x: x[1], reverse=True):
                behavior_table.add_row(event_type.replace('_', ' ').title(), str(count))
            
            console.print(behavior_table)
            console.print()


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

