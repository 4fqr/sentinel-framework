"""
Sentinel Framework - Rich CLI Display
Beautiful, informative terminal UI with real-time updates
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn
from rich.layout import Layout
from rich.live import Live
from rich.tree import Tree
from rich import box
from rich.text import Text
from rich.syntax import Syntax

from sentinel.core.events import BehaviorEvent, EventSeverity, EventType


console = Console(legacy_windows=True)


class ThreatLevelIndicator:
    """Visual threat level indicators with colors"""
    
    INDICATORS = {
        'clean': ('✓', 'bold green', 'Clean'),
        'suspicious': ('⚠', 'bold yellow', 'Suspicious'),
        'likely_malicious': ('⚠⚠', 'bold orange1', 'Likely Malicious'),
        'malicious': ('✖', 'bold red', 'Malicious'),
        'critical': ('☠', 'bold red on white', 'CRITICAL THREAT')
    }
    
    @staticmethod
    def get_indicator(threat_level: str) -> tuple:
        """Get icon, style, and label for threat level"""
        return ThreatLevelIndicator.INDICATORS.get(
            threat_level.lower(),
            ('?', 'white', 'Unknown')
        )


class SeverityIndicator:
    """Visual severity indicators for events"""
    
    ICONS = {
        EventSeverity.CRITICAL: '🔴',
        EventSeverity.HIGH: '🟠',
        EventSeverity.MEDIUM: '🟡',
        EventSeverity.LOW: '🔵',
        EventSeverity.INFO: '⚪'
    }
    
    STYLES = {
        EventSeverity.CRITICAL: 'bold red',
        EventSeverity.HIGH: 'bold orange1',
        EventSeverity.MEDIUM: 'bold yellow',
        EventSeverity.LOW: 'cyan',
        EventSeverity.INFO: 'dim white'
    }
    
    @staticmethod
    def format(severity: EventSeverity) -> str:
        """Format severity with icon and color"""
        icon = SeverityIndicator.ICONS.get(severity, '⚪')
        style = SeverityIndicator.STYLES.get(severity, 'white')
        return f"[{style}]{icon} {severity.value.upper()}[/{style}]"


class AnalysisDisplay:
    """Real-time analysis display with rich formatting"""
    
    def __init__(self):
        self.start_time = datetime.now()
        self.events: List[BehaviorEvent] = []
        self.detections: List[Dict[str, Any]] = []
        self.stats = {
            'files_accessed': 0,
            'registry_modified': 0,
            'network_connections': 0,
            'processes_created': 0,
            'events_by_severity': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
        }
    
    def update_event(self, event: BehaviorEvent):
        """Add new event"""
        self.events.append(event)
        severity_key = event.severity.value
        self.stats['events_by_severity'][severity_key] += 1
        
        # Update specific counters
        if event.event_type in [EventType.FILE_CREATED, EventType.FILE_MODIFIED, EventType.FILE_DELETED]:
            self.stats['files_accessed'] += 1
        elif event.event_type == EventType.REGISTRY_MODIFIED:
            self.stats['registry_modified'] += 1
        elif event.event_type == EventType.NETWORK_CONNECTION:
            self.stats['network_connections'] += 1
        elif event.event_type in [EventType.PROCESS_CREATED, EventType.PROCESS_TERMINATED]:
            self.stats['processes_created'] += 1
    
    def add_detection(self, detection: Dict[str, Any]):
        """Add threat detection"""
        self.detections.append(detection)
    
    def generate_layout(self, current_phase: str = "Analyzing") -> Layout:
        """Generate complete display layout"""
        layout = Layout()
        
        # Split into header, body, footer
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=4)
        )
        
        # Header with current phase
        elapsed = (datetime.now() - self.start_time).total_seconds()
        header_text = Text(
            f"SENTINEL FRAMEWORK - {current_phase.upper()} | Elapsed: {elapsed:.1f}s",
            style="bold white on blue",
            justify="center"
        )
        layout["header"].update(Panel(header_text, border_style="blue"))
        
        # Body split into stats, events, and detections
        layout["body"].split_row(
            Layout(name="stats", ratio=1),
            Layout(name="activity", ratio=2)
        )
        
        # Stats panel
        layout["stats"].update(self._create_stats_panel())
        
        # Activity (events + detections)
        layout["activity"].split_column(
            Layout(name="events", ratio=2),
            Layout(name="detections", ratio=1)
        )
        
        layout["activity"]["events"].update(self._create_events_panel())
        layout["activity"]["detections"].update(self._create_detections_panel())
        
        # Footer with controls
        footer_text = Text.assemble(
            ("Press ", "dim"),
            ("Ctrl+C", "bold red"),
            (" to stop analysis and view results", "dim")
        )
        layout["footer"].update(Panel(footer_text, border_style="dim"))
        
        return layout
    
    def _create_stats_panel(self) -> Panel:
        """Create statistics panel"""
        table = Table(show_header=False, box=box.SIMPLE, padding=(0, 1))
        table.add_column("Metric", style="cyan", no_wrap=True)
        table.add_column("Count", style="bold yellow", justify="right")
        
        table.add_row("Total Events", str(len(self.events)))
        table.add_row("", "")  # Spacer
        table.add_row("Files", str(self.stats['files_accessed']))
        table.add_row("Registry", str(self.stats['registry_modified']))
        table.add_row("Network", str(self.stats['network_connections']))
        table.add_row("Processes", str(self.stats['processes_created']))
        table.add_row("", "")  # Spacer
        
        # Severity breakdown
        for severity, count in self.stats['events_by_severity'].items():
            if count > 0:
                icon = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🔵', 'info': '⚪'}[severity]
                table.add_row(f"{icon} {severity.title()}", str(count))
        
        return Panel(table, title="[bold]Activity Statistics[/bold]", border_style="green")
    
    def _create_events_panel(self) -> Panel:
        """Create recent events panel"""
        table = Table(show_header=True, box=box.SIMPLE_HEAD)
        table.add_column("Time", style="dim", width=8)
        table.add_column("Type", style="cyan", width=18)
        table.add_column("Description", style="white")
        table.add_column("Sev", justify="center", width=4)
        
        # Show last 8 events
        for event in self.events[-8:]:
            elapsed = (event.timestamp - self.start_time).total_seconds()
            severity_icon = SeverityIndicator.ICONS.get(event.severity, '⚪')
            
            # Truncate description
            desc = event.description[:45] + "..." if len(event.description) > 45 else event.description
            
            table.add_row(
                f"{elapsed:>6.1f}s",
                event.event_type.value[:18],
                desc,
                severity_icon
            )
        
        if not self.events:
            table.add_row("", "", "[dim]No events yet...[/dim]", "")
        
        return Panel(table, title="[bold]Recent Events[/bold]", border_style="blue")
    
    def _create_detections_panel(self) -> Panel:
        """Create threat detections panel"""
        if not self.detections:
            return Panel(
                "[dim]No threats detected yet...[/dim]",
                title="[bold]Threat Detections[/bold]",
                border_style="yellow"
            )
        
        table = Table(show_header=True, box=box.SIMPLE_HEAD)
        table.add_column("Threat", style="bold red")
        table.add_column("Confidence", justify="right", style="yellow")
        
        for detection in self.detections[-5:]:
            threat_name = detection.get('threat_name', 'Unknown')
            confidence = detection.get('confidence', 0)
            severity = detection.get('severity', 'medium')
            
            severity_style = SeverityIndicator.STYLES.get(
                EventSeverity(severity),
                'white'
            )
            
            table.add_row(
                f"[{severity_style}]{threat_name}[/{severity_style}]",
                f"{confidence}%"
            )
        
        return Panel(
            table,
            title=f"[bold red]⚠ Threat Detections ({len(self.detections)})[/bold red]",
            border_style="red"
        )


class ResultsDisplay:
    """Display final analysis results with detailed breakdown"""
    
    @staticmethod
    def show_results(result: Any):
        """Display comprehensive analysis results"""
        console.print("\n")
        
        # Main verdict panel (handles errors internally)
        ResultsDisplay._show_verdict(result)
        
        # If it's an error result, don't try to show other sections
        if result.sample_hash == "error" or "Error:" in str(result.verdict):
            console.print("\n[dim]Analysis could not be completed due to the error above.[/dim]\n")
            return
        
        console.print("\n")
        
        # Details in sections
        if result.static_analysis:
            ResultsDisplay._show_static_analysis(result.static_analysis)
        
        if result.threat_detections:
            ResultsDisplay._show_threat_detections(result.threat_detections)
        
        if hasattr(result, 'behavioral_events') and result.behavioral_events:
            ResultsDisplay._show_behavioral_summary(result.behavioral_events)
        
        # IOCs if available
        if result.static_analysis.get('strings_analysis', {}).get('iocs'):
            ResultsDisplay._show_iocs(result.static_analysis['strings_analysis']['iocs'])
    
    @staticmethod
    def _show_verdict(result: Any):
        """Show main verdict with risk score"""
        # Check if this is an error result
        is_error = result.sample_hash == "error" or "Error:" in str(result.verdict)
        
        if is_error:
            # Simplified error display
            error_msg = result.verdict if isinstance(result.verdict, str) else "Analysis failed"
            
            console.print(Panel(
                f"[bold red]✗ ANALYSIS ERROR[/bold red]\n\n"
                f"[yellow]{error_msg}[/yellow]\n\n"
                f"File: {Path(result.sample_path).name}\n"
                f"Path: {result.sample_path}",
                title="[bold red]ERROR[/bold red]",
                border_style="red",
                expand=False
            ))
            return
        
        icon, style, label = ThreatLevelIndicator.get_indicator(
            getattr(result, 'verdict', 'unknown')
        )
        
        # Create verdict table
        verdict_table = Table(show_header=False, box=box.DOUBLE, padding=(1, 2))
        verdict_table.add_column("Property", style="bold cyan", width=20)
        verdict_table.add_column("Value", style="bold white")
        
        verdict_table.add_row("File", Path(result.sample_path).name)
        verdict_table.add_row("SHA256", result.sample_hash[:16] + "..." if len(result.sample_hash) > 16 else result.sample_hash)
        verdict_table.add_row("File Type", result.file_type)
        verdict_table.add_row("Size", f"{result.file_size:,} bytes")
        verdict_table.add_row("", "")
        
        # Verdict with colored indicator
        verdict_table.add_row(
            "VERDICT",
            f"[{style}]{icon} {label.upper()}[/{style}]"
        )
        verdict_table.add_row(
            "Risk Score",
            f"[{style}]{result.risk_score}/100[/{style}]"
        )
        verdict_table.add_row("Analysis Time", f"{result.analysis_time:.2f}s")
        
        # Extract border color from style (handles both 'color' and 'bold color' formats)
        border_color = style.split()[-1] if ' ' in style else style
        
        console.print(Panel(
            verdict_table,
            title="[bold white]ANALYSIS VERDICT[/bold white]",
            border_style=border_color
        ))
    
    @staticmethod
    def _show_static_analysis(static_analysis: Dict[str, Any]):
        """Show static analysis results"""
        # Deep PE analysis
        if 'deep_pe_analysis' in static_analysis:
            ResultsDisplay._show_pe_analysis(static_analysis['deep_pe_analysis'])
        
        # String analysis
        if 'strings_analysis' in static_analysis:
            ResultsDisplay._show_string_analysis(static_analysis['strings_analysis'])
    
    @staticmethod
    def _show_pe_analysis(pe_data: Dict[str, Any]):
        """Show PE analysis results"""
        tree = Tree("📦 [bold cyan]PE Analysis[/bold cyan]")
        
        # Entropy
        if 'entropy_analysis' in pe_data:
            entropy = pe_data['entropy_analysis']
            entropy_node = tree.add(f"📊 Entropy: [yellow]{entropy.get('overall_entropy', 0):.2f}[/yellow]/8.0")
            if entropy.get('high_entropy_sections'):
                high_ent_node = entropy_node.add("[red]⚠ High Entropy Sections (Possible Packing/Encryption)[/red]")
                for section in entropy.get('high_entropy_sections', [])[:3]:
                    high_ent_node.add(f"{section['name']}: {section['entropy']:.2f}")
        
        # Packer detection
        if 'packer_detection' in pe_data:
            packer = pe_data['packer_detection']
            if packer.get('detected'):
                packer_node = tree.add("[bold red]📦 Packer Detected[/bold red]")
                if packer.get('packer_name'):
                    packer_node.add(f"Type: [red]{packer['packer_name']}[/red]")
                for indicator in packer.get('indicators', [])[:3]:
                    packer_node.add(f"• {indicator}")
        
        # Suspicious imports
        if 'import_analysis' in pe_data:
            imports = pe_data['import_analysis']
            if imports.get('suspicious_imports'):
                import_node = tree.add("[yellow]⚠ Suspicious API Imports[/yellow]")
                for category, apis in imports.get('api_categories', {}).items():
                    if apis and category in ['Process Injection', 'Anti-Debug', 'Keylogging']:
                        cat_node = import_node.add(f"[red]{category}[/red]")
                        for api in apis[:3]:
                            cat_node.add(f"• {api}")
        
        console.print(Panel(tree, border_style="cyan"))
    
    @staticmethod
    def _show_string_analysis(strings_data: Dict[str, Any]):
        """Show string analysis results"""
        table = Table(title="[bold cyan]🔤 String Analysis[/bold cyan]", box=box.ROUNDED)
        table.add_column("Category", style="cyan")
        table.add_column("Count", justify="right", style="yellow")
        table.add_column("Samples", style="white")
        
        table.add_row(
            "Total Strings",
            str(strings_data.get('total_strings', 0)),
            ""
        )
        
        # Suspicious keywords
        if strings_data.get('suspicious_keywords'):
            keywords = strings_data['suspicious_keywords'][:5]
            table.add_row(
                "[red]Suspicious Keywords[/red]",
                str(len(strings_data.get('suspicious_keywords', []))),
                ", ".join(keywords)
            )
        
        # High entropy strings
        if strings_data.get('high_entropy_strings'):
            samples = [s['string'][:20] + "..." for s in strings_data['high_entropy_strings'][:2]]
            table.add_row(
                "[yellow]High Entropy[/yellow]",
                str(len(strings_data.get('high_entropy_strings', []))),
                ", ".join(samples)
            )
        
        console.print(table)
    
    @staticmethod
    def _show_threat_detections(detections: List[Dict[str, Any]]):
        """Show threat detections with evidence"""
        if not detections:
            return
        
        console.print("\n[bold red]⚠ THREAT DETECTIONS[/bold red]\n")
        
        for i, detection in enumerate(detections, 1):
            threat_name = detection.get('threat_name', 'Unknown Threat')
            confidence = detection.get('confidence', 0)
            severity = detection.get('severity', 'medium')
            description = detection.get('description', '')
            evidence = detection.get('evidence', [])
            
            # Severity styling
            severity_enum = EventSeverity(severity)
            style = SeverityIndicator.STYLES.get(severity_enum, 'white')
            icon = SeverityIndicator.ICONS.get(severity_enum, '⚪')
            
            # Create detection panel
            detection_content = f"[bold]{threat_name}[/bold]\n"
            detection_content += f"\n{description}\n"
            detection_content += f"\n[bold]Confidence:[/bold] [{style}]{confidence}%[/{style}]\n"
            
            if evidence:
                detection_content += f"\n[bold]Evidence:[/bold]\n"
                for item in evidence[:5]:
                    detection_content += f"  • {item}\n"
                if len(evidence) > 5:
                    detection_content += f"  ... and {len(evidence) - 5} more\n"
            
            console.print(Panel(
                detection_content,
                title=f"[{style}]{icon} Detection #{i}[/{style}]",
                border_style=style.split()[1] if ' ' in style else style,
                expand=False
            ))
    
    @staticmethod
    def _show_behavioral_summary(events: List[Dict[str, Any]]):
        """Show behavioral event summary"""
        if not events:
            return
        
        table = Table(title="[bold cyan]📋 Behavioral Summary[/bold cyan]", box=box.ROUNDED)
        table.add_column("Event Type", style="cyan")
        table.add_column("Count", justify="right", style="yellow")
        table.add_column("Highest Severity", justify="center")
        
        # Group by event type
        event_groups = {}
        for event in events:
            event_type = event.get('event_type', 'unknown')
            if event_type not in event_groups:
                event_groups[event_type] = {
                    'count': 0,
                    'max_severity': 'info'
                }
            event_groups[event_type]['count'] += 1
            
            # Track highest severity
            current_severity = event.get('severity', 'info')
            severity_order = ['info', 'low', 'medium', 'high', 'critical']
            if severity_order.index(current_severity) > severity_order.index(event_groups[event_type]['max_severity']):
                event_groups[event_type]['max_severity'] = current_severity
        
        # Add rows
        for event_type, data in sorted(event_groups.items(), key=lambda x: x[1]['count'], reverse=True):
            severity_enum = EventSeverity(data['max_severity'])
            icon = SeverityIndicator.ICONS.get(severity_enum, '⚪')
            table.add_row(event_type, str(data['count']), icon)
        
        console.print(table)
    
    @staticmethod
    def _show_iocs(iocs: Dict[str, List[str]]):
        """Show indicators of compromise"""
        has_iocs = any(len(v) > 0 for v in iocs.values())
        if not has_iocs:
            return
        
        console.print("\n[bold yellow]🔍 Indicators of Compromise (IOCs)[/bold yellow]\n")
        
        for ioc_type, items in iocs.items():
            if items:
                tree = Tree(f"[cyan]{ioc_type.upper()}[/cyan]")
                for item in items[:10]:  # Show first 10
                    tree.add(f"[yellow]{item}[/yellow]")
                if len(items) > 10:
                    tree.add(f"[dim]... and {len(items) - 10} more[/dim]")
                console.print(tree)
                console.print()


def show_banner():
    """Display Sentinel banner"""
    banner = """
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║   ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗    ║
║   ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║    ║
║   ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║    ║
║   ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║    ║
║   ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗║
║   ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝║
║                                                                   ║
║   ADVANCED MALWARE ANALYSIS FRAMEWORK                             ║
║   Real-time Behavioral Monitoring | Deep Static Analysis          ║
║   Accurate Threat Detection | Professional Reporting              ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold cyan")


from pathlib import Path
