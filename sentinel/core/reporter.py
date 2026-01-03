"""
Sentinel Framework - Report Generator
Creates comprehensive analysis reports in multiple formats
"""

import json
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime
from jinja2 import Environment, FileSystemLoader, select_autoescape

from sentinel.config import config
from sentinel.utils.logger import get_logger
from sentinel.utils.helpers import ensure_directory, safe_json_dumps


logger = get_logger(__name__)


class ReportGenerator:
    """Generates comprehensive analysis reports"""
    
    def __init__(self):
        """Initialize report generator"""
        self.config = config.reporting_config
        self.output_dir = Path(self.config.get('output_dir', 'reports'))
        ensure_directory(self.output_dir)
        
        # Setup Jinja2 environment
        template_dir = Path(__file__).parent.parent / 'templates'
        ensure_directory(template_dir)
        
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(['html', 'xml'])
        )
        
        logger.info("Report generator initialized")
    
    def generate(
        self,
        analysis_result: Any,
        format: Optional[str] = None,
        output_file: Optional[str] = None
    ) -> str:
        """
        Generate analysis report
        
        Args:
            analysis_result: Analysis result to report
            format: Report format (html, json, markdown)
            output_file: Custom output file path
        
        Returns:
            Path to generated report
        """
        report_format = format or self.config.get('format', 'html')
        
        logger.info(f"Generating {report_format.upper()} report")
        
        if output_file is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            sample_name = Path(analysis_result.sample_path).stem
            output_file = self.output_dir / f"report_{sample_name}_{timestamp}.{report_format}"
        
        output_path = Path(output_file)
        ensure_directory(output_path.parent)
        
        if report_format == 'html':
            content = self._generate_html(analysis_result)
        elif report_format == 'json':
            content = self._generate_json(analysis_result)
        elif report_format == 'markdown':
            content = self._generate_markdown(analysis_result)
        else:
            raise ValueError(f"Unsupported format: {report_format}")
        
        # Write report
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        logger.info(f"Report generated: {output_path}")
        
        return str(output_path)
    
    def _generate_html(self, result: Any) -> str:
        """Generate HTML report"""
        try:
            template = self.jinja_env.get_template('report.html')
        except Exception:
            # Use inline template if file doesn't exist
            template = self.jinja_env.from_string(self._get_default_html_template())
        
        # Prepare data for template
        data = {
            'title': f'Sentinel Analysis Report - {Path(result.sample_path).name}',
            'generation_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'result': result,
            'verdict_color': self._get_verdict_color(result.verdict),
            'severity_colors': {
                'critical': '#dc3545',
                'high': '#fd7e14',
                'medium': '#ffc107',
                'low': '#17a2b8',
                'info': '#6c757d',
            }
        }
        
        return template.render(**data)
    
    def _generate_json(self, result: Any) -> str:
        """Generate JSON report"""
        report_data = {
            'report_metadata': {
                'generated_at': datetime.now().isoformat(),
                'generator': 'Sentinel Framework v1.0.0',
                'format_version': '1.0'
            },
            'sample_info': {
                'path': result.sample_path,
                'hash': result.sample_hash,
                'type': result.file_type,
                'size': result.file_size,
            },
            'analysis': {
                'time': result.analysis_time,
                'verdict': result.verdict,
                'risk_score': result.risk_score,
            },
            'static_analysis': result.static_analysis,
            'dynamic_analysis': {
                'events': result.behavioral_events,
                'sandbox_result': result.sandbox_result.to_dict() if result.sandbox_result else None,
            },
            'threat_detections': result.threat_detections,
        }
        
        return safe_json_dumps(report_data, indent=2)
    
    def _generate_markdown(self, result: Any) -> str:
        """Generate Markdown report"""
        md = []
        
        md.append(f"# Sentinel Analysis Report")
        md.append(f"\n**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        md.append("## Sample Information")
        md.append(f"- **File:** {result.sample_path}")
        md.append(f"- **SHA256:** {result.sample_hash}")
        md.append(f"- **Type:** {result.file_type}")
        md.append(f"- **Size:** {result.file_size} bytes")
        
        md.append(f"\n## Analysis Summary")
        md.append(f"- **Verdict:** {result.verdict}")
        md.append(f"- **Risk Score:** {result.risk_score}/100")
        md.append(f"- **Analysis Time:** {result.analysis_time:.2f}s")
        
        if result.threat_detections:
            md.append(f"\n## Threat Detections ({len(result.threat_detections)})")
            for i, detection in enumerate(result.threat_detections, 1):
                md.append(f"\n### {i}. {detection['threat_type']} - {detection['technique']}")
                md.append(f"- **Description:** {detection['description']}")
                md.append(f"- **Confidence:** {detection['confidence']}%")
                md.append(f"- **Severity:** {detection['severity'].upper()}")
        
        if result.behavioral_events:
            md.append(f"\n## Behavioral Events ({len(result.behavioral_events)})")
            md.append(f"Total events captured during execution: {len(result.behavioral_events)}")
        
        md.append("\n---")
        md.append("*Report generated by Sentinel Framework*")
        
        return '\n'.join(md)
    
    def _get_verdict_color(self, verdict: str) -> str:
        """Get color for verdict"""
        colors = {
            'Malicious': '#dc3545',
            'Suspicious': '#fd7e14',
            'Potentially Unwanted': '#ffc107',
            'Clean': '#28a745',
            'Unknown': '#6c757d',
        }
        return colors.get(verdict, '#6c757d')
    
    def _get_default_html_template(self) -> str:
        """Get default HTML template"""
        return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            padding: 20px;
            line-height: 1.6;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            font-weight: 700;
            letter-spacing: -1px;
        }
        .header .subtitle {
            opacity: 0.9;
            font-size: 1.1em;
        }
        .content {
            padding: 40px;
        }
        .verdict-banner {
            background: {{ verdict_color }};
            color: white;
            padding: 30px;
            border-radius: 12px;
            text-align: center;
            margin-bottom: 30px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
        }
        .verdict-banner h2 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        .verdict-banner .score {
            font-size: 4em;
            font-weight: 700;
            margin: 10px 0;
        }
        .section {
            margin-bottom: 30px;
            background: #f8f9fa;
            padding: 25px;
            border-radius: 12px;
            border-left: 4px solid #667eea;
        }
        .section h3 {
            color: #1e3c72;
            margin-bottom: 20px;
            font-size: 1.5em;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
        }
        .info-item {
            background: white;
            padding: 15px;
            border-radius: 8px;
            border: 1px solid #e0e0e0;
        }
        .info-item label {
            font-weight: 600;
            color: #666;
            font-size: 0.9em;
            display: block;
            margin-bottom: 5px;
        }
        .info-item value {
            color: #333;
            font-family: "Courier New", monospace;
            font-size: 0.95em;
        }
        .detection {
            background: white;
            border: 2px solid #dc3545;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
        }
        .detection-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        .detection-title {
            font-size: 1.2em;
            font-weight: 600;
            color: #dc3545;
        }
        .badge {
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
            color: white;
        }
        .badge-critical { background: #dc3545; }
        .badge-high { background: #fd7e14; }
        .badge-medium { background: #ffc107; color: #333; }
        .badge-low { background: #17a2b8; }
        .footer {
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            font-size: 0.9em;
        }
        .hash {
            font-family: "Courier New", monospace;
            background: #f0f0f0;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ SENTINEL FRAMEWORK</h1>
            <div class="subtitle">Malware Analysis Report</div>
            <div style="margin-top: 15px; opacity: 0.8;">{{ generation_time }}</div>
        </div>
        
        <div class="content">
            <div class="verdict-banner">
                <h2>VERDICT</h2>
                <div class="score">{{ result.verdict }}</div>
                <div style="font-size: 1.5em;">Risk Score: {{ result.risk_score }}/100</div>
            </div>
            
            <div class="section">
                <h3>📄 Sample Information</h3>
                <div class="info-grid">
                    <div class="info-item">
                        <label>File Name</label>
                        <value>{{ result.sample_path }}</value>
                    </div>
                    <div class="info-item">
                        <label>File Type</label>
                        <value>{{ result.file_type }}</value>
                    </div>
                    <div class="info-item">
                        <label>File Size</label>
                        <value>{{ result.file_size }} bytes</value>
                    </div>
                    <div class="info-item">
                        <label>SHA-256</label>
                        <value class="hash">{{ result.sample_hash }}</value>
                    </div>
                    <div class="info-item">
                        <label>Analysis Time</label>
                        <value>{{ "%.2f"|format(result.analysis_time) }} seconds</value>
                    </div>
                    <div class="info-item">
                        <label>Events Captured</label>
                        <value>{{ result.behavioral_events|length }}</value>
                    </div>
                </div>
            </div>
            
            {% if result.threat_detections %}
            <div class="section">
                <h3>⚠️ Threat Detections ({{ result.threat_detections|length }})</h3>
                {% for detection in result.threat_detections %}
                <div class="detection">
                    <div class="detection-header">
                        <div class="detection-title">
                            {{ detection.threat_type }} - {{ detection.technique }}
                        </div>
                        <span class="badge badge-{{ detection.severity }}">
                            {{ detection.severity|upper }}
                        </span>
                    </div>
                    <p><strong>Description:</strong> {{ detection.description }}</p>
                    <p><strong>Confidence:</strong> {{ detection.confidence }}%</p>
                </div>
                {% endfor %}
            </div>
            {% endif %}
            
            {% if result.static_analysis %}
            <div class="section">
                <h3>🔍 Static Analysis</h3>
                {% if result.static_analysis.suspicious_imports %}
                <p><strong>Suspicious API Imports:</strong></p>
                <ul>
                    {% for imp in result.static_analysis.suspicious_imports %}
                    <li><code>{{ imp }}</code></li>
                    {% endfor %}
                </ul>
                {% endif %}
            </div>
            {% endif %}
        </div>
        
        <div class="footer">
            <strong>Sentinel Framework</strong> - Open-Source Malware Analysis Sandbox<br>
            Report generated on {{ generation_time }}
        </div>
    </div>
</body>
</html>'''
