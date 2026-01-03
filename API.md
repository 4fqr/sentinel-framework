# 📖 API Reference - Sentinel Framework

Complete API documentation for developers integrating Sentinel Framework.

## Table of Contents

- [Core Components](#core-components)
- [Analysis Engine](#analysis-engine)
- [Monitoring System](#monitoring-system)
- [Detection Engines](#detection-engines)
- [Report Generation](#report-generation)
- [Configuration](#configuration)
- [Examples](#examples)

---

## Core Components

### MalwareAnalyzer

Main analysis orchestration class.

```python
from sentinel.core.analyzer import MalwareAnalyzer

analyzer = MalwareAnalyzer()
```

#### Methods

##### `analyze(sample_path, enable_static=None, enable_dynamic=None, timeout=None)`

Perform comprehensive malware analysis.

**Parameters:**
- `sample_path` (str): Path to the sample file
- `enable_static` (bool, optional): Enable static analysis (default from config)
- `enable_dynamic` (bool, optional): Enable dynamic analysis (default from config)
- `timeout` (int, optional): Analysis timeout in seconds

**Returns:**
- `AnalysisResult`: Complete analysis results

**Example:**
```python
result = analyzer.analyze("malware.exe", timeout=300)
print(f"Verdict: {result.verdict}")
print(f"Risk Score: {result.risk_score}/100")
```

##### `cleanup()`

Cleanup analyzer resources.

**Example:**
```python
analyzer.cleanup()
```

---

### SandboxEngine

Isolated execution environment.

```python
from sentinel.core.sandbox import SandboxEngine

sandbox = SandboxEngine(sandbox_type="docker")
```

#### Parameters

- `sandbox_type` (str, optional): Type of sandbox ("docker", "process", "vm")

#### Methods

##### `execute(sample_path, arguments=None, environment=None, timeout=None)`

Execute sample in isolated environment.

**Parameters:**
- `sample_path` (str): Path to sample
- `arguments` (List[str], optional): Command-line arguments
- `environment` (Dict[str, str], optional): Environment variables
- `timeout` (int, optional): Execution timeout

**Returns:**
- `SandboxResult`: Execution results

**Example:**
```python
result = sandbox.execute(
    "malware.exe",
    arguments=["--param", "value"],
    timeout=300
)
print(f"Exit Code: {result.exit_code}")
print(f"Execution Time: {result.execution_time}s")
```

##### `create_snapshot(name)`

Create sandbox snapshot.

**Parameters:**
- `name` (str): Snapshot name

**Returns:**
- `bool`: Success status

##### `restore_snapshot(name)`

Restore from snapshot.

**Parameters:**
- `name` (str): Snapshot name

**Returns:**
- `bool`: Success status

##### `cleanup()`

Cleanup sandbox resources.

---

### BehaviorMonitor

Comprehensive behavioral monitoring.

```python
from sentinel.core.monitor import BehaviorMonitor

monitor = BehaviorMonitor()
```

#### Methods

##### `start()`

Start all monitoring subsystems.

**Example:**
```python
monitor.start()
# ... perform actions ...
monitor.stop()
```

##### `stop()`

Stop all monitoring subsystems.

##### `register_callback(callback)`

Register callback for real-time events.

**Parameters:**
- `callback` (Callable[[BehaviorEvent], None]): Event callback function

**Example:**
```python
def event_handler(event):
    print(f"Event: {event.event_type.value}")
    print(f"Severity: {event.severity.value}")

monitor.register_callback(event_handler)
```

##### `get_events(event_type=None, severity=None, min_severity=None)`

Get collected events with filtering.

**Parameters:**
- `event_type` (EventType, optional): Filter by event type
- `severity` (EventSeverity, optional): Filter by exact severity
- `min_severity` (EventSeverity, optional): Filter by minimum severity

**Returns:**
- `List[BehaviorEvent]`: Filtered events

**Example:**
```python
from sentinel.core.monitor import EventSeverity

high_severity_events = monitor.get_events(min_severity=EventSeverity.HIGH)
```

##### `get_event_summary()`

Get event statistics summary.

**Returns:**
- `Dict[str, Any]`: Event statistics

**Example:**
```python
summary = monitor.get_event_summary()
print(f"Total events: {summary['total_events']}")
print(f"By type: {summary['by_type']}")
```

##### `export_events(format='json')`

Export events in specified format.

**Parameters:**
- `format` (str): Export format ("json" or "csv")

**Returns:**
- `str`: Serialized events

---

## Analysis Engine

### AnalysisResult

Complete analysis results.

#### Attributes

- `sample_path` (str): Path to analyzed sample
- `sample_hash` (str): SHA256 hash
- `file_type` (str): File type description
- `file_size` (int): File size in bytes
- `analysis_time` (float): Analysis duration in seconds
- `sandbox_result` (SandboxResult): Sandbox execution results
- `static_analysis` (Dict): Static analysis results
- `behavioral_events` (List[Dict]): Behavioral events
- `threat_detections` (List[Dict]): Detected threats
- `verdict` (str): Overall verdict
- `risk_score` (int): Risk score 0-100

#### Methods

##### `to_dict()`

Convert to dictionary.

**Returns:**
- `Dict[str, Any]`: Dictionary representation

---

## Monitoring System

### EventType

Enumeration of event types.

```python
from sentinel.core.monitor import EventType

EventType.FILE_CREATED
EventType.FILE_MODIFIED
EventType.FILE_DELETED
EventType.FILE_RENAMED
EventType.PROCESS_CREATED
EventType.PROCESS_TERMINATED
EventType.PROCESS_INJECTION
EventType.REGISTRY_CREATED
EventType.REGISTRY_MODIFIED
EventType.REGISTRY_DELETED
EventType.NETWORK_CONNECTION
EventType.NETWORK_DNS
EventType.NETWORK_HTTP
```

### EventSeverity

Enumeration of severity levels.

```python
from sentinel.core.monitor import EventSeverity

EventSeverity.INFO
EventSeverity.LOW
EventSeverity.MEDIUM
EventSeverity.HIGH
EventSeverity.CRITICAL
```

### BehaviorEvent

Represents a behavioral event.

#### Attributes

- `event_type` (EventType): Type of event
- `timestamp` (float): Unix timestamp
- `severity` (EventSeverity): Severity level
- `data` (Dict): Event-specific data
- `process_id` (int, optional): Associated process ID
- `process_name` (str, optional): Process name
- `description` (str): Human-readable description
- `tags` (List[str]): Event tags

#### Methods

##### `to_dict()`

Convert to dictionary.

---

## Detection Engines

### Base Detector Interface

All detectors implement this interface:

```python
class Detector:
    def detect(self, events: List[BehaviorEvent], analysis_result: AnalysisResult) -> List[Dict[str, Any]]:
        """
        Detect threats based on events and analysis results.
        
        Returns:
            List of detection dictionaries with keys:
            - threat_type: Type of threat
            - technique: Specific technique
            - description: Human-readable description
            - confidence: Confidence level (0-100)
            - severity: Severity level (low, medium, high, critical)
            - indicators: Dict of specific indicators
        """
        pass
```

### Available Detectors

#### RansomwareDetector

```python
from sentinel.detectors.ransomware import RansomwareDetector

detector = RansomwareDetector()
detections = detector.detect(events, analysis_result)
```

**Detects:**
- File encryption patterns
- Ransom note creation
- Backup deletion
- Shadow copy deletion

#### C2Detector

```python
from sentinel.detectors.c2 import C2Detector

detector = C2Detector()
detections = detector.detect(events, analysis_result)
```

**Detects:**
- Beaconing behavior
- Suspicious domain connections
- Non-standard port usage

#### InjectionDetector

```python
from sentinel.detectors.injection import InjectionDetector

detector = InjectionDetector()
detections = detector.detect(events, analysis_result)
```

**Detects:**
- Process injection APIs
- Process hollowing
- DLL injection
- Suspicious child processes

#### PersistenceDetector

```python
from sentinel.detectors.persistence import PersistenceDetector

detector = PersistenceDetector()
detections = detector.detect(events, analysis_result)
```

**Detects:**
- Registry persistence
- Startup folder modifications
- Scheduled task creation
- Service creation

#### EvasionDetector

```python
from sentinel.detectors.evasion import EvasionDetector

detector = EvasionDetector()
detections = detector.detect(events, analysis_result)
```

**Detects:**
- VM detection attempts
- Debugger detection
- Time-based evasion
- Analysis tool enumeration

---

## Report Generation

### ReportGenerator

Generate comprehensive analysis reports.

```python
from sentinel.core.reporter import ReportGenerator

reporter = ReportGenerator()
```

#### Methods

##### `generate(analysis_result, format=None, output_file=None)`

Generate analysis report.

**Parameters:**
- `analysis_result` (AnalysisResult): Analysis results
- `format` (str, optional): Report format ("html", "json", "markdown")
- `output_file` (str, optional): Custom output path

**Returns:**
- `str`: Path to generated report

**Example:**
```python
# HTML report
report_path = reporter.generate(result, format='html')

# JSON report
report_path = reporter.generate(result, format='json', output_file='report.json')

# Markdown report
report_path = reporter.generate(result, format='markdown')
```

---

## Configuration

### Config

Centralized configuration management.

```python
from sentinel.config import config
```

#### Methods

##### `get(key, default=None)`

Get configuration value using dot notation.

**Parameters:**
- `key` (str): Configuration key (e.g., "sandbox.timeout")
- `default` (Any, optional): Default value

**Returns:**
- `Any`: Configuration value

**Example:**
```python
timeout = config.get('sandbox.timeout', 300)
network_mode = config.get('sandbox.network_mode', 'isolated')
```

##### `set(key, value)`

Set configuration value.

**Parameters:**
- `key` (str): Configuration key
- `value` (Any): Value to set

**Example:**
```python
config.set('sandbox.timeout', 600)
```

##### `get_section(section)`

Get entire configuration section.

**Parameters:**
- `section` (str): Section name

**Returns:**
- `Dict[str, Any]`: Section configuration

**Example:**
```python
sandbox_config = config.get_section('sandbox')
```

#### Properties

- `sandbox_config`: Sandbox configuration
- `monitoring_config`: Monitoring configuration
- `analysis_config`: Analysis configuration
- `reporting_config`: Reporting configuration
- `logging_config`: Logging configuration

---

## Examples

### Complete Analysis Workflow

```python
from sentinel.core.analyzer import MalwareAnalyzer
from sentinel.core.reporter import ReportGenerator

# Initialize
analyzer = MalwareAnalyzer()
reporter = ReportGenerator()

# Analyze
result = analyzer.analyze("malware.exe", timeout=300)

# Check verdict
if result.verdict in ["Malicious", "Suspicious"]:
    print(f"⚠️ Threat detected: {result.verdict}")
    print(f"Risk Score: {result.risk_score}/100")
    
    # Display detections
    for detection in result.threat_detections:
        print(f"- {detection['threat_type']}: {detection['technique']}")

# Generate report
report_path = reporter.generate(result, format='html')
print(f"Report: {report_path}")

# Cleanup
analyzer.cleanup()
```

### Real-Time Monitoring

```python
from sentinel.core.monitor import BehaviorMonitor
from sentinel.core.sandbox import SandboxEngine

monitor = BehaviorMonitor()
sandbox = SandboxEngine()

# Event callback
def handle_event(event):
    if event.severity.value in ['high', 'critical']:
        print(f"⚠️ {event.event_type.value}: {event.description}")

# Register callback
monitor.register_callback(handle_event)

# Start monitoring
monitor.start()

# Execute sample
result = sandbox.execute("sample.exe")

# Stop monitoring
monitor.stop()

# Get summary
summary = monitor.get_event_summary()
print(f"Captured {summary['total_events']} events")

# Cleanup
sandbox.cleanup()
```

### Custom Detector

```python
from typing import List, Dict, Any
from sentinel.core.monitor import BehaviorEvent, EventType
from sentinel.core.analyzer import MalwareAnalyzer

class CustomDetector:
    """Example custom detector"""
    
    def detect(self, events: List[BehaviorEvent], analysis_result: Any) -> List[Dict[str, Any]]:
        detections = []
        
        # Custom detection logic
        bitcoin_files = [
            e for e in events
            if e.event_type == EventType.FILE_CREATED
            and 'wallet' in e.data.get('path', '').lower()
        ]
        
        if bitcoin_files:
            detections.append({
                'threat_type': 'Cryptocurrency',
                'technique': 'Wallet Creation',
                'description': f'Detected {len(bitcoin_files)} wallet files',
                'confidence': 70,
                'severity': 'medium',
                'indicators': {'files': [e.data['path'] for e in bitcoin_files]}
            })
        
        return detections

# Use custom detector
analyzer = MalwareAnalyzer()
analyzer.detectors.append(CustomDetector())

result = analyzer.analyze("sample.exe")
analyzer.cleanup()
```

### Batch Analysis

```python
from pathlib import Path
from sentinel.core.analyzer import MalwareAnalyzer
from sentinel.core.reporter import ReportGenerator

analyzer = MalwareAnalyzer()
reporter = ReportGenerator()

samples_dir = Path("samples/")
results = []

for sample in samples_dir.glob("*.exe"):
    print(f"Analyzing: {sample.name}")
    
    try:
        result = analyzer.analyze(str(sample))
        results.append(result)
        
        # Generate report
        reporter.generate(result, format='json', 
                         output_file=f"reports/{sample.stem}.json")
        
    except Exception as e:
        print(f"Error analyzing {sample.name}: {e}")

# Summary
malicious = [r for r in results if r.verdict == "Malicious"]
print(f"\nAnalyzed {len(results)} samples")
print(f"Malicious: {len(malicious)}")

analyzer.cleanup()
```

---

For more examples, see the `examples/` directory in the repository.
