<div align="center">

# 🛡️ Sentinel Framework

### **Next-Generation Malware Analysis Sandbox**

*Transform suspicious code into actionable intelligence with real-time behavioral monitoring*

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Security](https://img.shields.io/badge/security-focused-green.svg)](https://github.com/4fqr/sentinel-framework)

[Features](#-features) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [Examples](#-examples) • [Contributing](#-contributing)

![Sentinel Framework Demo](https://via.placeholder.com/800x400/1e3c72/ffffff?text=Sentinel+Framework+Demo)

</div>

---

## 🎯 Overview

Sentinel Framework is a **state-of-the-art, open-source platform** that sets the gold standard for automated malware analysis. Born from the need for a powerful yet accessible analysis tool, Sentinel provides:

- 🔒 **Military-Grade Isolation** - Docker-based sandbox prevents malware escape
- 👁️ **360° Visibility** - Monitor every file, process, registry, and network operation
- 🤖 **AI-Powered Detection** - 5 specialized engines identify sophisticated threats
- 📊 **Stunning Reports** - Professional HTML/JSON/Markdown with executive summaries
- ⚡ **Real-Time Intelligence** - Live event streaming with beautiful CLI dashboard
- 🎨 **Developer-First** - Clean architecture, extensive docs, production-ready code

### Why Sentinel?

Traditional malware analysis tools are either expensive commercial products or outdated open-source projects. Sentinel bridges this gap by delivering enterprise-grade capabilities with the flexibility of open source.

**Perfect for:**
- 🔬 Security Researchers analyzing emerging threats
- 🛡️ SOC Teams investigating suspicious files
- 🎓 Students learning malware analysis techniques
- 🏢 Organizations needing automated threat assessment
- 💻 Developers building security automation

## ✨ Features

<table>
<tr>
<td width="50%">

### 🔒 **Secure Isolation**
- Docker containerization with resource limits
- Network isolation modes (isolated/monitored/none)
- Automatic cleanup and snapshot support
- No malware escape possible

### 👁️ **Deep Behavioral Analysis**
- **File System** - Track all file operations
- **Process** - Monitor creation, injection, hollowing
- **Registry** - Detect persistence mechanisms
- **Network** - Capture C2 communications

### 🤖 **Intelligent Detection**
- **Ransomware** - Encryption patterns, ransom notes
- **C2 Communication** - Beaconing, suspicious domains
- **Code Injection** - DLL/process injection, hollowing
- **Persistence** - Autorun, scheduled tasks, services
- **Evasion** - VM/debugger detection, time delays

</td>
<td width="50%">

### 📊 **Professional Reports**
- **HTML** - Beautiful visual reports with CSS
- **JSON** - Machine-readable for automation
- **Markdown** - Documentation-friendly format
- Risk scoring (0-100) with confidence levels

### ⚡ **Real-Time Interface**
- Live event streaming during analysis
- Color-coded severity levels
- Interactive dashboard with statistics
- Progress indicators and animations

### 🎨 **Developer Experience**
- Clean, modular architecture
- Comprehensive documentation
- Type hints throughout
- Extensive examples
- Unit tests included
- Easy to extend

</td>
</tr>
</table>

---

## 🚀 Quick Start

### Prerequisites

```bash
# Required
✅ Python 3.9 or higher
✅ Docker (Desktop for Windows/Mac, Engine for Linux)
✅ 4GB RAM minimum (8GB+ recommended)
✅ 2GB free disk space

# Optional but recommended
🔹 Virtual machine for safe analysis
🔹 Network isolation capability
```

### Installation

#### **🪟 Windows (Automated)**
```powershell
# Clone the repository
git clone https://github.com/4fqr/sentinel-framework.git
cd sentinel-framework

# Run automated setup
.\setup.bat

# Verify installation
sentinel --version
```

#### **🐧 Linux / 🍎 Mac (Automated)**
```bash
# Clone the repository
git clone https://github.com/4fqr/sentinel-framework.git
cd sentinel-framework

# Run automated setup
chmod +x setup.sh
./setup.sh

# Verify installation
sentinel --version
```

#### **📦 Manual Installation**
```bash
# Clone the repository
git clone https://github.com/4fqr/sentinel-framework.git
cd sentinel-framework

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install Sentinel Framework
pip install -e .

# Run installation test
python test_installation.py

# Verify installation
sentinel info
```

### 🎯 First Analysis in 30 Seconds

```bash
# Basic analysis with absolute path
python -m sentinel analyze "C:/Samples/suspicious_file.exe"

# With live real-time monitoring (RECOMMENDED)
python -m sentinel analyze "C:/Samples/suspicious_file.exe" --live

# Generate JSON report for automation
python -m sentinel analyze "C:/Samples/suspicious_file.exe" --format json --output "C:/Reports/report.json"

# Extended analysis with custom timeout (10 minutes)
python -m sentinel analyze "D:/Samples/suspicious_file.exe" --timeout 600 --live
```

### 📸 What You'll See

When running with `--live` mode, you get a beautiful real-time dashboard:

```
╔════════════════════════════════════════════════╗
║  🛡️  SENTINEL FRAMEWORK - LIVE ANALYSIS       ║
╠════════════════════════════════════════════════╣
║  Statistics          │  Recent Events          ║
║  Total Events: 156   │  file_created           ║
║  🔴 Critical: 3      │  process_created        ║
║  🟠 High: 12         │  network_connection     ║
║  🟡 Medium: 45       │  registry_modified      ║
║  🔵 Low: 96          │  file_modified          ║
╚════════════════════════════════════════════════╝
```

---

## 📖 Documentation

### Command Line Interface

Sentinel provides a comprehensive CLI for all your malware analysis needs. **Always use the `python -m sentinel` syntax** for reliable cross-platform execution:

#### 📋 **All Available Commands**

```bash
# Get help
python -m sentinel --help              # Show all commands
python -m sentinel analyze --help      # Get help for specific command

# View version
python -m sentinel --version           # Display Sentinel version

# System information
python -m sentinel info                # Show configuration and enabled features
```

---

### 🔬 **Analyze Command** - Core Analysis Functionality

#### Single File Analysis

```bash
# Basic analysis
python -m sentinel analyze "C:/Samples/malware.exe"

# With real-time monitoring dashboard (RECOMMENDED)
python -m sentinel analyze "C:/Samples/malware.exe" --live

# Analyze file on different drive
python -m sentinel analyze "D:/suspicious/sample.exe" --live

# Custom timeout (in seconds)
python -m sentinel analyze "C:/Samples/malware.exe" --timeout 600

# Disable specific analysis types
python -m sentinel analyze "C:/Samples/malware.exe" --no-static    # Skip static analysis
python -m sentinel analyze "C:/Samples/malware.exe" --no-dynamic   # Skip dynamic execution

# Specify report format
python -m sentinel analyze "C:/Samples/malware.exe" --format html       # HTML report (default)
python -m sentinel analyze "C:/Samples/malware.exe" --format json       # JSON for automation
python -m sentinel analyze "C:/Samples/malware.exe" --format markdown   # Markdown documentation

# Custom output location with absolute path
python -m sentinel analyze "C:/Samples/malware.exe" --output "D:/Reports/analysis.html"
```

#### 📂 **Directory Batch Analysis** - NEW!

```bash
# Analyze all files in a directory (current drive)
python -m sentinel analyze "C:/Samples" --recursive

# Analyze directory on different drive
python -m sentinel analyze "D:/MalwareCollection" --recursive

# Analyze with specific file extensions
python -m sentinel analyze "C:/Samples" --recursive --extensions .exe --extensions .dll

# Parallel analysis with multiple workers (faster!)
python -m sentinel analyze "C:/Samples" --recursive --parallel 4

# Complete example: recursive analysis with 8 workers, JSON output
python -m sentinel analyze "D:/MalwareCollection" --recursive \
    --parallel 8 \
    --extensions .exe --extensions .dll --extensions .pdf \
    --format json \
    --output "D:/AnalysisReports"

# Supported extensions (auto-detected):
# Executables: .exe, .dll, .sys
# Documents: .pdf, .doc, .docx, .xls, .xlsx
# Archives: .zip, .rar
# Mobile: .apk, .jar
# Linux: .elf, .so, .dylib
```

**Directory Analysis Features:**
- ✅ Recursive directory traversal
- ✅ Parallel processing (1-16 workers)
- ✅ File extension filtering
- ✅ Batch progress tracking
- ✅ Aggregate statistics and summary
- ✅ Individual reports for each sample
- ✅ Automatic output directory creation

---

### 📊 **Report Management Commands**

#### List Reports

```bash
# List all reports
python -m sentinel list-reports

# Filter by format
python -m sentinel list-reports --format html
python -m sentinel list-reports --format json
python -m sentinel list-reports --format markdown

# Limit results
python -m sentinel list-reports --limit 50

# Example output:
# ╔══════════════════════════════════════════════════╗
# ║            Found 15 reports                      ║
# ╠════════════════════╦═══════╦═════════╦═══════════╣
# ║ Report             ║ Type  ║ Size    ║ Modified  ║
# ╠════════════════════╬═══════╬═════════╬═══════════╣
# ║ malware_20240103.. ║ HTML  ║ 245 KB  ║ 2024-01-03║
# ║ sample_20240103... ║ JSON  ║ 89 KB   ║ 2024-01-03║
# ╚════════════════════╩═══════╩═════════╩═══════════╝
```

#### View Reports

```bash
# View a specific report with absolute path
python -m sentinel view "C:/Reports/analysis_20240103_120000.json"

# Opens HTML reports in browser automatically
python -m sentinel view "C:/Reports/malware_analysis.html"

# View report on different drive
python -m sentinel view "D:/AnalysisReports/report.json"
```

#### Clean Reports

```bash
# Delete old reports (with confirmation prompt)
python -m sentinel clean-reports --older-than 30    # Delete reports older than 30 days

# Delete all reports (WARNING: asks for confirmation)
python -m sentinel clean-reports --all
```

---

### 📝 **Analysis Options Reference**

| Option | Short | Type | Description | Example |
|--------|-------|------|-------------|---------|
| `--timeout` | `-t` | Integer | Analysis timeout in seconds | `-t 600` |
| `--no-static` | | Flag | Disable static analysis | `--no-static` |
| `--no-dynamic` | | Flag | Disable dynamic analysis | `--no-dynamic` |
| `--format` | `-f` | Choice | Report format (html/json/markdown) | `-f json` |
| `--output` | `-o` | Path | Output file or directory path | `-o ./reports` |
| `--live` | | Flag | Show real-time analysis dashboard | `--live` |
| `--recursive` | `-r` | Flag | Analyze directory recursively | `-r` |
| `--parallel` | `-p` | Integer | Number of parallel workers (1-16) | `-p 4` |
| `--extensions` | `-e` | Multiple | File extensions to analyze | `-e .exe -e .dll` |

---

### 💡 **Usage Examples**

#### Example 1: Quick Single File Analysis
```bash
# Analyze with live monitoring
python -m sentinel analyze "C:/Downloads/suspicious.exe" --live
```

#### Example 2: Batch Analysis of Malware Collection
```bash
# Analyze 100+ samples with 4 parallel workers
python -m sentinel analyze "D:/MalwareSamples" \
    --recursive \
    --parallel 4 \
    --format json \
    --output "D:/AnalysisReports"
```

#### Example 3: Targeted Extension Analysis
```bash
# Only analyze executables and DLLs from mixed directory
python -m sentinel analyze "C:/MixedFiles" \
    --recursive \
    --extensions .exe \
    --extensions .dll \
    --parallel 8
```

#### Example 4: Long-Running Deep Analysis
```bash
# Extended timeout for complex malware (30 minutes)
python -m sentinel analyze "D:/Threats/advanced_threat.exe" \
    --timeout 1800 \
    --live \
    --format html \
    --output "C:/Reports/detailed_report.html"
```

#### Example 5: Automation-Friendly JSON Output
```bash
# Generate machine-readable report for SIEM integration
python -m sentinel analyze "C:/Samples/sample.exe" \
    --format json \
    --output "C:/SIEM/report.json" \
    --no-dynamic  # Static analysis only for speed
```

---

### Configuration

Sentinel can be configured via `config/sentinel.yaml`:

```yaml
# Sandbox Settings
sandbox:
  type: "docker"
  timeout: 300
  network_mode: "isolated"

# Monitoring Settings
monitoring:
  file_system:
    enabled: true
  process:
    enabled: true
  registry:
    enabled: true
  network:
    enabled: true

# Analysis Settings
analysis:
  static_analysis: true
  dynamic_analysis: true
  detection:
    ransomware:
      enabled: true
    c2_communication:
      enabled: true
    code_injection:
      enabled: true

# Reporting Settings
reporting:
  format: "html"
  output_dir: "reports"
  verbosity: "detailed"
```

---

## 🏗️ Architecture

### Core Components

```
sentinel/
├── core/              # Core analysis engines
│   ├── sandbox.py     # Isolated execution environment
│   ├── monitor.py     # Behavioral monitoring orchestration
│   ├── analyzer.py    # Malware analysis engine
│   └── reporter.py    # Report generation system
├── monitors/          # Behavioral monitors
│   ├── filesystem.py  # File system monitoring
│   ├── process.py     # Process monitoring
│   ├── registry.py    # Registry monitoring
│   └── network.py     # Network monitoring
├── detectors/         # Threat detection engines
│   ├── ransomware.py  # Ransomware detection
│   ├── c2.py          # C2 communication detection
│   ├── injection.py   # Code injection detection
│   ├── persistence.py # Persistence detection
│   └── evasion.py     # Evasion technique detection
└── cli.py             # Command-line interface
```

### Analysis Workflow

1. **Sample Ingestion** - File hash calculation and type detection
2. **Static Analysis** - PE analysis, string extraction, import inspection
3. **Sandbox Execution** - Isolated execution in Docker container
4. **Behavioral Monitoring** - Real-time event capture across multiple subsystems
5. **Threat Detection** - Pattern matching against known malicious behaviors
6. **Report Generation** - Synthesis of findings into comprehensive report
7. **Verdict Calculation** - Risk scoring and classification

---

## 🎨 Features in Detail

### Sandbox Engine

The sandbox engine provides multiple isolation strategies:

- **Docker Containers** - Lightweight, fast, cross-platform
- **Process Isolation** - Quick analysis without virtualization overhead
- **Network Control** - Isolated, monitored, or disabled networking

### Behavioral Monitoring

Comprehensive system-level monitoring:

- **File System** - Creation, modification, deletion, renaming
- **Process** - Creation, termination, parent-child relationships
- **Registry** - Key creation, modification, deletion (Windows)
- **Network** - Connections, DNS queries, HTTP traffic

### Threat Detection

Intelligent pattern recognition for:

#### Ransomware Detection
- Rapid file encryption patterns
- Ransom note creation
- Backup file deletion
- Shadow copy deletion

#### C2 Communication
- Beaconing behavior (periodic check-ins)
- Suspicious domain connections
- Non-standard port usage

#### Code Injection
- Process injection APIs
- Process hollowing
- DLL injection
- Suspicious child processes

#### Persistence Mechanisms
- Registry autorun modifications
- Startup folder additions
- Scheduled task creation
- Service creation

#### Evasion Techniques
- VM detection attempts
- Debugger detection
- Time-based delays
- Analysis tool enumeration

### Report Generation

Professional reports with:

- **Visual Hierarchy** - Clear distinction between critical and informational data
- **Comprehensive Coverage** - Static analysis, dynamic behavior, threat detections
- **Multiple Formats** - HTML (beautiful web reports), JSON (machine-readable), Markdown (documentation-friendly)
- **Actionable Intelligence** - Executive summary, technical details, IOCs

---

## 🛠️ Development

### Project Structure

```
Sentinel Framework/
├── config/                 # Configuration files
│   └── sentinel.yaml      # Main configuration
├── sentinel/              # Source code
│   ├── core/              # Core components
│   ├── monitors/          # Monitoring modules
│   ├── detectors/         # Detection engines
│   ├── utils/             # Utility functions
│   └── cli.py             # CLI interface
├── reports/               # Generated reports
├── logs/                  # Log files
├── tests/                 # Unit tests
├── requirements.txt       # Python dependencies
├── pyproject.toml         # Project metadata
└── README.md              # This file
```

### Running Tests

```bash
pytest tests/
```

### Code Formatting

```bash
black sentinel/
flake8 sentinel/
```

---

## 🔒 Security Considerations

### ⚠️ Important Warnings

- **Always run Sentinel in an isolated environment** - Malware samples can be extremely dangerous
- **Never analyze samples on production systems** - Use dedicated analysis VMs or containers
- **Network isolation is critical** - Prevent malware from communicating with external C2 servers
- **Snapshot and restore** - Use VM snapshots or container cleanup to ensure clean analysis environment

### Best Practices

1. **Use dedicated analysis infrastructure** - Separate from production networks
2. **Enable all monitoring features** - Comprehensive visibility is crucial
3. **Review reports carefully** - Automated detection may have false positives
4. **Keep Sentinel updated** - New malware techniques emerge constantly
5. **Follow responsible disclosure** - Report vulnerabilities privately

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Follow PEP 8 style guidelines
- Write comprehensive docstrings
- Add unit tests for new features
- Update documentation as needed
- Maintain backward compatibility

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- The security research community for threat intelligence
- Open-source projects that made this possible: Docker, psutil, watchdog, Rich
- All contributors and users of Sentinel Framework

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/4fqr/sentinel-framework/issues)
- **Discussions**: [GitHub Discussions](https://github.com/4fqr/sentinel-framework/discussions)
- **Documentation**: [Full API Documentation](API.md)

---

## 🗺️ Roadmap

- [ ] Virtual machine integration (VirtualBox, VMware)
- [ ] Advanced memory forensics with Volatility
- [ ] YARA rule integration
- [ ] Machine learning-based classification
- [ ] Web-based dashboard
- [ ] Distributed analysis cluster
- [ ] Cloud deployment support
- [ ] Integration with threat intelligence platforms

---

<div align="center">

**Built with ❤️ for the security community**

⭐ Star this repository if you find it useful!

</div>
