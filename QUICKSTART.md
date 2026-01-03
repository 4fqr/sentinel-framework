# Sentinel Framework - Quick Start Guide

Welcome to Sentinel Framework! This guide will help you get started quickly.

## Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Install Sentinel
pip install -e .

# Verify installation
sentinel --version
```

## Your First Analysis

### 1. Basic Analysis

```bash
sentinel analyze sample.exe
```

This will:
- Perform static analysis
- Execute in isolated sandbox
- Monitor behavioral activity
- Generate HTML report

### 2. Live Monitoring

```bash
sentinel analyze sample.exe --live
```

Watch real-time events as they occur!

### 3. Custom Report Format

```bash
sentinel analyze sample.exe --format json --output report.json
```

## Common Use Cases

### Analyze with Timeout

```bash
sentinel analyze sample.exe --timeout 600
```

### Skip Static Analysis

```bash
sentinel analyze sample.exe --no-static
```

### Skip Dynamic Analysis

```bash
sentinel analyze sample.exe --no-dynamic
```

## Understanding the Output

### Verdict Levels

- **Malicious** (Risk Score 80-100): High confidence malware
- **Suspicious** (Risk Score 50-79): Likely malicious
- **Potentially Unwanted** (Risk Score 20-49): Gray area
- **Clean** (Risk Score 0-19): Appears benign

### Report Sections

1. **Sample Information** - File metadata and hashes
2. **Verdict Summary** - Overall assessment
3. **Threat Detections** - Identified malicious patterns
4. **Static Analysis** - PE analysis, imports, strings
5. **Behavioral Events** - Runtime activity timeline

## Configuration

Edit `config/sentinel.yaml` to customize:

```yaml
# Increase timeout
sandbox:
  timeout: 600

# Adjust detection sensitivity
analysis:
  detection:
    ransomware:
      sensitivity: "high"
```

## Programmatic Usage

```python
from sentinel.core.analyzer import MalwareAnalyzer

analyzer = MalwareAnalyzer()
result = analyzer.analyze("sample.exe")

print(f"Verdict: {result.verdict}")
print(f"Risk Score: {result.risk_score}/100")

analyzer.cleanup()
```

## Next Steps

1. **Read the full documentation**: `README.md`
2. **Explore examples**: `examples/` directory
3. **Customize configuration**: `config/sentinel.yaml`
4. **Review reports**: `reports/` directory

## Getting Help

- **Documentation**: README.md and INSTALL.md
- **Examples**: Check the `examples/` directory
- **Issues**: GitHub Issues
- **Community**: GitHub Discussions

## Safety Reminders

⚠️ **Always analyze malware in isolated environments**
- Use dedicated VMs or containers
- Enable network isolation
- Take snapshots before analysis
- Never run on production systems

## Pro Tips

1. **Use live mode** (`--live`) for interactive analysis
2. **Set reasonable timeouts** based on sample behavior
3. **Review all reports** - automated detection isn't perfect
4. **Keep Docker running** before starting analysis
5. **Check logs** in `logs/sentinel.log` for troubleshooting

---

Happy analyzing! 🛡️
