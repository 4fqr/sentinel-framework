# Windows Compatibility Guide

## Overview

Sentinel Framework is fully compatible with Windows systems. This document outlines the compatibility considerations and solutions implemented.

## Encoding Issues - RESOLVED ✓

### Problem
Windows console (cmd.exe, PowerShell) uses `cp1252` encoding by default, which doesn't support Unicode characters like:
- Box drawing characters (╔═══╗, ║, ╚═══╝)
- Emojis (🛡️)
- Special symbols (✓, ⚠)

### Solution
All Unicode characters have been replaced with ASCII-safe equivalents:
- Box drawing → ASCII art (`+=+`, `|  |`)
- Checkmarks (✓) → `[OK]`
- Warning symbols (⚠) → `[WARNING]`
- Emojis (🛡️) → Removed
- Rich console configured with `legacy_windows=True`

## Installation

### Quick Install (Recommended)
```powershell
.\setup.bat
```

### Manual Install
```powershell
# Create virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Install Sentinel
pip install -e .
```

## Running Sentinel

### Using Python Module (Recommended)
```powershell
python -m sentinel --help
python -m sentinel info
python -m sentinel analyze sample.exe --live
```

### Using Direct Command (If PATH configured)
```powershell
sentinel --help
sentinel info
sentinel analyze sample.exe
```

## Platform-Specific Dependencies

The framework automatically handles platform-specific packages:

### Windows-Only
- `python-magic-bin` - File type detection
- `pythonnet` - .NET interop for Windows APIs
- `pywin32` (optional) - Windows-specific functionality

### Linux/Mac
- `python-magic` - File type detection

## Optional Dependencies

These dependencies are optional and the framework will work without them:

- **Docker** - Container-based sandbox (falls back to process isolation)
- **YARA** - Advanced pattern matching
- **Matplotlib** - Visualization graphs
- **Scapy** - Network packet capture

## Testing

Run the comprehensive test suite:
```powershell
python test_comprehensive.py
```

Expected output:
```
============================================================
 TEST SUMMARY: 6/6 PASSED
============================================================

ALL TESTS PASSED!
[OK] Sentinel Framework is fully operational!
```

## Troubleshooting

### Issue: Unicode Errors
**Solution:** This has been fixed in the latest version. Update your installation:
```powershell
git pull
pip install -e . --force-reinstall
```

### Issue: 'sentinel' command not found
**Solution:** Use `python -m sentinel` instead:
```powershell
python -m sentinel --help
```

### Issue: Missing C++ Build Tools
**Solution:** This is no longer required. We removed dependencies that needed compilation (ssdeep, volatility3).

### Issue: Docker Daemon Not Running
**Solution:** Framework automatically falls back to process-based isolation. No action needed.

## Features Working on Windows

✓ **CLI Interface** - Full command-line functionality  
✓ **Static Analysis** - PE file analysis, hash calculation  
✓ **Dynamic Analysis** - Process monitoring, file system monitoring  
✓ **Behavioral Monitoring** - All 4 monitors operational  
✓ **Threat Detection** - All 5 detectors functional  
✓ **Report Generation** - HTML, JSON, Markdown formats  
✓ **Live Monitoring** - Real-time telemetry display  

## Known Limitations

### Registry Monitor
- Only available on Windows (by design)
- Automatically disabled on Linux/Mac

### Network Packet Capture
- Requires administrator privileges
- Optional feature (scapy)

### Memory Analysis
- Removed volatility3 dependency due to installation issues
- Can be added back if needed

## Performance Considerations

### Recommended Specs
- **CPU:** 4+ cores
- **RAM:** 8GB minimum, 16GB recommended
- **Disk:** 10GB free space
- **OS:** Windows 10/11, Windows Server 2016+

### Resource Usage
- Base memory: ~100MB
- Per-analysis: ~200-500MB (varies by sample)
- Docker containers: ~512MB each (if using Docker)

## Development Environment

### IDE Recommendations
- **VS Code** - Excellent Python support
- **PyCharm** - Full-featured Python IDE
- **Sublime Text** - Lightweight option

### Required Extensions (VS Code)
- Python (Microsoft)
- Pylance (Microsoft)
- GitLens (optional)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

When contributing, please ensure:
1. Code works on Windows, Linux, and Mac
2. No Unicode characters in console output
3. Platform-specific code has proper fallbacks
4. Tests pass on all platforms

## Support

### Getting Help
- GitHub Issues: https://github.com/4fqr/sentinel-framework/issues
- Documentation: See `docs/` folder
- Examples: See `examples/` folder

### Reporting Bugs
Please include:
1. Windows version
2. Python version (`python --version`)
3. Error message with full traceback
4. Steps to reproduce

## Version History

### v1.0.0 (Current)
- ✓ Full Windows compatibility
- ✓ All Unicode characters removed
- ✓ Comprehensive test suite
- ✓ 100% test pass rate
- ✓ Production ready

## License

MIT License - See [LICENSE](LICENSE) file for details.

---

**Status:** Production Ready ✓  
**Last Updated:** 2024  
**Tested On:** Windows 10, Windows 11, Windows Server 2019
