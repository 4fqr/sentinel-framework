# Sentinel Framework - Troubleshooting Guide

## Common Issues and Solutions

### 1. "Permission Denied" / "File Locked" Errors

**Problem:** Files fail with "Permission denied" or "File locked by another process"

**Causes:**
- Files are currently open in another application
- Files are system DLLs/EXEs in use by Windows
- Files are being used by running processes
- Insufficient permissions to access the files

**Solutions:**
```bash
# Option 1: Close the application using the files
# Close any programs that might have the files open

# Option 2: Copy files to a different directory
Copy-Item "C:\Path\To\Locked\File.exe" "C:\Temp\Analysis\File.exe"
python -m sentinel analyze "C:\Temp\Analysis\File.exe"

# Option 3: Run PowerShell as Administrator
# Right-click PowerShell → "Run as Administrator"
python -m sentinel analyze "C:\Path\To\File.exe"

# Option 4: Analyze a copy while original is running
python -m sentinel analyze "C:\Path\To\Copy.exe"
```

**Prevention:**
- Copy files to a temporary directory before analysis
- Don't analyze system files in `C:\Windows\System32`
- Close applications before analyzing their files

---

### 2. All Files Fail in Batch Analysis

**Problem:** Running `--recursive` on a directory results in all files failing

**Common Causes:**
1. Trying to analyze a folder with system files
2. Files locked by running applications
3. Analyzing wrong file types

**Solution - Test with Sample Files:**
```bash
# First, create a test directory with copies
New-Item -ItemType Directory -Path "C:\Temp\MalwareTest"
Copy-Item "C:\Path\To\Suspicious\File.exe" "C:\Temp\MalwareTest\"

# Then analyze the copies
python -m sentinel analyze "C:\Temp\MalwareTest" --recursive
```

**Solution - Use Specific Extensions:**
```bash
# Only analyze specific file types
python -m sentinel analyze "C:\Samples" --recursive -e .exe -e .dll

# This skips other files and focuses on executables
```

---

### 3. Directory vs File Analysis

**Problem:** Getting "Cannot analyze directory" error

**Understanding:**
- **Without `--recursive`**: Analyzes a single file
- **With `--recursive`**: Analyzes all files in a directory

**Correct Usage:**
```bash
# Single file (NO --recursive flag)
python -m sentinel analyze "C:\Path\To\File.exe"

# Directory (WITH --recursive flag)
python -m sentinel analyze "C:\Path\To\Directory" --recursive

# Wrong: This will fail
python -m sentinel analyze "C:\Path\To\Directory"
```

---

### 4. No Samples Found

**Problem:** "Found 0 samples to analyze"

**Causes:**
- Wrong file extensions in directory
- Need to use `--recursive` for subdirectories
- Files filtered out by default extensions

**Solutions:**
```bash
# Show which extensions are being searched
# Default: .exe, .dll, .sys, .pdf, .doc, .docx, .xls, .xlsx, .zip, .rar, .jar, .apk

# Add custom extensions
python -m sentinel analyze "C:\Samples" --recursive -e .exe -e .dll -e .bin

# Search subdirectories
python -m sentinel analyze "C:\Samples" --recursive

# Check what files exist
Get-ChildItem "C:\Samples" -Recurse -File | Select-Object Name, Extension
```

---

### 5. Analysis Takes Too Long

**Problem:** Analysis hangs or takes hours

**Solutions:**
```bash
# Set shorter timeout (default is 300 seconds = 5 minutes)
python -m sentinel analyze "file.exe" --timeout 60

# Disable dynamic analysis if only need static info
python -m sentinel analyze "file.exe" --no-dynamic

# Use parallel processing for batch analysis
python -m sentinel analyze "C:\Samples" --recursive --parallel 4
```

---

### 6. libpcap Warnings (Already Fixed)

**Problem:** "WARNING: No libpcap provider available"

**Status:** ✅ FIXED in latest version

**If still seeing warnings:**
- Restart Python/PowerShell session
- The warning is suppressed but network forensics still works
- Scapy is optional (only needed for PCAP export)

---

## Best Practices

### For Single File Analysis:
```bash
# Basic analysis with all features
python -m sentinel analyze "suspicious.exe"

# Live monitoring mode (press Ctrl+C when done)
python -m sentinel analyze "suspicious.exe" --live

# Quick static analysis only
python -m sentinel analyze "suspicious.exe" --no-dynamic

# Extended timeout for complex malware
python -m sentinel analyze "ransomware.exe" --timeout 600
```

### For Batch Analysis:
```bash
# Analyze all executables in directory
python -m sentinel analyze "C:\Samples" --recursive -e .exe

# Parallel processing (4 workers)
python -m sentinel analyze "C:\Samples" --recursive --parallel 4

# Custom output directory
python -m sentinel analyze "C:\Samples" --recursive -o "C:\Reports"

# JSON output for automation
python -m sentinel analyze "C:\Samples" --recursive --format json
```

### For Testing:
```bash
# Test with a known safe file first
python -m sentinel analyze "C:\Windows\notepad.exe"

# Then test with your samples
python -m sentinel analyze "C:\YourSamples\test.exe"
```

---

## File Access Requirements

### ✅ Files You CAN Analyze:
- Copied executables in your user directories
- Files you own/downloaded
- Files in `C:\Users\YourName\*`
- Files in temporary directories
- Standalone executable copies

### ❌ Files That May FAIL:
- System files in `C:\Windows\System32`
- DLLs loaded by running processes
- Files locked by applications
- Files in use by Windows
- Protected system files

---

## Getting Help

If you encounter errors:

1. **Check the error message** - It now shows specific reasons
2. **Copy files first** - Analyze copies, not originals
3. **Run as Administrator** - If permission issues persist
4. **Test with notepad.exe** - Verify Sentinel works
5. **Check file accessibility** - Can you open it in notepad?

**Report Issues:**
- GitHub: https://github.com/4fqr/sentinel-framework/issues
- Include: Error message, command used, file type being analyzed
