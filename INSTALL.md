# Sentinel Framework - Installation Guide

## Prerequisites

Before installing Sentinel Framework, ensure you have the following:

### System Requirements

- **Operating System**: Windows 10/11 or Linux (Ubuntu 20.04+ recommended)
- **Python**: Version 3.9 or higher
- **Memory**: Minimum 4GB RAM (8GB+ recommended)
- **Disk Space**: At least 2GB free space
- **Docker**: Latest version (for sandbox isolation)

### Required Software

1. **Python 3.9+**
   - Download from: https://www.python.org/downloads/
   - Ensure pip is installed and updated
   - Add Python to system PATH

2. **Docker**
   - **Windows**: Docker Desktop for Windows
     - Download: https://www.docker.com/products/docker-desktop
   - **Linux**: Docker Engine
     ```bash
     curl -fsSL https://get.docker.com -o get-docker.sh
     sudo sh get-docker.sh
     ```

3. **Git** (for cloning repository)
   - Download: https://git-scm.com/downloads

## Installation Steps

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/sentinel-framework.git
cd sentinel-framework
```

### 2. Create Virtual Environment (Recommended)

**Windows:**
```powershell
python -m venv venv
.\venv\Scripts\activate
```

**Linux/Mac:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Install Sentinel Framework

```bash
pip install -e .
```

This installs Sentinel in editable mode, allowing you to modify the code.

### 5. Verify Installation

```bash
sentinel --version
sentinel info
```

You should see the Sentinel Framework banner and version information.

## Docker Configuration

### Windows

1. **Enable WSL 2** (if not already enabled)
2. **Install Docker Desktop**
3. **Verify Docker is running:**
   ```powershell
   docker --version
   docker ps
   ```

### Linux

1. **Install Docker:**
   ```bash
   curl -fsSL https://get.docker.com -o get-docker.sh
   sudo sh get-docker.sh
   ```

2. **Add user to docker group:**
   ```bash
   sudo usermod -aG docker $USER
   newgrp docker
   ```

3. **Verify installation:**
   ```bash
   docker --version
   docker ps
   ```

## Configuration

### Basic Configuration

1. **Copy the default configuration:**
   ```bash
   cp config/sentinel.yaml config/sentinel.local.yaml
   ```

2. **Edit configuration:**
   ```bash
   notepad config/sentinel.local.yaml  # Windows
   nano config/sentinel.local.yaml     # Linux
   ```

3. **Key settings to review:**
   - Sandbox timeout
   - Network isolation mode
   - Report output directory
   - Enabled monitoring features

### Advanced Configuration

#### Custom Watch Paths

Edit `config/sentinel.yaml` to add custom paths for file system monitoring:

```yaml
monitoring:
  file_system:
    watch_paths:
      - "C:\\Custom\\Path"
      - "C:\\Another\\Path"
```

#### Detector Sensitivity

Adjust threat detection sensitivity:

```yaml
analysis:
  detection:
    ransomware:
      enabled: true
      sensitivity: "high"  # low, medium, high
```

## Troubleshooting

### Common Issues

#### 1. Docker Connection Error

**Problem:** `Cannot connect to Docker daemon`

**Solution:**
- Ensure Docker Desktop/Engine is running
- Check Docker service status:
  ```bash
  # Windows
  Get-Service docker
  
  # Linux
  systemctl status docker
  ```

#### 2. Python Module Not Found

**Problem:** `ModuleNotFoundError: No module named 'sentinel'`

**Solution:**
- Activate virtual environment
- Reinstall in editable mode:
  ```bash
  pip install -e .
  ```

#### 3. Permission Errors

**Problem:** Permission denied errors during analysis

**Solution:**
- **Windows:** Run PowerShell as Administrator
- **Linux:** Check file permissions or use sudo if necessary

#### 4. Missing Dependencies

**Problem:** Import errors for specific packages

**Solution:**
```bash
pip install --upgrade -r requirements.txt
```

### Getting Help

If you encounter issues not covered here:

1. Check the [GitHub Issues](https://github.com/yourusername/sentinel-framework/issues)
2. Review the [Wiki](https://github.com/yourusername/sentinel-framework/wiki)
3. Ask in [Discussions](https://github.com/yourusername/sentinel-framework/discussions)

## Next Steps

After installation:

1. **Read the documentation**: Check README.md for usage examples
2. **Run a test analysis**: Try analyzing a benign file first
3. **Review the configuration**: Customize Sentinel for your needs
4. **Explore features**: Try different CLI options and report formats

## Updating Sentinel

To update to the latest version:

```bash
cd sentinel-framework
git pull origin main
pip install --upgrade -r requirements.txt
```

## Uninstallation

To remove Sentinel Framework:

```bash
pip uninstall sentinel-framework
```

To completely remove:

```bash
# Remove virtual environment
rm -rf venv

# Remove repository
cd ..
rm -rf sentinel-framework
```

---

**Happy Analyzing! 🛡️**
