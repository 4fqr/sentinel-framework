#!/bin/bash
# Sentinel Framework - Linux/Mac Setup Script

echo ""
echo "========================================"
echo " SENTINEL FRAMEWORK - SETUP"
echo "========================================"
echo ""

# Check Python installation
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 is not installed"
    echo "Please install Python 3.9+ from your package manager"
    exit 1
fi

echo "[1/4] Python detected..."
python3 --version

# Check pip
echo ""
echo "[2/4] Upgrading pip..."
python3 -m pip install --upgrade pip

# Install dependencies
echo ""
echo "[3/4] Installing dependencies..."
pip3 install -r requirements.txt

if [ $? -ne 0 ]; then
    echo "[ERROR] Failed to install dependencies"
    exit 1
fi

# Install Sentinel
echo ""
echo "[4/4] Installing Sentinel Framework..."
pip3 install -e .

if [ $? -ne 0 ]; then
    echo "[ERROR] Failed to install Sentinel Framework"
    exit 1
fi

# Verify installation
echo ""
echo "========================================"
echo " VERIFYING INSTALLATION"
echo "========================================"
echo ""

python3 test_installation.py

if [ $? -ne 0 ]; then
    echo ""
    echo "[WARNING] Some tests failed. Please check the output above."
    echo ""
else
    echo ""
    echo "========================================"
    echo " INSTALLATION COMPLETE!"
    echo "========================================"
    echo ""
    echo "Sentinel Framework is ready to use."
    echo ""
    echo "Quick Start:"
    echo "  sentinel --help"
    echo "  sentinel info"
    echo "  sentinel analyze sample.exe --live"
    echo ""
    echo "Documentation:"
    echo "  README.md - Full documentation"
    echo "  QUICKSTART.md - Quick start guide"
    echo "  INSTALL.md - Installation details"
    echo ""
fi
