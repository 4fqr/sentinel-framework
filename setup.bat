@echo off
REM Sentinel Framework - Windows Setup Script
echo.
echo ========================================
echo  SENTINEL FRAMEWORK - WINDOWS SETUP
echo ========================================
echo.

REM Check Python installation
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.9+ from https://python.org
    pause
    exit /b 1
)

echo [1/4] Python detected...
python --version

REM Check pip
echo.
echo [2/4] Upgrading pip...
python -m pip install --upgrade pip

REM Install dependencies
echo.
echo [3/4] Installing dependencies...
pip install -r requirements.txt

if errorlevel 1 (
    echo [ERROR] Failed to install dependencies
    pause
    exit /b 1
)

REM Install Sentinel
echo.
echo [4/4] Installing Sentinel Framework...
pip install -e .

if errorlevel 1 (
    echo [ERROR] Failed to install Sentinel Framework
    pause
    exit /b 1
)

REM Verify installation
echo.
echo ========================================
echo  VERIFYING INSTALLATION
echo ========================================
echo.

python test_installation.py

if errorlevel 1 (
    echo.
    echo [WARNING] Some tests failed. Please check the output above.
    echo.
) else (
    echo.
    echo ========================================
    echo  INSTALLATION COMPLETE!
    echo ========================================
    echo.
    echo Sentinel Framework is ready to use.
    echo.
    echo Quick Start:
    echo   sentinel --help
    echo   sentinel info
    echo   sentinel analyze sample.exe --live
    echo.
    echo Documentation:
    echo   README.md - Full documentation
    echo   QUICKSTART.md - Quick start guide
    echo   INSTALL.md - Installation details
    echo.
)

pause
