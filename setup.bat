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
    echo [WARNING] Some optional dependencies failed
    echo [INFO] Installing core dependencies...
    pip install click rich psutil pyyaml jinja2 pefile watchdog requests networkx colorama pytest black flake8 python-magic-bin matplotlib docker scapy
)

REM Install Sentinel
echo.
echo [4/4] Installing Sentinel Framework...
pip uninstall sentinel-framework -y >nul 2>&1
pip install -e .

if errorlevel 1 (
    echo [ERROR] Failed to install Sentinel Framework
    pause
    exit /b 1
)

REM Configure PATH
echo.
echo [5/5] Configuring PATH...
for /f "tokens=*" %%i in ('python -c "import sys; print(sys.executable.replace('python.exe', 'Scripts'))"') do set SCRIPTS_DIR=%%i
echo Scripts directory: %SCRIPTS_DIR%

REM Check if already in PATH
echo %PATH% | find /i "%SCRIPTS_DIR%" >nul
if errorlevel 1 (
    echo Adding to PATH...
    setx PATH "%PATH%;%SCRIPTS_DIR%" >nul 2>&1
    echo [OK] PATH updated. Please restart your terminal.
) else (
    echo [OK] Already in PATH
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
    echo   sentinel --help              (after restarting terminal)
    echo   sentinel info
    echo   sentinel analyze sample.exe --live
    echo   sentinel analyze /samples --recursive --parallel 4
    echo.
    echo OR use Python module syntax:
    echo   python -m sentinel --help
    echo   python -m sentinel info
    echo.
    echo Documentation:
    echo   README.md - Full documentation
    echo   QUICKSTART.md - Quick start guide
    echo   INSTALL.md - Installation details
    echo   WINDOWS_COMPATIBILITY.md - Windows-specific guide
    echo.
)

pause

