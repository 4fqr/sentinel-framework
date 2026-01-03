#!/usr/bin/env python3
"""
Simple test script to verify Sentinel Framework installation
"""

import sys
from pathlib import Path


def test_imports():
    """Test that all required modules can be imported"""
    print("Testing imports...")
    
    try:
        import sentinel
        print(f"✓ sentinel module (v{sentinel.__version__})")
    except ImportError as e:
        print(f"✗ sentinel module: {e}")
        return False
    
    try:
        from sentinel.core.sandbox import SandboxEngine
        print("✓ SandboxEngine")
    except ImportError as e:
        print(f"✗ SandboxEngine: {e}")
        return False
    
    try:
        from sentinel.core.monitor import BehaviorMonitor
        print("✓ BehaviorMonitor")
    except ImportError as e:
        print(f"✗ BehaviorMonitor: {e}")
        return False
    
    try:
        from sentinel.core.analyzer import MalwareAnalyzer
        print("✓ MalwareAnalyzer")
    except ImportError as e:
        print(f"✗ MalwareAnalyzer: {e}")
        return False
    
    try:
        from sentinel.core.reporter import ReportGenerator
        print("✓ ReportGenerator")
    except ImportError as e:
        print(f"✗ ReportGenerator: {e}")
        return False
    
    return True


def test_dependencies():
    """Test that all dependencies are available"""
    print("\nTesting dependencies...")
    
    dependencies = [
        'click', 'rich', 'psutil', 'yaml', 'jinja2',
        'docker', 'watchdog'
    ]
    
    all_ok = True
    for dep in dependencies:
        try:
            __import__(dep)
            print(f"✓ {dep}")
        except ImportError:
            print(f"✗ {dep} - not installed")
            all_ok = False
    
    return all_ok


def test_configuration():
    """Test configuration loading"""
    print("\nTesting configuration...")
    
    try:
        from sentinel.config import config
        
        # Test basic config access
        sandbox_type = config.get('sandbox.type', 'not found')
        print(f"✓ Configuration loaded (sandbox type: {sandbox_type})")
        return True
    except Exception as e:
        print(f"✗ Configuration error: {e}")
        return False


def test_docker():
    """Test Docker connectivity"""
    print("\nTesting Docker...")
    
    try:
        import docker
        client = docker.from_env()
        client.ping()
        print("✓ Docker daemon is running")
        return True
    except Exception as e:
        print(f"✗ Docker not available: {e}")
        print("  Note: Docker is optional but recommended for full functionality")
        return False


def main():
    """Run all tests"""
    print("=" * 60)
    print("Sentinel Framework - Installation Test")
    print("=" * 60)
    
    results = []
    
    results.append(("Imports", test_imports()))
    results.append(("Dependencies", test_dependencies()))
    results.append(("Configuration", test_configuration()))
    results.append(("Docker", test_docker()))
    
    print("\n" + "=" * 60)
    print("Test Results:")
    print("=" * 60)
    
    for name, passed in results:
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{name:20} {status}")
    
    all_passed = all(result[1] for result in results[:3])  # Docker is optional
    
    print("=" * 60)
    
    if all_passed:
        print("\n✓ All critical tests passed!")
        print("  Sentinel Framework is ready to use.")
        print("\n  Try: sentinel --help")
        return 0
    else:
        print("\n✗ Some tests failed.")
        print("  Please check the installation guide.")
        return 1


if __name__ == '__main__':
    sys.exit(main())
