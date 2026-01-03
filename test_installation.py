#!/usr/bin/env python3
"""
Test Sentinel Framework Installation
Verifies that all required components are properly installed
"""

import sys
import importlib


def test_import(module_name, required=True):
    """Test if a module can be imported"""
    try:
        importlib.import_module(module_name)
        print(f"  ✓ {module_name}")
        return True
    except ImportError as e:
        if required:
            print(f"  ✗ {module_name} (REQUIRED - {e})")
            return False
        else:
            print(f"  ⚠ {module_name} (optional - not available)")
            return True


def main():
    """Run installation tests"""
    print("\n" + "="*50)
    print(" SENTINEL FRAMEWORK - INSTALLATION TEST")
    print("="*50 + "\n")
    
    all_required_ok = True
    
    # Test core dependencies
    print("Testing Core Dependencies:")
    all_required_ok &= test_import("click", required=True)
    all_required_ok &= test_import("rich", required=True)
    all_required_ok &= test_import("psutil", required=True)
    all_required_ok &= test_import("yaml", required=True)
    all_required_ok &= test_import("jinja2", required=True)
    
    print("\nTesting Analysis Libraries:")
    all_required_ok &= test_import("pefile", required=True)
    test_import("yara", required=False)
    
    print("\nTesting Monitoring Libraries:")
    all_required_ok &= test_import("watchdog", required=True)
    test_import("docker", required=False)
    
    print("\nTesting Utilities:")
    all_required_ok &= test_import("requests", required=True)
    all_required_ok &= test_import("networkx", required=True)
    test_import("matplotlib", required=False)
    test_import("magic", required=False)
    test_import("scapy", required=False)
    
    # Test Sentinel package
    print("\nTesting Sentinel Framework:")
    all_required_ok &= test_import("sentinel", required=True)
    all_required_ok &= test_import("sentinel.core.sandbox", required=True)
    all_required_ok &= test_import("sentinel.core.monitor", required=True)
    all_required_ok &= test_import("sentinel.core.analyzer", required=True)
    all_required_ok &= test_import("sentinel.core.reporter", required=True)
    
    # Test CLI
    print("\nTesting CLI:")
    try:
        from sentinel import cli
        print("  ✓ CLI module")
    except ImportError as e:
        print(f"  ✗ CLI module ({e})")
        all_required_ok = False
    
    # Test configuration
    print("\nTesting Configuration:")
    try:
        from sentinel.config import config
        print("  ✓ Configuration system")
    except Exception as e:
        print(f"  ✗ Configuration system ({e})")
        all_required_ok = False
    
    # Final result
    print("\n" + "="*50)
    if all_required_ok:
        print(" ✓ ALL REQUIRED TESTS PASSED!")
        print("="*50 + "\n")
        print("Sentinel Framework is ready to use!")
        print("\nQuick Start:")
        print("  sentinel --help")
        print("  sentinel info")
        print("\nNote: Some optional dependencies may not be installed.")
        print("This is normal and the framework will work without them.")
        return 0
    else:
        print(" ✗ SOME REQUIRED TESTS FAILED")
        print("="*50 + "\n")
        print("Please ensure all required dependencies are installed:")
        print("  pip install click rich psutil pyyaml jinja2 pefile watchdog requests networkx colorama")
        return 1


if __name__ == "__main__":
    sys.exit(main())
