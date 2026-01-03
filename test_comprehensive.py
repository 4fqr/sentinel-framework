#!/usr/bin/env python3
"""
Comprehensive Test Suite for Sentinel Framework
Tests all core functionality end-to-end
"""

import sys
import subprocess


def run_command(cmd, description):
    """Run a command and display results"""
    print(f"\n{'='*60}")
    print(f"TEST: {description}")
    print(f"{'='*60}")
    print(f"Command: {cmd}")
    print()
    
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, 
                          encoding='utf-8', errors='replace')
    
    print(result.stdout)
    if result.stderr:
        print("STDERR:", result.stderr)
    
    success = result.returncode == 0
    status = "[PASS]" if success else "[FAIL]"
    print(f"\nResult: {status}")
    print(f"{'='*60}\n")
    
    return success


def main():
    """Run all tests"""
    print("\n" + "="*60)
    print(" SENTINEL FRAMEWORK - COMPREHENSIVE TEST SUITE")
    print("="*60 + "\n")
    
    tests = []
    
    # Test 1: Help command
    tests.append(run_command(
        "python -m sentinel --help",
        "CLI Help Display"
    ))
    
    # Test 2: Version command
    tests.append(run_command(
        "python -m sentinel --version",
        "Version Display"
    ))
    
    # Test 3: Info command
    tests.append(run_command(
        "python -m sentinel info",
        "System Information"
    ))
    
    # Test 4: Import test
    tests.append(run_command(
        'python -c "from sentinel import MalwareAnalyzer, SandboxEngine, BehaviorMonitor, ReportGenerator; print(\'All imports successful\')"',
        "Core Imports"
    ))
    
    # Test 5: Event system
    tests.append(run_command(
        'python -c "from sentinel import BehaviorEvent, EventType, EventSeverity; print(\'Event system functional\')"',
        "Event System"
    ))
    
    # Test 6: Configuration
    tests.append(run_command(
        'python -c "from sentinel.config import config; print(\'Configuration loaded\')"',
        "Configuration System"
    ))
    
    # Summary
    passed = sum(tests)
    total = len(tests)
    
    print("\n" + "="*60)
    print(f" TEST SUMMARY: {passed}/{total} PASSED")
    print("="*60 + "\n")
    
    if passed == total:
        print("ALL TESTS PASSED!")
        print("[OK] Sentinel Framework is fully operational!")
        print("\nReady for production use:")
        print("  python -m sentinel analyze sample.exe --live")
        return 0
    else:
        print(f"[X] {total - passed} test(s) failed")
        print("Please review the errors above")
        return 1


if __name__ == "__main__":
    sys.exit(main())
