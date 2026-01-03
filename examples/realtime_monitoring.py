"""
Example: Real-time monitoring with Sentinel Framework
"""

from sentinel.core.monitor import BehaviorMonitor
from sentinel.core.sandbox import SandboxEngine
import time


def event_callback(event):
    """Handle real-time events"""
    print(f"[{event.severity.value.upper()}] {event.event_type.value}: {event.description}")


def main():
    """Real-time monitoring example"""
    
    # Initialize components
    monitor = BehaviorMonitor()
    sandbox = SandboxEngine()
    
    # Register callback for real-time notifications
    monitor.register_callback(event_callback)
    
    # Start monitoring
    print("Starting behavioral monitoring...")
    monitor.start()
    
    # Execute sample in sandbox
    print("Executing sample...")
    result = sandbox.execute("path/to/sample.exe")
    
    # Wait for completion
    time.sleep(5)
    
    # Stop monitoring
    monitor.stop()
    
    # Display summary
    summary = monitor.get_event_summary()
    print(f"\nCaptured {summary['total_events']} events")
    print(f"Event types: {summary['by_type']}")
    print(f"Severity: {summary['by_severity']}")
    
    # Cleanup
    sandbox.cleanup()


if __name__ == '__main__':
    main()
