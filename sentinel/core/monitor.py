"""
Sentinel Framework - Behavioral Monitor
Comprehensive system behavior monitoring and event collection
"""

import time
import threading
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime

from sentinel.core.events import BehaviorEvent, EventType, EventSeverity
from sentinel.config import config
from sentinel.utils.logger import get_logger
from sentinel.monitors.filesystem import FileSystemMonitor
from sentinel.monitors.process import ProcessMonitor
from sentinel.monitors.registry import RegistryMonitor
from sentinel.monitors.network import NetworkMonitor


logger = get_logger(__name__)


class BehaviorMonitor:
    """
    Comprehensive behavioral monitoring system
    Orchestrates multiple monitors for system-level event tracking
    """
    
    def __init__(self):
        """Initialize behavior monitor"""
        self.config = config.monitoring_config
        self.events: List[BehaviorEvent] = []
        self.is_monitoring = False
        self._lock = threading.Lock()
        self._callbacks: List[Callable[[BehaviorEvent], None]] = []
        
        # Initialize sub-monitors
        self.monitors: Dict[str, Any] = {}
        self._initialize_monitors()
        
        logger.info("Behavior monitor initialized")
    
    def _initialize_monitors(self) -> None:
        """Initialize all enabled monitoring subsystems"""
        if self.config.get('file_system', {}).get('enabled', True):
            try:
                self.monitors['filesystem'] = FileSystemMonitor(self._event_callback)
                logger.info("File system monitor initialized")
            except Exception as e:
                logger.error(f"Failed to initialize file system monitor: {e}")
        
        if self.config.get('process', {}).get('enabled', True):
            try:
                self.monitors['process'] = ProcessMonitor(self._event_callback)
                logger.info("Process monitor initialized")
            except Exception as e:
                logger.error(f"Failed to initialize process monitor: {e}")
        
        if self.config.get('registry', {}).get('enabled', True):
            try:
                self.monitors['registry'] = RegistryMonitor(self._event_callback)
                logger.info("Registry monitor initialized")
            except Exception as e:
                logger.error(f"Failed to initialize registry monitor: {e}")
        
        if self.config.get('network', {}).get('enabled', True):
            try:
                self.monitors['network'] = NetworkMonitor(self._event_callback)
                logger.info("Network monitor initialized")
            except Exception as e:
                logger.error(f"Failed to initialize network monitor: {e}")
    
    def start(self) -> None:
        """Start all monitoring subsystems"""
        if self.is_monitoring:
            logger.warning("Monitoring already active")
            return
        
        logger.info("Starting behavioral monitoring")
        self.is_monitoring = True
        self.events.clear()
        
        # Start all monitors
        for name, monitor in self.monitors.items():
            try:
                monitor.start()
                logger.debug(f"Started {name} monitor")
            except Exception as e:
                logger.error(f"Failed to start {name} monitor: {e}")
    
    def stop(self) -> None:
        """Stop all monitoring subsystems"""
        if not self.is_monitoring:
            return
        
        logger.info("Stopping behavioral monitoring")
        self.is_monitoring = False
        
        # Stop all monitors
        for name, monitor in self.monitors.items():
            try:
                monitor.stop()
                logger.debug(f"Stopped {name} monitor")
            except Exception as e:
                logger.error(f"Failed to stop {name} monitor: {e}")
    
    def _event_callback(self, event: BehaviorEvent) -> None:
        """
        Callback for receiving events from sub-monitors
        
        Args:
            event: Behavior event
        """
        with self._lock:
            self.events.append(event)
        
        # Trigger registered callbacks
        for callback in self._callbacks:
            try:
                callback(event)
            except Exception as e:
                logger.error(f"Event callback failed: {e}")
    
    def register_callback(self, callback: Callable[[BehaviorEvent], None]) -> None:
        """
        Register callback for real-time event notifications
        
        Args:
            callback: Function to call when event occurs
        """
        self._callbacks.append(callback)
    
    def get_events(
        self,
        event_type: Optional[EventType] = None,
        severity: Optional[EventSeverity] = None,
        min_severity: Optional[EventSeverity] = None
    ) -> List[BehaviorEvent]:
        """
        Get collected events with optional filtering
        
        Args:
            event_type: Filter by event type
            severity: Filter by exact severity
            min_severity: Filter by minimum severity
        
        Returns:
            List of matching events
        """
        with self._lock:
            events = self.events.copy()
        
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        
        if severity:
            events = [e for e in events if e.severity == severity]
        
        if min_severity:
            severity_order = [
                EventSeverity.INFO,
                EventSeverity.LOW,
                EventSeverity.MEDIUM,
                EventSeverity.HIGH,
                EventSeverity.CRITICAL
            ]
            min_index = severity_order.index(min_severity)
            events = [
                e for e in events
                if severity_order.index(e.severity) >= min_index
            ]
        
        return events
    
    def get_event_summary(self) -> Dict[str, Any]:
        """
        Get summary of collected events
        
        Returns:
            Dictionary with event statistics
        """
        with self._lock:
            total = len(self.events)
            
            by_type = {}
            by_severity = {}
            
            for event in self.events:
                event_type = event.event_type.value
                severity = event.severity.value
                
                by_type[event_type] = by_type.get(event_type, 0) + 1
                by_severity[severity] = by_severity.get(severity, 0) + 1
        
        return {
            'total_events': total,
            'by_type': by_type,
            'by_severity': by_severity,
            'start_time': self.events[0].timestamp if self.events else None,
            'end_time': self.events[-1].timestamp if self.events else None,
        }
    
    def export_events(self, format: str = 'json') -> str:
        """
        Export events in specified format
        
        Args:
            format: Export format (json, csv)
        
        Returns:
            Serialized events
        """
        import json
        
        with self._lock:
            events_data = [event.to_dict() for event in self.events]
        
        if format == 'json':
            return json.dumps(events_data, indent=2)
        
        elif format == 'csv':
            import csv
            import io
            
            output = io.StringIO()
            if events_data:
                writer = csv.DictWriter(output, fieldnames=events_data[0].keys())
                writer.writeheader()
                writer.writerows(events_data)
            
            return output.getvalue()
        
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def clear_events(self) -> None:
        """Clear all collected events"""
        with self._lock:
            self.events.clear()
        logger.debug("Events cleared")
    
    def get_timeline(self) -> List[Dict[str, Any]]:
        """
        Get chronological timeline of events
        
        Returns:
            List of events sorted by timestamp
        """
        with self._lock:
            events = sorted(self.events, key=lambda e: e.timestamp)
        
        return [event.to_dict() for event in events]
