"""
Sentinel Framework - Registry Monitor
Tracks Windows registry modifications (Windows-specific)
"""

import sys
import time
import threading
from typing import Callable, List, Optional

from sentinel.core.monitor import BehaviorEvent, EventType, EventSeverity
from sentinel.config import config
from sentinel.utils.logger import get_logger


logger = get_logger(__name__)


class RegistryMonitor:
    """Monitors Windows registry operations"""
    
    def __init__(self, callback: Callable[[BehaviorEvent], None]):
        """
        Initialize registry monitor
        
        Args:
            callback: Function to call with behavior events
        """
        self.callback = callback
        self.config = config.get_section('monitoring').get('registry', {})
        self.is_running = False
        self._monitor_thread: Optional[threading.Thread] = None
        
        # Registry monitoring is Windows-specific
        if sys.platform != 'win32':
            logger.warning("Registry monitoring is only available on Windows")
            self.is_available = False
        else:
            self.is_available = True
            try:
                import winreg
                self.winreg = winreg
            except ImportError:
                self.is_available = False
                logger.error("winreg module not available")
    
    def start(self) -> None:
        """Start registry monitoring"""
        if not self.is_available:
            logger.warning("Registry monitoring not available on this platform")
            return
        
        if self.is_running:
            return
        
        logger.info("Starting registry monitor")
        self.is_running = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
    
    def stop(self) -> None:
        """Stop registry monitoring"""
        if not self.is_running:
            return
        
        logger.info("Stopping registry monitor")
        self.is_running = False
        
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
    
    def _monitor_loop(self) -> None:
        """Main monitoring loop"""
        # Simplified registry monitoring
        # In production, would use Windows API hooks or WMI
        
        watch_keys = self.config.get('watch_keys', [])
        
        while self.is_running:
            try:
                # This is a placeholder implementation
                # Real implementation would use RegNotifyChangeKeyValue or WMI
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Registry monitoring error: {e}")
                time.sleep(1)
    
    def _emit_registry_event(
        self,
        event_type: EventType,
        key_path: str,
        value_name: str,
        value_data: Optional[str] = None
    ) -> None:
        """Emit registry modification event"""
        # Assess severity based on key path
        severity = EventSeverity.INFO
        
        # Critical registry keys
        critical_keys = [
            'currentversion\\run',
            'currentversion\\runonce',
            'services',
            'winlogon',
        ]
        
        if any(ck in key_path.lower() for ck in critical_keys):
            severity = EventSeverity.HIGH
        
        event = BehaviorEvent(
            event_type=event_type,
            timestamp=time.time(),
            severity=severity,
            description=f"Registry {event_type.value}: {key_path}",
            data={
                'key_path': key_path,
                'value_name': value_name,
                'value_data': value_data,
            },
            tags=['persistence', 'registry']
        )
        
        self.callback(event)
