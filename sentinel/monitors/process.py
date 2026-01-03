"""
Sentinel Framework - Process Monitor
Tracks process creation, termination, and injection attempts
"""

import psutil
import time
import threading
from typing import Callable, Dict, List, Optional, Set

from sentinel.core.monitor import BehaviorEvent, EventType, EventSeverity
from sentinel.config import config
from sentinel.utils.logger import get_logger


logger = get_logger(__name__)


class ProcessMonitor:
    """Monitors process activity and behavior"""
    
    def __init__(self, callback: Callable[[BehaviorEvent], None]):
        """
        Initialize process monitor
        
        Args:
            callback: Function to call with behavior events
        """
        self.callback = callback
        self.config = config.get_section('monitoring').get('process', {})
        self.is_running = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._tracked_processes: Set[int] = set()
        self._process_tree: Dict[int, List[int]] = {}
    
    def start(self) -> None:
        """Start process monitoring"""
        if self.is_running:
            return
        
        logger.info("Starting process monitor")
        
        # Get initial process snapshot
        self._tracked_processes = set(p.pid for p in psutil.process_iter())
        
        self.is_running = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
    
    def stop(self) -> None:
        """Stop process monitoring"""
        if not self.is_running:
            return
        
        logger.info("Stopping process monitor")
        self.is_running = False
        
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
    
    def _monitor_loop(self) -> None:
        """Main monitoring loop"""
        poll_interval = 0.5  # Check every 500ms
        
        while self.is_running:
            try:
                current_pids = set(p.pid for p in psutil.process_iter())
                
                # Detect new processes
                new_pids = current_pids - self._tracked_processes
                for pid in new_pids:
                    self._handle_process_created(pid)
                
                # Detect terminated processes
                terminated_pids = self._tracked_processes - current_pids
                for pid in terminated_pids:
                    self._handle_process_terminated(pid)
                
                self._tracked_processes = current_pids
                
                time.sleep(poll_interval)
                
            except Exception as e:
                logger.error(f"Process monitoring error: {e}")
                time.sleep(poll_interval)
    
    def _handle_process_created(self, pid: int) -> None:
        """Handle process creation event"""
        try:
            process = psutil.Process(pid)
            proc_info = {
                'pid': pid,
                'name': process.name(),
                'exe': process.exe(),
                'cmdline': ' '.join(process.cmdline()),
                'parent_pid': process.ppid(),
            }
            
            # Check for suspicious behavior
            severity = self._assess_process_severity(proc_info)
            
            # Track parent-child relationship
            parent_pid = proc_info['parent_pid']
            if parent_pid not in self._process_tree:
                self._process_tree[parent_pid] = []
            self._process_tree[parent_pid].append(pid)
            
            event = BehaviorEvent(
                event_type=EventType.PROCESS_CREATED,
                timestamp=time.time(),
                severity=severity,
                process_id=pid,
                process_name=proc_info['name'],
                description=f"Process created: {proc_info['name']}",
                data=proc_info
            )
            
            self.callback(event)
            
        except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError):
            pass
    
    def _handle_process_terminated(self, pid: int) -> None:
        """Handle process termination event"""
        event = BehaviorEvent(
            event_type=EventType.PROCESS_TERMINATED,
            timestamp=time.time(),
            severity=EventSeverity.INFO,
            process_id=pid,
            description=f"Process terminated: PID {pid}",
            data={'pid': pid}
        )
        
        self.callback(event)
        
        # Clean up process tree
        self._process_tree.pop(pid, None)
    
    def _assess_process_severity(self, proc_info: Dict) -> EventSeverity:
        """Assess severity of process based on characteristics"""
        name = proc_info.get('name', '').lower()
        cmdline = proc_info.get('cmdline', '').lower()
        exe = proc_info.get('exe', '').lower()
        
        # Critical processes
        critical_names = ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe']
        if name in critical_names:
            return EventSeverity.HIGH
        
        # Suspicious command line arguments
        suspicious_args = [
            'invoke-expression', 'downloadstring', 'hidden',
            'bypass', 'encoded', 'noprofile', 'noninteractive'
        ]
        if any(arg in cmdline for arg in suspicious_args):
            return EventSeverity.CRITICAL
        
        # System directory executables
        if 'system32' in exe or 'syswow64' in exe:
            return EventSeverity.MEDIUM
        
        return EventSeverity.INFO
    
    def get_process_tree(self) -> Dict[int, List[int]]:
        """Get current process tree"""
        return self._process_tree.copy()
