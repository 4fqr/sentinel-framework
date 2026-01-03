"""
Sentinel Framework - File System Monitor
Tracks file system operations and modifications
"""

import os
import threading
from pathlib import Path
from typing import Callable, List, Optional, Set
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

from sentinel.core.events import BehaviorEvent, EventType, EventSeverity
from sentinel.config import config
from sentinel.utils.logger import get_logger


logger = get_logger(__name__)


class FileSystemEventAdapter(FileSystemEventHandler):
    """Adapter to convert watchdog events to BehaviorEvents"""
    
    def __init__(self, callback: Callable[[BehaviorEvent], None]):
        """
        Initialize adapter
        
        Args:
            callback: Function to call with behavior events
        """
        super().__init__()
        self.callback = callback
    
    def on_created(self, event: FileSystemEvent) -> None:
        """Handle file creation"""
        if not event.is_directory:
            self._emit_event(
                EventType.FILE_CREATED,
                event.src_path,
                "File created"
            )
    
    def on_modified(self, event: FileSystemEvent) -> None:
        """Handle file modification"""
        if not event.is_directory:
            self._emit_event(
                EventType.FILE_MODIFIED,
                event.src_path,
                "File modified"
            )
    
    def on_deleted(self, event: FileSystemEvent) -> None:
        """Handle file deletion"""
        if not event.is_directory:
            self._emit_event(
                EventType.FILE_DELETED,
                event.src_path,
                "File deleted",
                severity=EventSeverity.MEDIUM
            )
    
    def on_moved(self, event: FileSystemEvent) -> None:
        """Handle file rename/move"""
        if not event.is_directory:
            self._emit_event(
                EventType.FILE_RENAMED,
                event.src_path,
                f"File renamed to {event.dest_path}",
                data={'destination': event.dest_path}
            )
    
    def _emit_event(
        self,
        event_type: EventType,
        path: str,
        description: str,
        severity: EventSeverity = EventSeverity.INFO,
        data: Optional[dict] = None
    ) -> None:
        """Emit behavior event"""
        import time
        
        event_data = data or {}
        event_data['path'] = path
        event_data['file_name'] = os.path.basename(path)
        event_data['directory'] = os.path.dirname(path)
        
        # Check for suspicious extensions
        ext = Path(path).suffix.lower()
        suspicious_extensions = [
            '.exe', '.dll', '.bat', '.ps1', '.vbs', '.js',
            '.encrypted', '.locked', '.crypto'
        ]
        
        if ext in suspicious_extensions:
            severity = EventSeverity.MEDIUM
            event_data['suspicious'] = True
        
        # Check for system directories
        system_paths = ['windows', 'system32', 'program files']
        if any(sp in path.lower() for sp in system_paths):
            severity = EventSeverity.HIGH
            event_data['system_directory'] = True
        
        behavior_event = BehaviorEvent(
            event_type=event_type,
            timestamp=time.time(),
            severity=severity,
            description=description,
            data=event_data
        )
        
        self.callback(behavior_event)


class FileSystemMonitor:
    """Monitors file system operations"""
    
    def __init__(self, callback: Callable[[BehaviorEvent], None]):
        """
        Initialize file system monitor
        
        Args:
            callback: Function to call with behavior events
        """
        self.callback = callback
        self.config = config.get_section('monitoring').get('file_system', {})
        self.observer: Optional[Observer] = None
        self.watch_paths: List[str] = []
        self.is_running = False
        
        self._setup_watch_paths()
    
    def _setup_watch_paths(self) -> None:
        """Setup paths to monitor"""
        configured_paths = self.config.get('watch_paths', [])
        
        for path in configured_paths:
            # Expand environment variables
            expanded = os.path.expandvars(path)
            
            if os.path.exists(expanded):
                self.watch_paths.append(expanded)
            else:
                logger.warning(f"Watch path does not exist: {expanded}")
    
    def start(self) -> None:
        """Start file system monitoring"""
        if self.is_running:
            return
        
        logger.info("Starting file system monitor")
        
        self.observer = Observer()
        event_handler = FileSystemEventAdapter(self.callback)
        
        # Schedule observers for each watch path
        for path in self.watch_paths:
            try:
                self.observer.schedule(event_handler, path, recursive=True)
                logger.debug(f"Watching: {path}")
            except Exception as e:
                logger.error(f"Failed to watch {path}: {e}")
        
        self.observer.start()
        self.is_running = True
    
    def stop(self) -> None:
        """Stop file system monitoring"""
        if not self.is_running or not self.observer:
            return
        
        logger.info("Stopping file system monitor")
        
        self.observer.stop()
        self.observer.join()
        self.is_running = False
