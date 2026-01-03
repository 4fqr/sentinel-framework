"""
Sentinel Framework - Persistence Detector
Identifies persistence mechanisms
"""

from typing import List, Dict, Any, Optional

from sentinel.core.monitor import BehaviorEvent, EventType
from sentinel.utils.logger import get_logger


logger = get_logger(__name__)


class PersistenceDetector:
    """Detects persistence mechanisms"""
    
    def __init__(self):
        """Initialize persistence detector"""
        self.autorun_keys = [
            'run', 'runonce', 'runonceex',
            'winlogon', 'userinit', 'shell'
        ]
        
        self.startup_locations = [
            'startup', 'start menu\\programs\\startup'
        ]
    
    def detect(self, events: List[BehaviorEvent], analysis_result: Any) -> List[Dict[str, Any]]:
        """
        Detect persistence mechanisms
        
        Args:
            events: List of behavioral events
            analysis_result: Complete analysis result
        
        Returns:
            List of detection results
        """
        detections = []
        
        # Check for registry persistence
        registry_persistence = self._detect_registry_persistence(events)
        if registry_persistence:
            detections.append(registry_persistence)
        
        # Check for startup folder persistence
        startup_persistence = self._detect_startup_persistence(events)
        if startup_persistence:
            detections.append(startup_persistence)
        
        # Check for scheduled task creation
        scheduled_task = self._detect_scheduled_task(events)
        if scheduled_task:
            detections.append(scheduled_task)
        
        # Check for service creation
        service_creation = self._detect_service_creation(events)
        if service_creation:
            detections.append(service_creation)
        
        return detections
    
    def _detect_registry_persistence(self, events: List[BehaviorEvent]) -> Optional[Dict[str, Any]]:
        """Detect registry-based persistence"""
        registry_events = [
            e for e in events
            if e.event_type in [EventType.REGISTRY_CREATED, EventType.REGISTRY_MODIFIED]
        ]
        
        persistence_modifications = []
        
        for event in registry_events:
            key_path = event.data.get('key_path', '').lower()
            
            # Check for autorun keys
            if any(autorun in key_path for autorun in self.autorun_keys):
                persistence_modifications.append({
                    'key': event.data.get('key_path'),
                    'value': event.data.get('value_name'),
                    'type': 'Registry Autorun'
                })
        
        if persistence_modifications:
            return {
                'threat_type': 'Persistence',
                'technique': 'Registry Modification',
                'description': f'Detected {len(persistence_modifications)} registry persistence mechanisms',
                'confidence': 85,
                'severity': 'high',
                'indicators': {
                    'modifications': persistence_modifications
                }
            }
        
        return None
    
    def _detect_startup_persistence(self, events: List[BehaviorEvent]) -> Optional[Dict[str, Any]]:
        """Detect startup folder persistence"""
        file_events = [
            e for e in events
            if e.event_type == EventType.FILE_CREATED
        ]
        
        startup_files = []
        
        for event in file_events:
            path = event.data.get('path', '').lower()
            
            # Check for startup folder
            if any(startup in path for startup in self.startup_locations):
                startup_files.append(path)
        
        if startup_files:
            return {
                'threat_type': 'Persistence',
                'technique': 'Startup Folder',
                'description': f'Detected {len(startup_files)} files added to startup folder',
                'confidence': 80,
                'severity': 'high',
                'indicators': {
                    'files': startup_files
                }
            }
        
        return None
    
    def _detect_scheduled_task(self, events: List[BehaviorEvent]) -> Optional[Dict[str, Any]]:
        """Detect scheduled task creation"""
        process_events = [
            e for e in events
            if e.event_type == EventType.PROCESS_CREATED
        ]
        
        for event in process_events:
            cmdline = event.data.get('cmdline', '').lower()
            
            # Check for schtasks.exe
            if 'schtasks' in cmdline and '/create' in cmdline:
                return {
                    'threat_type': 'Persistence',
                    'technique': 'Scheduled Task',
                    'description': 'Detected scheduled task creation',
                    'confidence': 90,
                    'severity': 'high',
                    'indicators': {
                        'command': cmdline
                    }
                }
        
        return None
    
    def _detect_service_creation(self, events: List[BehaviorEvent]) -> Optional[Dict[str, Any]]:
        """Detect Windows service creation"""
        process_events = [
            e for e in events
            if e.event_type == EventType.PROCESS_CREATED
        ]
        
        for event in process_events:
            cmdline = event.data.get('cmdline', '').lower()
            
            # Check for sc.exe service creation
            if 'sc' in cmdline and 'create' in cmdline:
                return {
                    'threat_type': 'Persistence',
                    'technique': 'Service Creation',
                    'description': 'Detected Windows service creation',
                    'confidence': 90,
                    'severity': 'high',
                    'indicators': {
                        'command': cmdline
                    }
                }
        
        return None
