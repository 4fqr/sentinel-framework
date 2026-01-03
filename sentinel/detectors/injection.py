"""
Sentinel Framework - Code Injection Detector
Identifies process injection and code manipulation techniques
"""

from typing import List, Dict, Any, Optional

from sentinel.core.monitor import BehaviorEvent, EventType
from sentinel.utils.logger import get_logger


logger = get_logger(__name__)


class InjectionDetector:
    """Detects code injection techniques"""
    
    def __init__(self):
        """Initialize injection detector"""
        self.injection_apis = [
            'CreateRemoteThread', 'NtCreateThreadEx',
            'QueueUserAPC', 'SetThreadContext',
            'WriteProcessMemory', 'VirtualAllocEx',
            'NtMapViewOfSection', 'RtlCreateUserThread'
        ]
        
        self.suspicious_processes = [
            'powershell.exe', 'cmd.exe', 'wscript.exe',
            'cscript.exe', 'mshta.exe', 'rundll32.exe'
        ]
    
    def detect(self, events: List[BehaviorEvent], analysis_result: Any) -> List[Dict[str, Any]]:
        """
        Detect code injection patterns
        
        Args:
            events: List of behavioral events
            analysis_result: Complete analysis result
        
        Returns:
            List of detection results
        """
        detections = []
        
        # Check for process injection APIs in imports
        injection_detection = self._detect_injection_apis(analysis_result)
        if injection_detection:
            detections.append(injection_detection)
        
        # Check for process hollowing
        hollowing = self._detect_process_hollowing(events)
        if hollowing:
            detections.append(hollowing)
        
        # Check for DLL injection
        dll_injection = self._detect_dll_injection(events)
        if dll_injection:
            detections.append(dll_injection)
        
        # Check for suspicious child processes
        suspicious_children = self._detect_suspicious_children(events)
        if suspicious_children:
            detections.append(suspicious_children)
        
        return detections
    
    def _detect_injection_apis(self, analysis_result: Any) -> Optional[Dict[str, Any]]:
        """Detect presence of injection-related APIs"""
        static_analysis = analysis_result.static_analysis
        suspicious_imports = static_analysis.get('suspicious_imports', [])
        
        injection_imports = []
        for imp in suspicious_imports:
            if any(api in imp for api in self.injection_apis):
                injection_imports.append(imp)
        
        if len(injection_imports) >= 2:
            return {
                'threat_type': 'Code Injection',
                'technique': 'Injection APIs',
                'description': f'Detected {len(injection_imports)} injection-related API imports',
                'confidence': min(95, 60 + len(injection_imports) * 10),
                'severity': 'high',
                'indicators': {
                    'apis': injection_imports
                }
            }
        
        return None
    
    def _detect_process_hollowing(self, events: List[BehaviorEvent]) -> Optional[Dict[str, Any]]:
        """Detect process hollowing technique"""
        process_events = [
            e for e in events
            if e.event_type == EventType.PROCESS_CREATED
        ]
        
        for event in process_events:
            cmdline = event.data.get('cmdline', '').lower()
            
            # Look for suspended process creation
            if 'suspended' in cmdline or '/suspend' in cmdline:
                return {
                    'threat_type': 'Code Injection',
                    'technique': 'Process Hollowing',
                    'description': 'Detected process creation in suspended state',
                    'confidence': 85,
                    'severity': 'critical',
                    'indicators': {
                        'process': event.data.get('name'),
                        'cmdline': cmdline
                    }
                }
        
        return None
    
    def _detect_dll_injection(self, events: List[BehaviorEvent]) -> Optional[Dict[str, Any]]:
        """Detect DLL injection attempts"""
        file_events = [
            e for e in events
            if e.event_type in [EventType.FILE_CREATED, EventType.FILE_MODIFIED]
        ]
        
        dll_operations = []
        for event in file_events:
            path = event.data.get('path', '')
            
            # Check for DLL operations in suspicious locations
            if path.lower().endswith('.dll'):
                if any(loc in path.lower() for loc in ['temp', 'appdata', 'public']):
                    dll_operations.append(path)
        
        if dll_operations:
            return {
                'threat_type': 'Code Injection',
                'technique': 'DLL Injection',
                'description': f'Detected {len(dll_operations)} suspicious DLL operations',
                'confidence': 70,
                'severity': 'high',
                'indicators': {
                    'dlls': dll_operations
                }
            }
        
        return None
    
    def _detect_suspicious_children(self, events: List[BehaviorEvent]) -> Optional[Dict[str, Any]]:
        """Detect suspicious child processes"""
        process_events = [
            e for e in events
            if e.event_type == EventType.PROCESS_CREATED
        ]
        
        suspicious_spawns = []
        
        for event in process_events:
            process_name = event.data.get('name', '').lower()
            cmdline = event.data.get('cmdline', '').lower()
            
            # Check for suspicious processes
            if process_name in self.suspicious_processes:
                # Extra suspicious if using obfuscation or encoding
                if any(keyword in cmdline for keyword in ['encoded', 'hidden', 'bypass']):
                    suspicious_spawns.append({
                        'process': process_name,
                        'cmdline': cmdline,
                        'reason': 'Suspicious process with obfuscation'
                    })
        
        if suspicious_spawns:
            return {
                'threat_type': 'Code Injection',
                'technique': 'Suspicious Child Process',
                'description': f'Detected {len(suspicious_spawns)} suspicious child processes',
                'confidence': 75,
                'severity': 'high',
                'indicators': {
                    'processes': suspicious_spawns
                }
            }
        
        return None
