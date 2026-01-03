"""
Sentinel Framework - Evasion Detector
Identifies anti-analysis and evasion techniques
"""

from typing import List, Dict, Any, Optional

from sentinel.core.monitor import BehaviorEvent, EventType
from sentinel.utils.logger import get_logger


logger = get_logger(__name__)


class EvasionDetector:
    """Detects anti-analysis and evasion techniques"""
    
    def __init__(self):
        """Initialize evasion detector"""
        self.vm_artifacts = [
            'vmware', 'virtualbox', 'vbox', 'qemu',
            'xen', 'parallels', 'vmtoolsd', 'vmmouse'
        ]
        
        self.analysis_tools = [
            'wireshark', 'fiddler', 'procmon', 'processhacker',
            'ollydbg', 'x64dbg', 'ida', 'ghidra'
        ]
    
    def detect(self, events: List[BehaviorEvent], analysis_result: Any) -> List[Dict[str, Any]]:
        """
        Detect evasion techniques
        
        Args:
            events: List of behavioral events
            analysis_result: Complete analysis result
        
        Returns:
            List of detection results
        """
        detections = []
        
        # Check for VM detection attempts
        vm_detection = self._detect_vm_checks(events, analysis_result)
        if vm_detection:
            detections.append(vm_detection)
        
        # Check for debugger detection
        debugger_detection = self._detect_debugger_checks(events, analysis_result)
        if debugger_detection:
            detections.append(debugger_detection)
        
        # Check for time-based evasion
        time_evasion = self._detect_time_evasion(events)
        if time_evasion:
            detections.append(time_evasion)
        
        # Check for analysis tool detection
        tool_detection = self._detect_analysis_tools(events)
        if tool_detection:
            detections.append(tool_detection)
        
        return detections
    
    def _detect_vm_checks(
        self,
        events: List[BehaviorEvent],
        analysis_result: Any
    ) -> Optional[Dict[str, Any]]:
        """Detect virtual machine detection attempts"""
        vm_indicators = []
        
        # Check static strings for VM artifacts
        static_analysis = analysis_result.static_analysis
        strings = static_analysis.get('strings', {})
        suspicious_strings = strings.get('suspicious', [])
        
        for string in suspicious_strings:
            if any(vm_artifact in string.lower() for vm_artifact in self.vm_artifacts):
                vm_indicators.append(f'String: {string}')
        
        # Check for registry queries to VM-related keys
        registry_events = [
            e for e in events
            if e.event_type == EventType.REGISTRY_CREATED
        ]
        
        for event in registry_events:
            key_path = event.data.get('key_path', '').lower()
            if any(vm_artifact in key_path for vm_artifact in self.vm_artifacts):
                vm_indicators.append(f'Registry: {key_path}')
        
        if vm_indicators:
            return {
                'threat_type': 'Evasion',
                'technique': 'VM Detection',
                'description': f'Detected {len(vm_indicators)} VM detection indicators',
                'confidence': 75,
                'severity': 'medium',
                'indicators': {
                    'checks': vm_indicators
                }
            }
        
        return None
    
    def _detect_debugger_checks(
        self,
        events: List[BehaviorEvent],
        analysis_result: Any
    ) -> Optional[Dict[str, Any]]:
        """Detect debugger detection attempts"""
        # Check for debugger-related API imports
        static_analysis = analysis_result.static_analysis
        suspicious_imports = static_analysis.get('suspicious_imports', [])
        
        debugger_apis = [
            'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
            'NtQueryInformationProcess', 'OutputDebugString'
        ]
        
        debugger_imports = []
        for imp in suspicious_imports:
            if any(api in imp for api in debugger_apis):
                debugger_imports.append(imp)
        
        if debugger_imports:
            return {
                'threat_type': 'Evasion',
                'technique': 'Debugger Detection',
                'description': f'Detected {len(debugger_imports)} debugger detection APIs',
                'confidence': 80,
                'severity': 'medium',
                'indicators': {
                    'apis': debugger_imports
                }
            }
        
        return None
    
    def _detect_time_evasion(self, events: List[BehaviorEvent]) -> Optional[Dict[str, Any]]:
        """Detect time-based evasion (delays before malicious activity)"""
        process_events = [
            e for e in events
            if e.event_type == EventType.PROCESS_CREATED
        ]
        
        for event in process_events:
            cmdline = event.data.get('cmdline', '').lower()
            
            # Check for sleep/delay commands
            delay_keywords = ['sleep', 'timeout', 'ping -n', 'start-sleep']
            
            for keyword in delay_keywords:
                if keyword in cmdline:
                    return {
                        'threat_type': 'Evasion',
                        'technique': 'Time-based Evasion',
                        'description': 'Detected deliberate execution delay',
                        'confidence': 65,
                        'severity': 'low',
                        'indicators': {
                            'command': cmdline
                        }
                    }
        
        return None
    
    def _detect_analysis_tools(self, events: List[BehaviorEvent]) -> Optional[Dict[str, Any]]:
        """Detect checks for analysis tools"""
        process_events = [
            e for e in events
            if e.event_type == EventType.PROCESS_CREATED
        ]
        
        tool_checks = []
        
        for event in process_events:
            process_name = event.data.get('name', '').lower()
            
            # Check if looking for analysis tools
            if 'tasklist' in process_name or 'wmic process' in event.data.get('cmdline', '').lower():
                tool_checks.append('Process enumeration detected')
        
        if tool_checks:
            return {
                'threat_type': 'Evasion',
                'technique': 'Analysis Tool Detection',
                'description': 'Detected attempts to enumerate running processes',
                'confidence': 60,
                'severity': 'low',
                'indicators': {
                    'checks': tool_checks
                }
            }
        
        return None
