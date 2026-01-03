"""
Trojan Detector - Detects Trojan horses and backdoors
"""

from typing import Dict, Any, List, Optional
from sentinel.core.events import BehaviorEvent, EventType
import logging

logger = logging.getLogger(__name__)


class TrojanDetector:
    """Detects Trojan behavior patterns"""
    
    def __init__(self):
        self.trojan_indicators = {
            # Remote Access Trojan (RAT) indicators
            'rat_ports': [1337, 31337, 12345, 27374, 6666, 6667, 6668, 6669],  # Common RAT ports
            'rat_processes': ['rat.exe', 'remcos', 'njrat', 'darkcomet', 'cybergate'],
            
            # Banking Trojan indicators
            'banking_targets': ['chrome.dll', 'firefox.dll', 'msedge.dll', 'wallet', 'bank'],
            'banking_hooks': ['SetWindowsHookEx', 'GetAsyncKeyState', 'GetForegroundWindow'],
            
            # Dropper indicators
            'dropper_behavior': ['URLDownloadToFile', 'InternetReadFile', 'CreateProcess'],
        }
    
    def detect(self, events: List[BehaviorEvent], static_analysis: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect Trojan activity"""
        
        detections = []
        
        # Check for RAT behavior
        rat_detection = self._detect_rat(events, static_analysis)
        if rat_detection:
            detections.append(rat_detection)
        
        # Check for banking Trojan
        banking_detection = self._detect_banking_trojan(events, static_analysis)
        if banking_detection:
            detections.append(banking_detection)
        
        # Check for dropper behavior
        dropper_detection = self._detect_dropper(events, static_analysis)
        if dropper_detection:
            detections.append(dropper_detection)
        
        # Check for keylogger
        keylogger_detection = self._detect_keylogger(events, static_analysis)
        if keylogger_detection:
            detections.append(keylogger_detection)
        
        return detections if detections else None
    
    def _detect_rat(self, events: List[BehaviorEvent], static_analysis: Dict) -> Optional[Dict]:
        """Detect Remote Access Trojan"""
        indicators = []
        
        # Check for suspicious network connections
        network_events = [e for e in events if hasattr(e, 'event_type') and e.event_type == EventType.NETWORK_CONNECTION]
        
        for event in network_events:
            if hasattr(event, 'remote_port') and event.remote_port in self.trojan_indicators['rat_ports']:
                indicators.append(f'Connection to RAT port {event.remote_port}')
        
        # Check for screen capture APIs
        if 'dangerous_imports' in static_analysis:
            screen_apis = ['BitBlt', 'GetDC', 'CreateCompatibleDC']
            for api in static_analysis['dangerous_imports']:
                if any(screen_api in api.get('function', '') for screen_api in screen_apis):
                    indicators.append(f'Screen capture API: {api["function"]}')
        
        # Check for remote desktop APIs
        remote_apis = ['WTSEnumerateSessions', 'WTSQuerySessionInformation']
        if 'imports' in static_analysis:
            for dll, funcs in static_analysis['imports'].items():
                for func in funcs:
                    if func in remote_apis:
                        indicators.append(f'Remote desktop API: {func}')
        
        if len(indicators) >= 2:
            return {
                'threat_type': 'Trojan',
                'technique': 'Remote Access Trojan (RAT)',
                'confidence': min(95, len(indicators) * 25),
                'severity': 'critical',
                'description': f'Remote Access Trojan detected - enables attacker to control system remotely',
                'indicators': {
                    'rat_indicators': len(indicators),
                    'evidence': indicators
                },
                'impact': 'Full system compromise - attacker can: execute commands, steal files, capture screenshots, log keystrokes',
                'mitigation': 'Isolate system immediately, kill suspicious processes, check Task Scheduler and startup items'
            }
        
        return None
    
    def _detect_banking_trojan(self, events: List[BehaviorEvent], static_analysis: Dict) -> Optional[Dict]:
        """Detect Banking Trojan"""
        indicators = []
        
        # Check for browser injection
        browser_processes = ['chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe']
        process_events = [e for e in events if hasattr(e, 'event_type') and e.event_type in [EventType.PROCESS_CREATED, EventType.PROCESS_TERMINATED]]
        
        for event in process_events:
            if hasattr(event, 'process_name'):
                for browser in browser_processes:
                    if browser in event.process_name.lower():
                        indicators.append(f'Browser process interaction: {event.process_name}')
        
        # Check for form grabbing APIs
        form_apis = ['InternetSetOption', 'HttpSendRequest', 'InternetReadFile']
        if 'imports' in static_analysis:
            for dll, funcs in static_analysis['imports'].items():
                for func in funcs:
                    if func in form_apis:
                        indicators.append(f'Form grabbing API: {func}')
        
        # Check for banking keywords in strings
        if 'strings' in static_analysis and 'iocs' in static_analysis['strings']:
            suspicious_strings = static_analysis['strings']['iocs'].get('suspicious_strings', [])
            banking_keywords = ['bank', 'paypal', 'credit card', 'password', 'login']
            for s in suspicious_strings:
                if any(kw in s.lower() for kw in banking_keywords):
                    indicators.append(f'Banking keyword found: {s}')
        
        if len(indicators) >= 3:
            return {
                'threat_type': 'Trojan',
                'technique': 'Banking Trojan',
                'confidence': min(90, len(indicators) * 20),
                'severity': 'critical',
                'description': f'Banking Trojan detected - steals credentials and financial information',
                'indicators': {
                    'banking_indicators': len(indicators),
                    'evidence': indicators[:10]
                },
                'impact': 'Financial data theft - can steal: bank credentials, credit cards, online payment info',
                'mitigation': 'Change all banking passwords, enable 2FA, scan for browser extensions, check bank statements'
            }
        
        return None
    
    def _detect_dropper(self, events: List[BehaviorEvent], static_analysis: Dict) -> Optional[Dict]:
        """Detect Dropper/Downloader behavior"""
        indicators = []
        
        # Check for download APIs
        download_apis = ['URLDownloadToFile', 'InternetOpenUrl', 'HttpQueryInfo', 'InternetReadFile']
        if 'dangerous_imports' in static_analysis:
            for api in static_analysis['dangerous_imports']:
                if api.get('function') in download_apis:
                    indicators.append(f'Download API: {api["function"]}')
        
        # Check for file creation after network activity
        file_created = [e for e in events if hasattr(e, 'event_type') and e.event_type == EventType.FILE_CREATED]
        network_activity = [e for e in events if hasattr(e, 'event_type') and e.event_type == EventType.NETWORK_CONNECTION]
        
        if file_created and network_activity:
            indicators.append(f'{len(file_created)} files created after network activity')
        
        # Check for CreateProcess after download
        process_created = [e for e in events if hasattr(e, 'event_type') and e.event_type == EventType.PROCESS_CREATED]
        if process_created and network_activity:
            indicators.append('Process spawned after network connection - likely downloaded payload')
        
        if len(indicators) >= 2:
            return {
                'threat_type': 'Trojan',
                'technique': 'Dropper/Downloader',
                'confidence': min(85, len(indicators) * 25),
                'severity': 'high',
                'description': f'Dropper detected - downloads and executes additional malware',
                'indicators': {
                    'dropper_indicators': len(indicators),
                    'evidence': indicators
                },
                'impact': 'Multi-stage attack - downloads additional payloads (ransomware, spyware, etc.)',
                'mitigation': 'Block internet access, check downloaded files in temp directories, monitor scheduled tasks'
            }
        
        return None
    
    def _detect_keylogger(self, events: List[BehaviorEvent], static_analysis: Dict) -> Optional[Dict]:
        """Detect Keylogger"""
        indicators = []
        
        # Check for keyboard hook APIs
        keyboard_apis = ['SetWindowsHookEx', 'GetAsyncKeyState', 'GetKeyState', 'RegisterHotKey']
        if 'dangerous_imports' in static_analysis:
            for api in static_analysis['dangerous_imports']:
                if any(kapi in api.get('function', '') for kapi in keyboard_apis):
                    indicators.append(f'Keyboard monitoring API: {api["function"]}')
        
        # Check for low-level keyboard hook constant
        if 'imports' in static_analysis:
            for dll, funcs in static_analysis['imports'].items():
                if 'SetWindowsHookExA' in funcs or 'SetWindowsHookExW' in funcs:
                    indicators.append('Low-level keyboard hook detected')
        
        # Check for file logging behavior
        file_writes = [e for e in events if hasattr(e, 'event_type') and e.event_type in [EventType.FILE_MODIFIED, EventType.FILE_CREATED]]
        if len(file_writes) > 50:  # Frequent file writes = logging
            indicators.append(f'Excessive file writes ({len(file_writes)}) - consistent with keylogging')
        
        if len(indicators) >= 2:
            return {
                'threat_type': 'Trojan',
                'technique': 'Keylogger',
                'confidence': min(90, len(indicators) * 30),
                'severity': 'high',
                'description': f'Keylogger detected - records all keyboard input',
                'indicators': {
                    'keylogger_indicators': len(indicators),
                    'evidence': indicators
                },
                'impact': 'Credential theft - captures: passwords, credit cards, personal messages, confidential data',
                'mitigation': 'Use on-screen keyboard for sensitive input, change all passwords, check startup programs'
            }
        
        return None
