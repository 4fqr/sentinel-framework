"""
Comprehensive Malware Family Detector
Detects: Trojans, Worms, Rootkits, Botnets, Miners, Spyware, Adware, APT techniques
"""

from typing import List, Dict, Any
from sentinel.core.events import EventType
import logging

logger = logging.getLogger(__name__)


class ComprehensiveMalwareDetector:
    """All-in-one malware family detector"""
    
    def __init__(self):
        self.malware_signatures = self._load_signatures()
    
    def _load_signatures(self) -> Dict:
        """Load malware family signatures"""
        return {
            'rootkit': {
                'apis': ['ZwQuerySystemInformation', 'NtQuerySystemInformation', 'KeServiceDescriptorTable', 'SSDT'],
                'behaviors': ['driver_load', 'kernel_modification'],
                'severity': 'CRITICAL'
            },
            'botnet': {
                'apis': ['InternetOpen', 'HttpSendRequest', 'send', 'recv'],
                'behaviors': ['periodic_beacon', 'command_control'],
                'ports': [6667, 6668, 6669, 8080, 443],  # IRC and HTTPS C2
                'severity': 'CRITICAL'
            },
            'cryptominer': {
                'apis': ['CreateThread', 'SetThreadPriority', 'CryptGenRandom'],
                'processes': ['xmrig', 'minergate', 'cpuminer'],
                'network_indicators': ['pool.', 'mining', ':3333', ':8080'],
                'severity': 'HIGH'
            },
            'worm': {
                'apis': ['CreateFileMapping', 'CopyFile', 'MoveFile'],
                'behaviors': ['network_scan', 'self_replication', 'usb_spread'],
                'severity': 'HIGH'
            },
            'spyware': {
                'apis': ['GetForegroundWindow', 'GetWindowText', 'GetKeyState', 'GetClipboardData'],
                'behaviors': ['screenshot', 'clipboard_monitor', 'browser_history'],
                'severity': 'HIGH'
            },
            'adware': {
                'apis': ['InternetOpenUrl', 'ShellExecute', 'CreateProcess'],
                'indicators': ['ad', 'banner', 'popup', 'advertisement'],
                'severity': 'MEDIUM'
            },
            'rat': {
                'apis': ['VirtualAlloc', 'WriteProcessMemory', 'CreateRemoteThread', 'OpenProcess'],
                'behaviors': ['remote_shell', 'file_transfer', 'screen_capture'],
                'severity': 'CRITICAL'
            }
        }
    
    def detect(self, events: List, static_analysis: Dict) -> List[Dict[str, Any]]:
        """Standard detect interface that calls detect_all"""
        return self.detect_all(events, static_analysis)
    
    def detect_all(self, events: List, static_analysis: Dict) -> List[Dict[str, Any]]:
        """Detect all malware families"""
        detections = []
        
        # Rootkit detection
        rootkit = self._detect_rootkit(static_analysis)
        if rootkit:
            detections.append(rootkit)
        
        # Botnet detection
        botnet = self._detect_botnet(events, static_analysis)
        if botnet:
            detections.append(botnet)
        
        # Cryptominer detection
        miner = self._detect_cryptominer(events, static_analysis)
        if miner:
            detections.append(miner)
        
        # Worm detection
        worm = self._detect_worm(events, static_analysis)
        if worm:
            detections.append(worm)
        
        # Spyware detection
        spyware = self._detect_spyware(events, static_analysis)
        if spyware:
            detections.append(spyware)
        
        # Fileless malware detection
        fileless = self._detect_fileless(events, static_analysis)
        if fileless:
            detections.append(fileless)
        
        return detections
    
    def _detect_rootkit(self, static_analysis: Dict) -> Dict:
        """Detect rootkit indicators"""
        indicators = []
        
        if 'dangerous_imports' in static_analysis:
            for api in static_analysis['dangerous_imports']:
                if any(rootkit_api in api.get('function', '') for rootkit_api in self.malware_signatures['rootkit']['apis']):
                    indicators.append(f'Rootkit API: {api["function"]}')
        
        # Check for .sys file (driver)
        if 'file_type' in static_analysis:
            if '.sys' in static_analysis['file_type'].lower() or 'driver' in static_analysis['file_type'].lower():
                indicators.append('Kernel driver detected')
        
        if len(indicators) >= 2:
            return {
                'threat_type': 'Rootkit',
                'technique': 'Kernel Manipulation',
                'confidence': 95,
                'severity': 'critical',
                'description': 'Rootkit detected - operates at kernel level to hide malicious activity',
                'indicators': {'evidence': indicators},
                'impact': 'Complete system compromise - can hide processes, files, network connections',
                'mitigation': 'Boot into Safe Mode, use rootkit scanner, reinstall OS if persistent'
            }
        return None
    
    def _detect_botnet(self, events: List, static_analysis: Dict) -> Dict:
        """Detect botnet behavior"""
        indicators = []
        
        # Check for periodic network beaconing
        network_events = [e for e in events if hasattr(e, 'event_type') and e.event_type == EventType.NETWORK_CONNECTION]
        if len(network_events) > 10:
            indicators.append(f'{len(network_events)} network connections - potential C2 beaconing')
        
        # Check for IRC ports
        for event in network_events:
            if hasattr(event, 'remote_port') and event.remote_port in self.malware_signatures['botnet']['ports']:
                indicators.append(f'Botnet port detected: {event.remote_port}')
        
        if len(indicators) >= 2:
            return {
                'threat_type': 'Botnet',
                'technique': 'Command & Control Communication',
                'confidence': 90,
                'severity': 'critical',
                'description': 'Botnet agent detected - system is part of attacker botnet',
                'indicators': {'evidence': indicators},
                'impact': 'System used for DDoS attacks, spam, cryptocurrency mining, data theft',
                'mitigation': 'Block C2 IPs, isolate system, analyze network traffic, check DNS requests'
            }
        return None
    
    def _detect_cryptominer(self, events: List, static_analysis: Dict) -> Dict:
        """Detect cryptocurrency miner"""
        indicators = []
        
        # Check for mining pool connections
        if 'strings' in static_analysis and 'iocs' in static_analysis['strings']:
            urls = static_analysis['strings']['iocs'].get('urls', [])
            for url in urls:
                if any(ind in url.lower() for ind in self.malware_signatures['cryptominer']['network_indicators']):
                    indicators.append(f'Mining pool URL: {url}')
        
        # Check for CPU-intensive operations
        if 'dangerous_imports' in static_analysis:
            thread_apis = [api for api in static_analysis['dangerous_imports'] if 'Thread' in api.get('function', '')]
            if len(thread_apis) > 5:
                indicators.append(f'{len(thread_apis)} thread creation APIs - CPU mining pattern')
        
        if len(indicators) >= 2:
            return {
                'threat_type': 'Cryptominer',
                'technique': 'Cryptocurrency Mining',
                'confidence': 85,
                'severity': 'high',
                'description': 'Cryptocurrency miner detected - consumes system resources',
                'indicators': {'evidence': indicators},
                'impact': 'High CPU/GPU usage, electricity cost, system slowdown, hardware wear',
                'mitigation': 'Kill mining process, block mining pools, check scheduled tasks and startup'
            }
        return None
    
    def _detect_worm(self, events: List, static_analysis: Dict) -> Dict:
        """Detect worm behavior"""
        indicators = []
        
        # Check for file replication
        file_created = [e for e in events if hasattr(e, 'event_type') and e.event_type == EventType.FILE_CREATED]
        if len(file_created) > 20:
            indicators.append(f'{len(file_created)} files created - possible self-replication')
        
        # Check for network scanning
        network_events = [e for e in events if hasattr(e, 'event_type') and e.event_type == EventType.NETWORK_CONNECTION]
        unique_ips = set()
        for event in network_events:
            if hasattr(event, 'remote_ip'):
                unique_ips.add(event.remote_ip)
        
        if len(unique_ips) > 10:
            indicators.append(f'Connected to {len(unique_ips)} different IPs - network scanning')
        
        if len(indicators) >= 2:
            return {
                'threat_type': 'Worm',
                'technique': 'Self-Replication',
                'confidence': 80,
                'severity': 'high',
                'description': 'Worm detected - spreads across network automatically',
                'indicators': {'evidence': indicators},
                'impact': 'Network-wide infection, bandwidth consumption, system compromise',
                'mitigation': 'Isolate infected systems, block affected ports, patch vulnerabilities'
            }
        return None
    
    def _detect_spyware(self, events: List, static_analysis: Dict) -> Dict:
        """Detect spyware"""
        indicators = []
        
        # Check for clipboard monitoring
        if 'dangerous_imports' in static_analysis:
            spyware_apis = ['GetClipboardData', 'GetForegroundWindow', 'GetWindowText']
            for api in static_analysis['dangerous_imports']:
                if api.get('function') in spyware_apis:
                    indicators.append(f'Spyware API: {api["function"]}')
        
        # Check for screenshot APIs
        screenshot_apis = ['BitBlt', 'GetDC', 'CreateCompatibleDC']
        if 'imports' in static_analysis:
            for dll, funcs in static_analysis['imports'].items():
                for func in funcs:
                    if func in screenshot_apis:
                        indicators.append(f'Screenshot capability: {func}')
        
        if len(indicators) >= 2:
            return {
                'threat_type': 'Spyware',
                'technique': 'Information Stealing',
                'confidence': 85,
                'severity': 'high',
                'description': 'Spyware detected - monitors user activity and steals data',
                'indicators': {'evidence': indicators},
                'impact': 'Privacy violation - steals passwords, browsing history, personal data',
                'mitigation': 'Remove spyware, change passwords, check browser extensions, scan for keyloggers'
            }
        return None
    
    def _detect_fileless(self, events: List, static_analysis: Dict) -> Dict:
        """Detect fileless malware techniques"""
        indicators = []
        
        # Check for PowerShell usage
        process_events = [e for e in events if hasattr(e, 'event_type') and e.event_type in [EventType.PROCESS_CREATED, EventType.PROCESS_TERMINATED]]
        for event in process_events:
            if hasattr(event, 'process_name') and 'powershell' in event.process_name.lower():
                indicators.append('PowerShell execution detected')
        
        # Check for WMI usage
        if 'imports' in static_analysis:
            for dll, funcs in static_analysis['imports'].items():
                if any('WMI' in func for func in funcs):
                    indicators.append('WMI API usage - fileless execution vector')
        
        # Check for memory-only execution
        if 'dangerous_imports' in static_analysis:
            memory_apis = ['VirtualAlloc', 'VirtualProtect', 'WriteProcessMemory']
            mem_count = sum(1 for api in static_analysis['dangerous_imports'] if api.get('function') in memory_apis)
            if mem_count >= 2:
                indicators.append(f'{mem_count} memory manipulation APIs - in-memory execution')
        
        if len(indicators) >= 2:
            return {
                'threat_type': 'Fileless Malware',
                'technique': 'Living-off-the-Land / Memory-Resident',
                'confidence': 80,
                'severity': 'critical',
                'description': 'Fileless malware detected - operates without dropping files',
                'indicators': {'evidence': indicators},
                'impact': 'Evades traditional AV, harder to detect and remove, persistent threat',
                'mitigation': 'Monitor PowerShell/WMI usage, enable script logging, use EDR solutions'
            }
        return None
