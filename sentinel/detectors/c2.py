"""
Sentinel Framework - C2 (Command & Control) Detector
Identifies command and control communication patterns
"""

from typing import List, Dict, Any, Optional
from collections import defaultdict
import re

from sentinel.core.events import BehaviorEvent, EventType
from sentinel.utils.logger import get_logger


logger = get_logger(__name__)


class C2Detector:
    """Detects command and control communication patterns"""
    
    def __init__(self):
        """Initialize C2 detector"""
        self.suspicious_domains = [
            'duckdns.org', 'no-ip.', 'freeddns.',
            'ddns.net', 'ngrok.io', 'localtunnel.me'
        ]
        
        self.suspicious_ports = [4444, 5555, 6666, 8080, 8888, 9999]
    
    def detect(self, events: List[BehaviorEvent], analysis_result: Any) -> List[Dict[str, Any]]:
        """
        Detect C2 communication patterns
        
        Args:
            events: List of behavioral events
            analysis_result: Complete analysis result
        
        Returns:
            List of detection results
        """
        detections = []
        
        # Check for beaconing behavior
        beaconing = self._detect_beaconing(events)
        if beaconing:
            detections.append(beaconing)
        
        # Check for suspicious domains
        suspicious_domains = self._detect_suspicious_domains(events)
        if suspicious_domains:
            detections.append(suspicious_domains)
        
        # Check for non-standard ports
        suspicious_ports = self._detect_suspicious_ports(events)
        if suspicious_ports:
            detections.append(suspicious_ports)
        
        return detections
    
    def _detect_beaconing(self, events: List[BehaviorEvent]) -> Optional[Dict[str, Any]]:
        """Detect beaconing behavior (periodic C2 check-ins)"""
        network_events = [
            e for e in events
            if e.event_type == EventType.NETWORK_CONNECTION
        ]
        
        if len(network_events) < 3:
            return None
        
        # Group connections by remote IP
        connections_by_ip = defaultdict(list)
        for event in network_events:
            remote_ip = event.data.get('remote_ip')
            if remote_ip:
                connections_by_ip[remote_ip].append(event.timestamp)
        
        # Check for regular intervals
        for ip, timestamps in connections_by_ip.items():
            if len(timestamps) < 3:
                continue
            
            # Calculate intervals between connections
            intervals = []
            for i in range(1, len(timestamps)):
                intervals.append(timestamps[i] - timestamps[i-1])
            
            # Check if intervals are regular (within 10% variance)
            if len(intervals) >= 2:
                avg_interval = sum(intervals) / len(intervals)
                variance = sum(abs(i - avg_interval) for i in intervals) / len(intervals)
                regularity = 1 - (variance / avg_interval) if avg_interval > 0 else 0
                
                # If intervals are regular (>80% similarity), likely beaconing
                if regularity > 0.8:
                    return {
                        'threat_type': 'C2 Communication',
                        'technique': 'Beaconing',
                        'description': f'Detected regular beaconing to {ip} ({len(timestamps)} connections)',
                        'confidence': int(regularity * 100),
                        'severity': 'high',
                        'indicators': {
                            'remote_ip': ip,
                            'connection_count': len(timestamps),
                            'avg_interval': f'{avg_interval:.2f}s',
                            'regularity': f'{regularity * 100:.1f}%'
                        }
                    }
        
        return None
    
    def _detect_suspicious_domains(self, events: List[BehaviorEvent]) -> Optional[Dict[str, Any]]:
        """Detect connections to suspicious domains"""
        network_events = [
            e for e in events
            if e.event_type == EventType.NETWORK_CONNECTION
        ]
        
        suspicious_connections = []
        
        for event in network_events:
            hostname = event.data.get('hostname', '')
            remote_ip = event.data.get('remote_ip', '')
            
            # Check against known suspicious TLDs and services
            for suspicious in self.suspicious_domains:
                if suspicious in hostname.lower():
                    suspicious_connections.append({
                        'hostname': hostname,
                        'ip': remote_ip,
                        'reason': f'Suspicious domain: {suspicious}'
                    })
                    break
        
        if suspicious_connections:
            return {
                'threat_type': 'C2 Communication',
                'technique': 'Suspicious Domain',
                'description': f'Detected {len(suspicious_connections)} connections to suspicious domains',
                'confidence': 70,
                'severity': 'medium',
                'indicators': {
                    'connections': suspicious_connections
                }
            }
        
        return None
    
    def _detect_suspicious_ports(self, events: List[BehaviorEvent]) -> Optional[Dict[str, Any]]:
        """Detect connections to suspicious ports"""
        network_events = [
            e for e in events
            if e.event_type == EventType.NETWORK_CONNECTION
        ]
        
        suspicious_connections = []
        
        for event in network_events:
            remote_port = event.data.get('remote_port')
            remote_ip = event.data.get('remote_ip')
            
            if remote_port in self.suspicious_ports:
                suspicious_connections.append({
                    'ip': remote_ip,
                    'port': remote_port,
                    'protocol': event.data.get('protocol', 'Unknown')
                })
        
        if suspicious_connections:
            return {
                'threat_type': 'C2 Communication',
                'technique': 'Non-Standard Port',
                'description': f'Detected {len(suspicious_connections)} connections to suspicious ports',
                'confidence': 65,
                'severity': 'medium',
                'indicators': {
                    'connections': suspicious_connections
                }
            }
        
        return None
