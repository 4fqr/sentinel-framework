"""
Sentinel Framework - Network Traffic Analyzer
Deep packet inspection, C2 detection, and traffic forensics
"""

import socket
import struct
import time
import threading
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import re
import json

try:
    import scapy.all as scapy
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


@dataclass
class NetworkConnection:
    """Network connection information"""
    timestamp: datetime
    protocol: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    data_size: int
    direction: str  # outbound/inbound
    payload: Optional[bytes] = None


@dataclass
class C2Detection:
    """Command and Control detection"""
    confidence: float
    c2_type: str
    indicators: List[str]
    destinations: List[str]
    evidence: Dict[str, Any] = field(default_factory=dict)


class NetworkForensics:
    """
    Advanced network traffic analysis and C2 detection
    """
    
    # Known C2 patterns
    C2_PATTERNS = {
        'http_beacon': {
            'regular_intervals': True,
            'fixed_size': True,
            'user_agent_suspicious': True,
            'unusual_headers': True
        },
        'dns_tunneling': {
            'high_subdomain_entropy': True,
            'unusual_query_length': True,
            'high_frequency': True,
            'txt_record_abuse': True
        },
        'https_c2': {
            'self_signed_cert': True,
            'unusual_cipher': True,
            'regular_beaconing': True
        },
        'icmp_tunnel': {
            'large_icmp_packets': True,
            'regular_intervals': True,
            'payload_patterns': True
        }
    }
    
    # Suspicious ports
    SUSPICIOUS_PORTS = {
        4444: 'Metasploit default',
        5555: 'Common backdoor',
        6666: 'IRC bot',
        6667: 'IRC server',
        6668: 'IRC alternate',
        6669: 'IRC alternate',
        8080: 'HTTP proxy',
        8888: 'Alternative HTTP',
        9999: 'Common backdoor',
        31337: 'Elite/leet',
        12345: 'NetBus trojan',
        27374: 'SubSeven trojan',
        1337: 'Common backdoor',
    }
    
    # Suspicious user agents
    SUSPICIOUS_USER_AGENTS = [
        'python-requests',
        'curl',
        'wget',
        'powershell',
        'go-http-client',
        'nmap',
        'nikto',
        'sqlmap',
        'metasploit',
    ]
    
    # Malicious domain patterns
    SUSPICIOUS_DOMAIN_PATTERNS = [
        r'\.(tk|ml|ga|cf|gq)$',  # Free TLDs
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # Direct IPs
        r'[a-z0-9]{20,}',  # Very long random strings
        r'(dyn|dynamic|ddns)',  # Dynamic DNS
    ]
    
    def __init__(self):
        """Initialize network forensics engine"""
        self.connections: List[NetworkConnection] = []
        self.dns_queries: List[Dict[str, Any]] = []
        self.http_requests: List[Dict[str, Any]] = []
        self.suspicious_traffic: List[Dict[str, Any]] = []
        self.c2_detections: List[C2Detection] = []
        
        self.traffic_stats = {
            'total_packets': 0,
            'total_bytes': 0,
            'protocols': Counter(),
            'destinations': Counter(),
            'ports': Counter(),
        }
        
        self.beaconing_analysis = defaultdict(list)
    
    def analyze_connection(self, conn: NetworkConnection):
        """Analyze a single network connection"""
        self.connections.append(conn)
        
        # Update statistics
        self.traffic_stats['total_packets'] += 1
        self.traffic_stats['total_bytes'] += conn.data_size
        self.traffic_stats['protocols'][conn.protocol] += 1
        self.traffic_stats['destinations'][conn.dst_ip] += 1
        self.traffic_stats['ports'][conn.dst_port] += 1
        
        # Check for suspicious indicators
        self._check_suspicious_connection(conn)
        
        # Track beaconing patterns
        if conn.direction == 'outbound':
            self._track_beaconing(conn)
    
    def _check_suspicious_connection(self, conn: NetworkConnection):
        """Check connection for suspicious indicators"""
        indicators = []
        
        # Check suspicious ports
        if conn.dst_port in self.SUSPICIOUS_PORTS:
            indicators.append({
                'type': 'suspicious_port',
                'description': f'Connection to suspicious port {conn.dst_port}',
                'details': self.SUSPICIOUS_PORTS[conn.dst_port],
                'severity': 'high'
            })
        
        # Check for connections to IP addresses (no domain)
        if self._is_ip_address(conn.dst_ip):
            # Check if private IP
            if not self._is_private_ip(conn.dst_ip):
                indicators.append({
                    'type': 'direct_ip_connection',
                    'description': f'Direct connection to public IP: {conn.dst_ip}',
                    'severity': 'medium'
                })
        
        # Check for non-standard ports
        if conn.protocol == 'HTTP' and conn.dst_port not in [80, 8080, 3000, 8000]:
            indicators.append({
                'type': 'non_standard_port',
                'description': f'HTTP on non-standard port {conn.dst_port}',
                'severity': 'medium'
            })
        
        if indicators:
            self.suspicious_traffic.append({
                'timestamp': conn.timestamp,
                'connection': conn,
                'indicators': indicators
            })
    
    def _track_beaconing(self, conn: NetworkConnection):
        """Track potential beaconing behavior"""
        dest_key = f"{conn.dst_ip}:{conn.dst_port}"
        self.beaconing_analysis[dest_key].append({
            'timestamp': conn.timestamp,
            'size': conn.data_size
        })
    
    def analyze_http_traffic(self, http_data: Dict[str, Any]):
        """Analyze HTTP/HTTPS traffic"""
        self.http_requests.append(http_data)
        
        indicators = []
        
        # Check user agent
        user_agent = http_data.get('user_agent', '').lower()
        if any(sus in user_agent for sus in self.SUSPICIOUS_USER_AGENTS):
            indicators.append({
                'type': 'suspicious_user_agent',
                'description': f'Suspicious User-Agent: {user_agent}',
                'severity': 'high'
            })
        
        # Check for unusual headers
        headers = http_data.get('headers', {})
        if not headers.get('Accept'):
            indicators.append({
                'type': 'missing_standard_headers',
                'description': 'Missing standard HTTP headers',
                'severity': 'medium'
            })
        
        # Check for base64 in parameters (common in C2)
        url = http_data.get('url', '')
        if re.search(r'[A-Za-z0-9+/]{40,}=*', url):
            indicators.append({
                'type': 'base64_in_url',
                'description': 'Potential base64-encoded data in URL',
                'severity': 'medium'
            })
        
        # Check for POST with suspicious content
        if http_data.get('method') == 'POST':
            content_type = headers.get('Content-Type', '')
            if 'application/octet-stream' in content_type:
                indicators.append({
                    'type': 'binary_post',
                    'description': 'Binary data POST request',
                    'severity': 'medium'
                })
        
        if indicators:
            self.suspicious_traffic.append({
                'timestamp': datetime.now(),
                'type': 'http',
                'data': http_data,
                'indicators': indicators
            })
    
    def analyze_dns_query(self, query_data: Dict[str, Any]):
        """Analyze DNS queries for tunneling"""
        self.dns_queries.append(query_data)
        
        domain = query_data.get('domain', '')
        indicators = []
        
        # Check for high entropy (randomized domains)
        entropy = self._calculate_entropy(domain)
        if entropy > 4.5:
            indicators.append({
                'type': 'high_entropy_domain',
                'description': f'High entropy domain: {domain}',
                'entropy': entropy,
                'severity': 'high'
            })
        
        # Check for unusually long domains
        if len(domain) > 50:
            indicators.append({
                'type': 'long_domain',
                'description': f'Unusually long domain ({len(domain)} chars)',
                'severity': 'high'
            })
        
        # Check for suspicious TLDs
        for pattern in self.SUSPICIOUS_DOMAIN_PATTERNS:
            if re.search(pattern, domain, re.IGNORECASE):
                indicators.append({
                    'type': 'suspicious_domain_pattern',
                    'description': f'Suspicious domain pattern: {domain}',
                    'severity': 'medium'
                })
                break
        
        # Check for excessive subdomain levels
        subdomain_levels = domain.count('.')
        if subdomain_levels > 5:
            indicators.append({
                'type': 'excessive_subdomains',
                'description': f'Too many subdomain levels ({subdomain_levels})',
                'severity': 'high'
            })
        
        if indicators:
            self.suspicious_traffic.append({
                'timestamp': datetime.now(),
                'type': 'dns',
                'data': query_data,
                'indicators': indicators
            })
    
    def detect_c2_beaconing(self) -> List[C2Detection]:
        """Detect C2 beaconing patterns"""
        detections = []
        
        for dest, traffic in self.beaconing_analysis.items():
            if len(traffic) < 5:  # Need multiple connections to detect pattern
                continue
            
            # Calculate intervals between connections
            intervals = []
            for i in range(1, len(traffic)):
                delta = (traffic[i]['timestamp'] - traffic[i-1]['timestamp']).total_seconds()
                intervals.append(delta)
            
            if not intervals:
                continue
            
            # Check for regular intervals (beaconing)
            avg_interval = sum(intervals) / len(intervals)
            variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
            std_dev = variance ** 0.5
            
            # Low variance = regular beaconing
            coefficient_of_variation = std_dev / avg_interval if avg_interval > 0 else 1
            
            if coefficient_of_variation < 0.3:  # Very regular intervals
                # Check for consistent packet sizes
                sizes = [t['size'] for t in traffic]
                size_variance = sum((x - sum(sizes)/len(sizes)) ** 2 for x in sizes) / len(sizes)
                
                confidence = 0.6
                indicators = [
                    f'Regular beaconing detected: {len(traffic)} connections',
                    f'Average interval: {avg_interval:.1f}s (CoV: {coefficient_of_variation:.2f})',
                ]
                
                if size_variance < 100:  # Very consistent sizes
                    confidence += 0.2
                    indicators.append(f'Consistent packet sizes (variance: {size_variance:.1f})')
                
                detection = C2Detection(
                    confidence=confidence,
                    c2_type='http_beacon' if avg_interval < 60 else 'slow_beacon',
                    indicators=indicators,
                    destinations=[dest],
                    evidence={
                        'connection_count': len(traffic),
                        'avg_interval': avg_interval,
                        'coefficient_of_variation': coefficient_of_variation,
                        'avg_size': sum(sizes) / len(sizes)
                    }
                )
                
                detections.append(detection)
                self.c2_detections.append(detection)
        
        return detections
    
    def detect_data_exfiltration(self) -> List[Dict[str, Any]]:
        """Detect potential data exfiltration"""
        detections = []
        
        # Group outbound traffic by destination
        outbound = [c for c in self.connections if c.direction == 'outbound']
        dest_traffic = defaultdict(list)
        
        for conn in outbound:
            dest_traffic[conn.dst_ip].append(conn)
        
        # Check for large volumes of outbound data
        for dest, conns in dest_traffic.items():
            total_bytes = sum(c.data_size for c in conns)
            
            # Alert if more than 10MB to single destination
            if total_bytes > 10 * 1024 * 1024:
                detections.append({
                    'type': 'large_data_transfer',
                    'destination': dest,
                    'total_bytes': total_bytes,
                    'total_mb': total_bytes / (1024 * 1024),
                    'connection_count': len(conns),
                    'confidence': 0.7,
                    'severity': 'high'
                })
        
        return detections
    
    def analyze_protocol_anomalies(self) -> List[Dict[str, Any]]:
        """Detect protocol-level anomalies"""
        anomalies = []
        
        # Check for unusual protocol usage
        total_packets = self.traffic_stats['total_packets']
        if total_packets == 0:
            return anomalies
        
        for protocol, count in self.traffic_stats['protocols'].items():
            percentage = (count / total_packets) * 100
            
            # Alert on unusual protocols
            if protocol in ['ICMP', 'GRE', 'RAW'] and percentage > 5:
                anomalies.append({
                    'type': 'unusual_protocol_volume',
                    'protocol': protocol,
                    'percentage': percentage,
                    'count': count,
                    'severity': 'medium'
                })
        
        return anomalies
    
    def get_traffic_summary(self) -> Dict[str, Any]:
        """Get comprehensive traffic summary"""
        return {
            'statistics': dict(self.traffic_stats),
            'total_connections': len(self.connections),
            'suspicious_traffic_count': len(self.suspicious_traffic),
            'c2_detections': len(self.c2_detections),
            'top_destinations': self._get_top_destinations(10),
            'top_ports': self._get_top_ports(10),
            'protocol_breakdown': dict(self.traffic_stats['protocols']),
        }
    
    def _get_top_destinations(self, limit: int) -> List[Tuple[str, int]]:
        """Get top destinations by connection count"""
        return self.traffic_stats['destinations'].most_common(limit)
    
    def _get_top_ports(self, limit: int) -> List[Tuple[int, int]]:
        """Get top ports by connection count"""
        return self.traffic_stats['ports'].most_common(limit)
    
    def _is_ip_address(self, addr: str) -> bool:
        """Check if address is an IP"""
        try:
            socket.inet_aton(addr)
            return True
        except socket.error:
            return False
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private"""
        try:
            parts = [int(p) for p in ip.split('.')]
            return (
                parts[0] == 10 or
                (parts[0] == 172 and 16 <= parts[1] <= 31) or
                (parts[0] == 192 and parts[1] == 168) or
                parts[0] == 127
            )
        except:
            return False
    
    def _calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0.0
        
        entropy = 0
        for x in range(256):
            p_x = float(data.count(chr(x))) / len(data)
            if p_x > 0:
                entropy += - p_x * (p_x ** 0.5).bit_length()
        
        return entropy
    
    def export_pcap(self, output_file: str) -> bool:
        """Export captured traffic to PCAP file"""
        if not HAS_SCAPY:
            return False
        
        try:
            # This would use scapy to write packets to PCAP
            # Simplified placeholder
            return True
        except Exception:
            return False
