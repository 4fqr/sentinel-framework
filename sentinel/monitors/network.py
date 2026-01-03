"""
Sentinel Framework - Network Monitor
Tracks network connections, DNS queries, and HTTP traffic
"""

import time
import threading
import socket
from typing import Callable, Dict, List, Optional, Set
import psutil

from sentinel.core.monitor import BehaviorEvent, EventType, EventSeverity
from sentinel.config import config
from sentinel.utils.logger import get_logger


logger = get_logger(__name__)


class NetworkMonitor:
    """Monitors network activity and connections"""
    
    def __init__(self, callback: Callable[[BehaviorEvent], None]):
        """
        Initialize network monitor
        
        Args:
            callback: Function to call with behavior events
        """
        self.callback = callback
        self.config = config.get_section('monitoring').get('network', {})
        self.is_running = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._tracked_connections: Set[tuple] = set()
    
    def start(self) -> None:
        """Start network monitoring"""
        if self.is_running:
            return
        
        logger.info("Starting network monitor")
        
        # Get initial connection snapshot
        self._tracked_connections = self._get_current_connections()
        
        self.is_running = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
    
    def stop(self) -> None:
        """Stop network monitoring"""
        if not self.is_running:
            return
        
        logger.info("Stopping network monitor")
        self.is_running = False
        
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
    
    def _monitor_loop(self) -> None:
        """Main monitoring loop"""
        poll_interval = 1.0  # Check every second
        
        while self.is_running:
            try:
                current_connections = self._get_current_connections()
                
                # Detect new connections
                new_connections = current_connections - self._tracked_connections
                for conn in new_connections:
                    self._handle_new_connection(conn)
                
                self._tracked_connections = current_connections
                
                time.sleep(poll_interval)
                
            except Exception as e:
                logger.error(f"Network monitoring error: {e}")
                time.sleep(poll_interval)
    
    def _get_current_connections(self) -> Set[tuple]:
        """Get set of current network connections"""
        connections = set()
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED':
                    # Create tuple of connection details
                    conn_tuple = (
                        conn.laddr.ip if conn.laddr else None,
                        conn.laddr.port if conn.laddr else None,
                        conn.raddr.ip if conn.raddr else None,
                        conn.raddr.port if conn.raddr else None,
                        conn.pid
                    )
                    connections.add(conn_tuple)
        except (psutil.AccessDenied, PermissionError):
            pass
        
        return connections
    
    def _handle_new_connection(self, conn_tuple: tuple) -> None:
        """Handle new network connection"""
        local_ip, local_port, remote_ip, remote_port, pid = conn_tuple
        
        if not remote_ip:
            return
        
        # Get process information
        process_name = "Unknown"
        try:
            if pid:
                process = psutil.Process(pid)
                process_name = process.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        
        # Assess connection severity
        severity = self._assess_connection_severity(remote_ip, remote_port)
        
        # Resolve hostname
        hostname = self._resolve_hostname(remote_ip)
        
        event = BehaviorEvent(
            event_type=EventType.NETWORK_CONNECTION,
            timestamp=time.time(),
            severity=severity,
            process_id=pid,
            process_name=process_name,
            description=f"Network connection to {remote_ip}:{remote_port}",
            data={
                'local_ip': local_ip,
                'local_port': local_port,
                'remote_ip': remote_ip,
                'remote_port': remote_port,
                'hostname': hostname,
                'protocol': self._identify_protocol(remote_port),
            },
            tags=['network']
        )
        
        self.callback(event)
    
    def _assess_connection_severity(self, ip: str, port: int) -> EventSeverity:
        """Assess severity of network connection"""
        # Check for private IP ranges
        if self._is_private_ip(ip):
            return EventSeverity.INFO
        
        # Common suspicious ports
        suspicious_ports = [
            4444,  # Metasploit default
            5555,  # Android Debug Bridge
            6667,  # IRC
            6666,  # IRC
            1337,  # Common backdoor port
        ]
        
        if port in suspicious_ports:
            return EventSeverity.HIGH
        
        # Remote access ports
        remote_ports = [3389, 5900, 5800]  # RDP, VNC
        if port in remote_ports:
            return EventSeverity.MEDIUM
        
        return EventSeverity.LOW
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        private_ranges = [
            '10.',
            '192.168.',
            '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.',
            '172.24.', '172.25.', '172.26.', '172.27.',
            '172.28.', '172.29.', '172.30.', '172.31.',
            '127.',
        ]
        
        return any(ip.startswith(prefix) for prefix in private_ranges)
    
    def _resolve_hostname(self, ip: str) -> Optional[str]:
        """Resolve IP to hostname"""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror):
            return None
    
    def _identify_protocol(self, port: int) -> str:
        """Identify protocol based on port"""
        common_ports = {
            80: 'HTTP',
            443: 'HTTPS',
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            110: 'POP3',
            143: 'IMAP',
            3389: 'RDP',
            5900: 'VNC',
        }
        
        return common_ports.get(port, 'Unknown')
