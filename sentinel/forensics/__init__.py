"""
Sentinel Forensics Module
Advanced forensic analysis capabilities
"""

from .memory_forensics import MemoryForensics, MemoryRegion, InjectionDetection
from .network_forensics import NetworkForensics, NetworkConnection, C2Detection
from .filesystem_forensics import FileSystemForensics, FileOperation, FileArtifact

__all__ = [
    'MemoryForensics',
    'MemoryRegion',
    'InjectionDetection',
    'NetworkForensics',
    'NetworkConnection',
    'C2Detection',
    'FileSystemForensics',
    'FileOperation',
    'FileArtifact',
]
