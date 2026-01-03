"""
Sentinel Framework - Utility Functions
Common helper functions used throughout the framework
"""

import hashlib
import json
import time
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime
import magic


def calculate_hash(file_path: str, algorithm: str = 'sha256') -> str:
    """
    Calculate file hash
    
    Args:
        file_path: Path to file
        algorithm: Hash algorithm (md5, sha1, sha256)
    
    Returns:
        Hex digest of file hash
    """
    hash_func = getattr(hashlib, algorithm)()
    
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except Exception as e:
        raise IOError(f"Failed to calculate hash: {e}")


def get_file_hashes(file_path: str) -> Dict[str, str]:
    """
    Calculate multiple hashes for a file
    
    Args:
        file_path: Path to file
    
    Returns:
        Dictionary with md5, sha1, and sha256 hashes
    """
    return {
        'md5': calculate_hash(file_path, 'md5'),
        'sha1': calculate_hash(file_path, 'sha1'),
        'sha256': calculate_hash(file_path, 'sha256'),
    }


def get_file_type(file_path: str) -> str:
    """
    Detect file type using magic bytes
    
    Args:
        file_path: Path to file
    
    Returns:
        File type description
    """
    try:
        return magic.from_file(file_path)
    except Exception:
        # Fallback to extension-based detection
        ext = Path(file_path).suffix.lower()
        type_map = {
            '.exe': 'Windows Executable',
            '.dll': 'Windows Dynamic Link Library',
            '.bat': 'Windows Batch File',
            '.ps1': 'PowerShell Script',
            '.vbs': 'VBScript',
            '.js': 'JavaScript',
            '.jar': 'Java Archive',
            '.apk': 'Android Package',
        }
        return type_map.get(ext, 'Unknown')


def format_bytes(size: int) -> str:
    """
    Format byte size to human-readable string
    
    Args:
        size: Size in bytes
    
    Returns:
        Formatted string (e.g., "1.5 MB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"


def format_timestamp(timestamp: Optional[float] = None) -> str:
    """
    Format timestamp to ISO 8601 string
    
    Args:
        timestamp: Unix timestamp (uses current time if None)
    
    Returns:
        ISO 8601 formatted string
    """
    if timestamp is None:
        timestamp = time.time()
    
    dt = datetime.fromtimestamp(timestamp)
    return dt.isoformat()


def ensure_directory(path: str) -> Path:
    """
    Ensure directory exists, create if necessary
    
    Args:
        path: Directory path
    
    Returns:
        Path object
    """
    directory = Path(path)
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def safe_json_dumps(data: Any, indent: int = 2) -> str:
    """
    Safely serialize data to JSON, handling non-serializable objects
    
    Args:
        data: Data to serialize
        indent: JSON indentation
    
    Returns:
        JSON string
    """
    def json_serializer(obj: Any) -> Any:
        """Custom JSON serializer for non-standard types"""
        if isinstance(obj, (datetime,)):
            return obj.isoformat()
        elif isinstance(obj, bytes):
            return obj.hex()
        elif isinstance(obj, Path):
            return str(obj)
        elif hasattr(obj, '__dict__'):
            return obj.__dict__
        return str(obj)
    
    return json.dumps(data, indent=indent, default=json_serializer)


def truncate_string(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """
    Truncate string to maximum length
    
    Args:
        text: String to truncate
        max_length: Maximum length
        suffix: Suffix to append if truncated
    
    Returns:
        Truncated string
    """
    if len(text) <= max_length:
        return text
    return text[:max_length - len(suffix)] + suffix


def extract_strings(data: bytes, min_length: int = 4) -> List[str]:
    """
    Extract ASCII strings from binary data
    
    Args:
        data: Binary data
        min_length: Minimum string length
    
    Returns:
        List of extracted strings
    """
    import re
    
    # Extract ASCII strings
    ascii_pattern = rb'[ -~]{%d,}' % min_length
    strings = re.findall(ascii_pattern, data)
    
    # Extract Unicode strings
    unicode_pattern = rb'(?:[ -~]\x00){%d,}' % min_length
    unicode_strings = re.findall(unicode_pattern, data)
    
    result = [s.decode('ascii', errors='ignore') for s in strings]
    result.extend([s.decode('utf-16le', errors='ignore') for s in unicode_strings])
    
    return result


def is_suspicious_string(string: str) -> bool:
    """
    Check if string contains suspicious indicators
    
    Args:
        string: String to check
    
    Returns:
        True if string appears suspicious
    """
    suspicious_patterns = [
        'cmd.exe', 'powershell', 'rundll32',
        'http://', 'https://', 'ftp://',
        'HKEY_', 'HKLM', 'HKCU',
        'DELETE', 'ENCRYPT', 'RANSOM',
        'kernel32', 'ntdll', 'advapi32',
        'CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory',
    ]
    
    string_lower = string.lower()
    return any(pattern.lower() in string_lower for pattern in suspicious_patterns)


class Timer:
    """Context manager for timing code execution"""
    
    def __init__(self, name: str = "Operation"):
        self.name = name
        self.start_time: Optional[float] = None
        self.elapsed: Optional[float] = None
    
    def __enter__(self) -> 'Timer':
        self.start_time = time.time()
        return self
    
    def __exit__(self, *args: Any) -> None:
        self.elapsed = time.time() - self.start_time
    
    def __str__(self) -> str:
        if self.elapsed is not None:
            return f"{self.name}: {self.elapsed:.2f}s"
        return f"{self.name}: Not completed"
