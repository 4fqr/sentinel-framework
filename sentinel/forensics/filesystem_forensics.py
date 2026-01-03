"""
Sentinel Framework - File System Forensics
Timeline analysis, ADS detection, and comprehensive file operations tracking
"""

import os
import hashlib
import json
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
import stat


@dataclass
class FileOperation:
    """File system operation record"""
    timestamp: datetime
    operation_type: str  # created, modified, deleted, renamed, accessed
    file_path: str
    file_size: int
    file_hash: Optional[str] = None
    previous_path: Optional[str] = None  # For renames
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FileArtifact:
    """File artifact with analysis"""
    path: str
    size: int
    created: datetime
    modified: datetime
    accessed: datetime
    hash_md5: Optional[str] = None
    hash_sha256: Optional[str] = None
    entropy: float = 0.0
    is_suspicious: bool = False
    suspicion_reasons: List[str] = field(default_factory=list)
    alternate_data_streams: List[str] = field(default_factory=list)


class FileSystemForensics:
    """
    Advanced file system forensics and timeline analysis
    """
    
    # Suspicious file locations (Windows-focused)
    SUSPICIOUS_LOCATIONS = [
        r'C:\Users\Public',
        r'C:\ProgramData',
        r'C:\Windows\Temp',
        r'C:\Windows\System32\Tasks',
        r'%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup',
        r'%LOCALAPPDATA%\Temp',
        r'%TEMP%',
        r'C:\$Recycle.Bin',
    ]
    
    # Suspicious extensions
    SUSPICIOUS_EXTENSIONS = [
        '.exe', '.dll', '.sys', '.scr', '.bat', '.cmd', '.vbs', '.ps1',
        '.jar', '.js', '.hta', '.wsf', '.reg', '.msi', '.com', '.pif'
    ]
    
    # Common ransomware extensions
    RANSOMWARE_EXTENSIONS = [
        '.encrypted', '.locked', '.crypted', '.crypt', '.cerber',
        '.locky', '.zepto', '.osiris', '.thor', '.aesir',
        '.wallet', '.wcry', '.wncry', '.onion', '.cry'
    ]
    
    # Suspicious filenames
    SUSPICIOUS_NAMES = [
        'mimikatz', 'procdump', 'psexec', 'netcat', 'nc.exe',
        'ncat', 'winexe', 'pwdump', 'gsecdump', 'wce',
        'keylog', 'stealer', 'backdoor', 'payload', 'inject'
    ]
    
    def __init__(self):
        """Initialize file system forensics engine"""
        self.operations: List[FileOperation] = []
        self.artifacts: List[FileArtifact] = []
        self.timeline: List[Tuple[datetime, str, str]] = []
        
        self.stats = {
            'total_files_created': 0,
            'total_files_modified': 0,
            'total_files_deleted': 0,
            'total_files_renamed': 0,
            'suspicious_files': 0,
            'total_bytes_written': 0,
        }
        
        self.location_activity = defaultdict(int)
        self.extension_activity = defaultdict(int)
    
    def record_operation(self, operation: FileOperation):
        """Record a file system operation"""
        self.operations.append(operation)
        
        # Update timeline
        self.timeline.append((
            operation.timestamp,
            operation.operation_type,
            operation.file_path
        ))
        
        # Update statistics
        if operation.operation_type == 'created':
            self.stats['total_files_created'] += 1
            self.stats['total_bytes_written'] += operation.file_size
        elif operation.operation_type == 'modified':
            self.stats['total_files_modified'] += 1
        elif operation.operation_type == 'deleted':
            self.stats['total_files_deleted'] += 1
        elif operation.operation_type == 'renamed':
            self.stats['total_files_renamed'] += 1
        
        # Track activity by location
        directory = str(Path(operation.file_path).parent)
        self.location_activity[directory] += 1
        
        # Track activity by extension
        extension = Path(operation.file_path).suffix.lower()
        if extension:
            self.extension_activity[extension] += 1
    
    def analyze_file(self, file_path: str) -> FileArtifact:
        """Analyze a file for suspicious characteristics"""
        path = Path(file_path)
        
        if not path.exists():
            return None
        
        try:
            stat_info = path.stat()
            
            artifact = FileArtifact(
                path=str(path),
                size=stat_info.st_size,
                created=datetime.fromtimestamp(stat_info.st_ctime),
                modified=datetime.fromtimestamp(stat_info.st_mtime),
                accessed=datetime.fromtimestamp(stat_info.st_atime)
            )
            
            # Calculate hashes
            if stat_info.st_size < 100 * 1024 * 1024:  # Only hash files < 100MB
                artifact.hash_md5 = self._calculate_md5(file_path)
                artifact.hash_sha256 = self._calculate_sha256(file_path)
            
            # Calculate entropy
            artifact.entropy = self._calculate_file_entropy(file_path)
            
            # Check for alternate data streams (Windows)
            if os.name == 'nt':
                artifact.alternate_data_streams = self._find_ads(file_path)
            
            # Analyze for suspicious indicators
            artifact.is_suspicious, artifact.suspicion_reasons = self._check_suspicious(artifact)
            
            self.artifacts.append(artifact)
            
            if artifact.is_suspicious:
                self.stats['suspicious_files'] += 1
            
            return artifact
            
        except Exception as e:
            return None
    
    def _check_suspicious(self, artifact: FileArtifact) -> Tuple[bool, List[str]]:
        """Check if file is suspicious"""
        reasons = []
        path = Path(artifact.path)
        
        # Check location
        path_str = str(path).lower()
        for suspicious_loc in self.SUSPICIOUS_LOCATIONS:
            if suspicious_loc.lower() in path_str:
                reasons.append(f'Located in suspicious directory: {suspicious_loc}')
        
        # Check extension
        extension = path.suffix.lower()
        if extension in self.SUSPICIOUS_EXTENSIONS:
            reasons.append(f'Suspicious file extension: {extension}')
        
        if extension in self.RANSOMWARE_EXTENSIONS:
            reasons.append(f'Ransomware-associated extension: {extension}')
        
        # Check filename
        filename = path.name.lower()
        for suspicious_name in self.SUSPICIOUS_NAMES:
            if suspicious_name in filename:
                reasons.append(f'Suspicious filename pattern: {suspicious_name}')
        
        # Check for hidden attribute
        if os.name == 'nt':
            try:
                attrs = os.stat(artifact.path).st_file_attributes
                if attrs & stat.FILE_ATTRIBUTE_HIDDEN:
                    reasons.append('File has hidden attribute')
            except:
                pass
        
        # Check entropy (high entropy = likely packed/encrypted)
        if artifact.entropy > 7.5:
            reasons.append(f'Very high entropy ({artifact.entropy:.2f}) - possibly packed/encrypted')
        
        # Check for alternate data streams
        if artifact.alternate_data_streams:
            reasons.append(f'Contains {len(artifact.alternate_data_streams)} alternate data stream(s)')
        
        # Check for suspicious timestamps
        if artifact.created > artifact.modified:
            reasons.append('Created timestamp is newer than modified (timestamp manipulation)')
        
        # Check for double extensions
        if path.name.count('.') > 1:
            # Common trick: file.pdf.exe
            parts = path.name.split('.')
            if len(parts) > 2 and parts[-2] in ['pdf', 'doc', 'xls', 'jpg', 'png']:
                reasons.append('Double extension detected (possible masquerading)')
        
        # Check for very long filenames (common in ransomware)
        if len(path.name) > 100:
            reasons.append(f'Unusually long filename ({len(path.name)} characters)')
        
        # Small executable files (common in droppers)
        if extension == '.exe' and artifact.size < 10 * 1024:
            reasons.append(f'Very small executable ({artifact.size} bytes) - possible dropper')
        
        return len(reasons) > 0, reasons
    
    def _find_ads(self, file_path: str) -> List[str]:
        """Find alternate data streams (Windows NTFS)"""
        streams = []
        
        if os.name != 'nt':
            return streams
        
        try:
            # Use Windows-specific APIs to find ADS
            # This is a placeholder - real implementation would use ctypes/win32api
            import subprocess
            result = subprocess.run(
                ['powershell', '-Command', f'Get-Item -Path "{file_path}" -Stream *'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines[3:]:  # Skip headers
                    if line.strip():
                        parts = line.split()
                        if parts and parts[0] != ':$DATA':
                            streams.append(parts[0])
        except:
            pass
        
        return streams
    
    def analyze_timeline(self) -> Dict[str, Any]:
        """Analyze the timeline for patterns"""
        if not self.timeline:
            return {'error': 'No timeline data'}
        
        # Sort timeline by timestamp
        sorted_timeline = sorted(self.timeline, key=lambda x: x[0])
        
        # Detect rapid file operations (potential ransomware)
        rapid_operations = self._detect_rapid_operations(sorted_timeline)
        
        # Detect mass file modifications
        mass_modifications = self._detect_mass_modifications()
        
        # Detect suspicious patterns
        patterns = self._detect_patterns()
        
        return {
            'total_operations': len(self.timeline),
            'rapid_operations': rapid_operations,
            'mass_modifications': mass_modifications,
            'patterns': patterns,
            'timeline_summary': self._generate_timeline_summary(sorted_timeline),
            'hotspot_directories': self._get_hotspot_directories(10),
        }
    
    def _detect_rapid_operations(self, timeline: List[Tuple[datetime, str, str]]) -> List[Dict[str, Any]]:
        """Detect periods of rapid file operations"""
        rapid_periods = []
        
        # Window of 1 second
        window_size = 1.0
        window_threshold = 10  # 10+ operations in 1 second
        
        i = 0
        while i < len(timeline):
            window_start = timeline[i][0]
            window_ops = []
            
            # Collect operations in window
            j = i
            while j < len(timeline):
                time_diff = (timeline[j][0] - window_start).total_seconds()
                if time_diff <= window_size:
                    window_ops.append(timeline[j])
                    j += 1
                else:
                    break
            
            # Check if exceeds threshold
            if len(window_ops) >= window_threshold:
                rapid_periods.append({
                    'start_time': window_start,
                    'operation_count': len(window_ops),
                    'duration': window_size,
                    'operations_per_second': len(window_ops) / window_size,
                    'files': [op[2] for op in window_ops[:5]]  # Sample of files
                })
                i = j
            else:
                i += 1
        
        return rapid_periods
    
    def _detect_mass_modifications(self) -> Dict[str, Any]:
        """Detect mass file modifications (ransomware indicator)"""
        # Count modifications by extension
        modified_by_ext = defaultdict(int)
        
        for op in self.operations:
            if op.operation_type == 'modified':
                ext = Path(op.file_path).suffix.lower()
                modified_by_ext[ext] += 1
        
        # Alert if many files of same type modified
        alerts = []
        for ext, count in modified_by_ext.items():
            if count > 20:  # More than 20 files of same type
                alerts.append({
                    'extension': ext,
                    'count': count,
                    'severity': 'high' if count > 50 else 'medium'
                })
        
        return {
            'alerts': alerts,
            'total_modifications': self.stats['total_files_modified'],
            'unique_extensions_modified': len(modified_by_ext)
        }
    
    def _detect_patterns(self) -> List[Dict[str, Any]]:
        """Detect suspicious patterns"""
        patterns = []
        
        # Pattern 1: Many files renamed with same extension
        renamed_extensions = defaultdict(int)
        for op in self.operations:
            if op.operation_type == 'renamed':
                new_ext = Path(op.file_path).suffix.lower()
                renamed_extensions[new_ext] += 1
        
        for ext, count in renamed_extensions.items():
            if count > 10:
                patterns.append({
                    'type': 'mass_rename',
                    'extension': ext,
                    'count': count,
                    'description': f'{count} files renamed with {ext} extension',
                    'severity': 'high'
                })
        
        # Pattern 2: Files created then immediately deleted
        created_files = {op.file_path for op in self.operations if op.operation_type == 'created'}
        deleted_files = {op.file_path for op in self.operations if op.operation_type == 'deleted'}
        temp_files = created_files & deleted_files
        
        if len(temp_files) > 5:
            patterns.append({
                'type': 'temporary_files',
                'count': len(temp_files),
                'description': f'{len(temp_files)} files created and deleted',
                'severity': 'low'
            })
        
        # Pattern 3: Concentrated activity in single directory
        for directory, count in self.location_activity.items():
            if count > 50:
                patterns.append({
                    'type': 'hotspot_directory',
                    'directory': directory,
                    'operation_count': count,
                    'description': f'High activity in directory: {count} operations',
                    'severity': 'medium'
                })
        
        return patterns
    
    def _generate_timeline_summary(self, timeline: List[Tuple[datetime, str, str]]) -> Dict[str, Any]:
        """Generate timeline summary"""
        if not timeline:
            return {}
        
        start_time = timeline[0][0]
        end_time = timeline[-1][0]
        duration = (end_time - start_time).total_seconds()
        
        # Count operations by type
        op_counts = defaultdict(int)
        for _, op_type, _ in timeline:
            op_counts[op_type] += 1
        
        return {
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'duration_seconds': duration,
            'total_operations': len(timeline),
            'operations_per_second': len(timeline) / duration if duration > 0 else 0,
            'operations_by_type': dict(op_counts)
        }
    
    def _get_hotspot_directories(self, limit: int) -> List[Tuple[str, int]]:
        """Get directories with most activity"""
        sorted_dirs = sorted(
            self.location_activity.items(),
            key=lambda x: x[1],
            reverse=True
        )
        return sorted_dirs[:limit]
    
    def _calculate_md5(self, file_path: str) -> str:
        """Calculate MD5 hash"""
        try:
            hash_md5 = hashlib.md5()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except:
            return None
    
    def _calculate_sha256(self, file_path: str) -> str:
        """Calculate SHA256 hash"""
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except:
            return None
    
    def _calculate_file_entropy(self, file_path: str) -> float:
        """Calculate file entropy"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(min(10240, os.path.getsize(file_path)))  # First 10KB
            
            if not data:
                return 0.0
            
            # Calculate Shannon entropy
            import math
            entropy = 0
            for x in range(256):
                p_x = float(data.count(bytes([x]))) / len(data)
                if p_x > 0:
                    entropy += - p_x * math.log2(p_x)
            
            return entropy
        except:
            return 0.0
    
    def export_timeline(self, output_file: str) -> bool:
        """Export timeline to JSON"""
        try:
            timeline_data = {
                'statistics': self.stats,
                'timeline': [
                    {
                        'timestamp': ts.isoformat(),
                        'operation': op_type,
                        'file': file_path
                    }
                    for ts, op_type, file_path in sorted(self.timeline, key=lambda x: x[0])
                ],
                'suspicious_files': [
                    {
                        'path': artifact.path,
                        'reasons': artifact.suspicion_reasons,
                        'entropy': artifact.entropy,
                        'size': artifact.size
                    }
                    for artifact in self.artifacts if artifact.is_suspicious
                ]
            }
            
            with open(output_file, 'w') as f:
                json.dump(timeline_data, f, indent=2)
            
            return True
        except Exception:
            return False
    
    def get_summary(self) -> Dict[str, Any]:
        """Get comprehensive summary"""
        return {
            'statistics': self.stats,
            'suspicious_file_count': self.stats['suspicious_files'],
            'total_operations': len(self.operations),
            'top_active_directories': self._get_hotspot_directories(5),
            'top_extensions': sorted(
                self.extension_activity.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]
        }
