"""
Sentinel Framework - Ransomware Detector
Identifies ransomware behavior patterns
"""

import re
from typing import List, Dict, Any, Optional
from collections import defaultdict

from sentinel.core.events import BehaviorEvent, EventType, EventSeverity
from sentinel.utils.logger import get_logger


logger = get_logger(__name__)


class RansomwareDetector:
    """Detects ransomware behavior patterns"""
    
    def __init__(self):
        """Initialize ransomware detector"""
        self.encryption_extensions = [
            '.encrypted', '.locked', '.crypto', '.crypt', '.cerber',
            '.locky', '.zepto', '.osiris', '.dharma', '.wallet',
            '.wcry', '.wncry', '.wncryt', '.cryptolocker'
        ]
        
        self.ransom_keywords = [
            'ransom', 'decrypt', 'bitcoin', 'payment', 'your files',
            'encrypted', 'restore', 'unlock', 'recover your'
        ]
    
    def detect(self, events: List[BehaviorEvent], analysis_result: Any) -> List[Dict[str, Any]]:
        """
        Detect ransomware patterns
        
        Args:
            events: List of behavioral events
            analysis_result: Complete analysis result
        
        Returns:
            List of detection results
        """
        detections = []
        
        # Check for rapid file encryption
        encryption_detection = self._detect_file_encryption(events)
        if encryption_detection:
            detections.append(encryption_detection)
        
        # Check for ransom note creation
        ransom_note_detection = self._detect_ransom_notes(events)
        if ransom_note_detection:
            detections.append(ransom_note_detection)
        
        # Check for backup deletion
        backup_deletion = self._detect_backup_deletion(events)
        if backup_deletion:
            detections.append(backup_deletion)
        
        # Check for shadow copy deletion
        shadow_copy_deletion = self._detect_shadow_copy_deletion(events)
        if shadow_copy_deletion:
            detections.append(shadow_copy_deletion)
        
        return detections
    
    def _detect_file_encryption(self, events: List[BehaviorEvent]) -> Optional[Dict[str, Any]]:
        """Detect rapid file modifications indicative of encryption"""
        file_modified_events = [
            e for e in events
            if e.event_type == EventType.FILE_MODIFIED
        ]
        
        if len(file_modified_events) < 10:
            return None
        
        # Check for suspicious extensions
        renamed_events = [
            e for e in events
            if e.event_type == EventType.FILE_RENAMED
        ]
        
        suspicious_renames = 0
        for event in renamed_events:
            dest = event.data.get('destination', '')
            if any(ext in dest.lower() for ext in self.encryption_extensions):
                suspicious_renames += 1
        
        # Calculate modification rate (files per second)
        if file_modified_events:
            time_span = file_modified_events[-1].timestamp - file_modified_events[0].timestamp
            if time_span > 0:
                modification_rate = len(file_modified_events) / time_span
            else:
                modification_rate = len(file_modified_events)
        else:
            modification_rate = 0
        
        # High modification rate + suspicious renames = likely ransomware
        if modification_rate > 5 or suspicious_renames >= 3:
            confidence = min(90, int(modification_rate * 10 + suspicious_renames * 15))
            
            return {
                'threat_type': 'Ransomware',
                'technique': 'File Encryption',
                'description': f'Detected rapid file modifications ({len(file_modified_events)} files) and suspicious renames',
                'confidence': confidence,
                'severity': 'critical',
                'indicators': {
                    'files_modified': len(file_modified_events),
                    'suspicious_renames': suspicious_renames,
                    'modification_rate': f'{modification_rate:.2f} files/sec'
                }
            }
        
        return None
    
    def _detect_ransom_notes(self, events: List[BehaviorEvent]) -> Optional[Dict[str, Any]]:
        """Detect creation of ransom notes"""
        file_created_events = [
            e for e in events
            if e.event_type == EventType.FILE_CREATED
        ]
        
        ransom_note_files = []
        ransom_note_patterns = [
            r'readme.*\.txt',
            r'decrypt.*\.txt',
            r'how.*to.*decrypt',
            r'restore.*files',
            r'read.*me.*\.html',
            r'.*ransom.*',
        ]
        
        for event in file_created_events:
            filename = event.data.get('file_name', '').lower()
            
            for pattern in ransom_note_patterns:
                if re.match(pattern, filename):
                    ransom_note_files.append(event.data.get('path'))
                    break
        
        if ransom_note_files:
            return {
                'threat_type': 'Ransomware',
                'technique': 'Ransom Note Creation',
                'description': f'Detected creation of {len(ransom_note_files)} potential ransom note(s)',
                'confidence': 85,
                'severity': 'critical',
                'indicators': {
                    'ransom_notes': ransom_note_files
                }
            }
        
        return None
    
    def _detect_backup_deletion(self, events: List[BehaviorEvent]) -> Optional[Dict[str, Any]]:
        """Detect deletion of backup files"""
        deleted_events = [
            e for e in events
            if e.event_type == EventType.FILE_DELETED
        ]
        
        backup_patterns = ['.bak', '.backup', '.bkf', '.bk']
        backup_deletions = []
        
        for event in deleted_events:
            path = event.data.get('path', '').lower()
            if any(pattern in path for pattern in backup_patterns):
                backup_deletions.append(path)
        
        if len(backup_deletions) >= 2:
            return {
                'threat_type': 'Ransomware',
                'technique': 'Backup Deletion',
                'description': f'Detected deletion of {len(backup_deletions)} backup files',
                'confidence': 75,
                'severity': 'high',
                'indicators': {
                    'deleted_backups': backup_deletions
                }
            }
        
        return None
    
    def _detect_shadow_copy_deletion(self, events: List[BehaviorEvent]) -> Optional[Dict[str, Any]]:
        """Detect Windows shadow copy deletion"""
        process_events = [
            e for e in events
            if e.event_type == EventType.PROCESS_CREATED
        ]
        
        for event in process_events:
            cmdline = event.data.get('cmdline', '').lower()
            
            # Check for vssadmin or wmic commands
            shadow_deletion_commands = [
                'vssadmin delete shadows',
                'wmic shadowcopy delete',
                'vssadmin.exe delete shadows'
            ]
            
            for cmd in shadow_deletion_commands:
                if cmd in cmdline:
                    return {
                        'threat_type': 'Ransomware',
                        'technique': 'Shadow Copy Deletion',
                        'description': 'Detected attempt to delete Windows shadow copies',
                        'confidence': 90,
                        'severity': 'critical',
                        'indicators': {
                            'command': cmdline
                        }
                    }
        
        return None


from typing import Optional
