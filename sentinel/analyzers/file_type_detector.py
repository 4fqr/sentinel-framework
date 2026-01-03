"""
Universal File Type Detector - Identifies all file types with magic bytes
"""

import magic
import os
from pathlib import Path
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class UniversalFileDetector:
    """Detect and categorize any file type"""
    
    FILE_CATEGORIES = {
        'executable': [
            'PE32', 'PE32+', 'ELF', 'Mach-O', 'MS-DOS executable',
            '.NET assembly', 'DLL', 'COM executable'
        ],
        'script': [
            'Python script', 'PowerShell', 'Bash script', 'shell script',
            'JavaScript', 'VBScript', 'Batch', 'Ruby script', 'Perl script'
        ],
        'document': [
            'PDF', 'Microsoft Word', 'Microsoft Excel', 'Microsoft PowerPoint',
            'Rich Text Format', 'OpenDocument', 'HTML', 'XML'
        ],
        'archive': [
            'Zip archive', 'RAR archive', '7-zip archive', 'gzip compressed',
            'bzip2 compressed', 'tar archive', 'ISO 9660', 'XZ compressed'
        ],
        'image': [
            'JPEG', 'PNG', 'GIF', 'BMP', 'TIFF', 'WebP', 'ICO', 'SVG'
        ],
        'audio': [
            'MP3', 'WAV', 'FLAC', 'OGG', 'AAC', 'WMA', 'M4A'
        ],
        'video': [
            'MP4', 'AVI', 'MKV', 'MOV', 'WMV', 'FLV', 'MPEG'
        ],
        'database': [
            'SQLite', 'MySQL', 'PostgreSQL', 'Microsoft Access'
        ],
        'android': [
            'APK', 'DEX', 'Android'
        ],
        'java': [
            'Java archive', 'JAR', 'Java class'
        ],
        'email': [
            'RFC 822 mail', 'MIME entity', 'Outlook Message'
        ]
    }
    
    EXTENSION_MAP = {
        # Scripts
        '.ps1': 'PowerShell Script',
        '.psm1': 'PowerShell Module',
        '.vbs': 'VBScript',
        '.vbe': 'Encrypted VBScript',
        '.js': 'JavaScript',
        '.jse': 'Encrypted JavaScript',
        '.bat': 'Batch Script',
        '.cmd': 'Command Script',
        '.sh': 'Shell Script',
        '.py': 'Python Script',
        '.rb': 'Ruby Script',
        '.pl': 'Perl Script',
        '.php': 'PHP Script',
        
        # Documents
        '.doc': 'Microsoft Word',
        '.docx': 'Microsoft Word (OOXML)',
        '.xls': 'Microsoft Excel',
        '.xlsx': 'Microsoft Excel (OOXML)',
        '.ppt': 'Microsoft PowerPoint',
        '.pptx': 'Microsoft PowerPoint (OOXML)',
        '.pdf': 'PDF Document',
        '.rtf': 'Rich Text Format',
        '.odt': 'OpenDocument Text',
        
        # Archives
        '.zip': 'ZIP Archive',
        '.rar': 'RAR Archive',
        '.7z': '7-Zip Archive',
        '.tar': 'TAR Archive',
        '.gz': 'GZIP Archive',
        '.bz2': 'BZIP2 Archive',
        '.xz': 'XZ Archive',
        '.iso': 'ISO Image',
        
        # Executables
        '.exe': 'Windows Executable',
        '.dll': 'Dynamic Link Library',
        '.sys': 'System Driver',
        '.scr': 'Screen Saver',
        '.cpl': 'Control Panel Item',
        
        # Android
        '.apk': 'Android Package',
        '.dex': 'Dalvik Executable',
        
        # Java
        '.jar': 'Java Archive',
        '.class': 'Java Class',
        
        # Email
        '.eml': 'Email Message',
        '.msg': 'Outlook Message',
    }
    
    def detect(self, file_path: str) -> Dict[str, Any]:
        """
        Detect file type using multiple methods
        
        Args:
            file_path: Path to file
            
        Returns:
            Detailed file type information
        """
        try:
            path = Path(file_path)
            extension = path.suffix.lower()
            
            # Get MIME type
            mime_type = None
            try:
                mime_type = magic.from_file(file_path, mime=True)
            except:
                pass
            
            # Get file description
            file_type = None
            try:
                file_type = magic.from_file(file_path)
            except:
                pass
            
            # Fallback to extension
            if not file_type:
                file_type = self.EXTENSION_MAP.get(extension, 'Unknown')
            
            # Categorize
            category = self._categorize(file_type, extension)
            
            # Read magic bytes
            magic_bytes = None
            try:
                with open(file_path, 'rb') as f:
                    magic_bytes = f.read(16).hex()
            except:
                pass
            
            return {
                'file_type': file_type,
                'mime_type': mime_type,
                'extension': extension,
                'category': category,
                'magic_bytes': magic_bytes,
                'size': os.path.getsize(file_path),
                'is_dangerous': self._is_dangerous_type(category, extension)
            }
            
        except Exception as e:
            logger.error(f"File type detection failed: {e}")
            return {
                'file_type': 'Unknown',
                'error': str(e)
            }
    
    def _categorize(self, file_type: str, extension: str) -> str:
        """Categorize file based on type description"""
        file_type_lower = file_type.lower()
        
        for category, keywords in self.FILE_CATEGORIES.items():
            for keyword in keywords:
                if keyword.lower() in file_type_lower:
                    return category
        
        # Check extension as fallback
        ext_type = self.EXTENSION_MAP.get(extension, '')
        for category, keywords in self.FILE_CATEGORIES.items():
            for keyword in keywords:
                if keyword.lower() in ext_type.lower():
                    return category
        
        return 'unknown'
    
    def _is_dangerous_type(self, category: str, extension: str) -> bool:
        """Check if file type is potentially dangerous"""
        dangerous_categories = ['executable', 'script', 'android']
        dangerous_extensions = [
            '.exe', '.dll', '.sys', '.scr', '.bat', '.cmd', '.ps1', 
            '.vbs', '.js', '.hta', '.wsf', '.apk', '.dex', '.jar'
        ]
        
        return (category in dangerous_categories or 
                extension.lower() in dangerous_extensions)
    
    def get_analyzer_for_type(self, category: str) -> Optional[str]:
        """Get appropriate analyzer module for file category"""
        analyzer_map = {
            'executable': 'deep_pe_analyzer',
            'script': 'script_analyzer',
            'document': 'document_analyzer',
            'archive': 'archive_analyzer',
            'android': 'apk_analyzer',
            'java': 'jar_analyzer',
        }
        
        return analyzer_map.get(category)
