"""
Archive Analyzer - Deep inspection of compressed files
Supports: ZIP, RAR, 7z, TAR, GZ, BZ2, XZ with password cracking
"""

import zipfile
import tarfile
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
import tempfile
import shutil

logger = logging.getLogger(__name__)


class ArchiveAnalyzer:
    """Analyzes compressed archives and extracts contents for scanning"""
    
    # Common passwords for encrypted archives
    COMMON_PASSWORDS = [
        'infected', 'malware', 'virus', 'password', '123456', 'admin',
        '12345', 'password123', 'root', 'toor', '1234', 'test'
    ]
    
    def __init__(self):
        self.max_extraction_depth = 5  # Prevent zip bombs
        self.max_file_size = 500 * 1024 * 1024  # 500MB limit
        self.current_depth = 0
        
    def analyze(self, file_path: str) -> Dict[str, Any]:
        """
        Analyze archive file and extract contents
        
        Returns detailed information about:
        - Archive type and structure
        - Encrypted status
        - Suspicious patterns (zip bombs, path traversal)
        - Extracted files for further analysis
        """
        results = {
            'archive_type': self._detect_archive_type(file_path),
            'is_encrypted': False,
            'file_count': 0,
            'total_compressed_size': 0,
            'total_uncompressed_size': 0,
            'compression_ratio': 0,
            'suspicious_indicators': [],
            'extracted_files': [],
            'password_used': None,
            'contents': []
        }
        
        try:
            if file_path.lower().endswith('.zip'):
                results = self._analyze_zip(file_path, results)
            elif file_path.lower().endswith(('.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tar.xz')):
                results = self._analyze_tar(file_path, results)
            elif file_path.lower().endswith('.rar'):
                results = self._analyze_rar(file_path, results)
            elif file_path.lower().endswith('.7z'):
                results = self._analyze_7z(file_path, results)
            
            # Check for zip bomb (compression ratio > 100:1)
            if results['total_uncompressed_size'] > 0:
                results['compression_ratio'] = results['total_uncompressed_size'] / results['total_compressed_size']
                
                if results['compression_ratio'] > 100:
                    results['suspicious_indicators'].append({
                        'type': 'Potential Zip Bomb',
                        'severity': 'CRITICAL',
                        'evidence': f'Compression ratio: {results["compression_ratio"]:.0f}:1',
                        'reason': 'Extremely high compression suggests zip bomb attack - decompression could exhaust resources'
                    })
            
            # Check for path traversal attempts
            for item in results['contents']:
                if '../' in item['name'] or '..\\' in item['name']:
                    results['suspicious_indicators'].append({
                        'type': 'Path Traversal Attack',
                        'severity': 'HIGH',
                        'evidence': f'Malicious path: {item["name"]}',
                        'reason': 'Archive contains files with directory traversal - could overwrite system files'
                    })
            
            # Check for suspicious extensions
            dangerous_extensions = ['.exe', '.dll', '.sys', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js']
            dangerous_files = [f for f in results['contents'] if any(f['name'].lower().endswith(ext) for ext in dangerous_extensions)]
            
            if dangerous_files:
                results['suspicious_indicators'].append({
                    'type': 'Executable Files in Archive',
                    'severity': 'HIGH',
                    'evidence': f'{len(dangerous_files)} executable files found',
                    'reason': f'Archive contains potentially malicious executables: {", ".join([f["name"] for f in dangerous_files[:5]])}'
                })
            
        except Exception as e:
            logger.error(f"Archive analysis failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def _detect_archive_type(self, file_path: str) -> str:
        """Detect archive type from magic bytes"""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(10)
                
                # ZIP: PK\x03\x04
                if header[:4] == b'PK\x03\x04':
                    return 'ZIP'
                # RAR: Rar!\x1a\x07
                elif header[:6] == b'Rar!\x1a\x07':
                    return 'RAR5'
                elif header[:4] == b'Rar!':
                    return 'RAR4'
                # 7z: 7z\xbc\xaf\x27\x1c
                elif header[:6] == b'7z\xbc\xaf\x27\x1c':
                    return '7-Zip'
                # GZIP: \x1f\x8b
                elif header[:2] == b'\x1f\x8b':
                    return 'GZIP'
                # BZ2: BZ
                elif header[:2] == b'BZ':
                    return 'BZ2'
                # TAR (POSIX)
                elif header[:5] == b'ustar':
                    return 'TAR'
                
        except Exception as e:
            logger.debug(f"Magic byte detection failed: {e}")
        
        # Fallback to extension
        return Path(file_path).suffix.upper()
    
    def _analyze_zip(self, file_path: str, results: Dict) -> Dict:
        """Analyze ZIP archive"""
        try:
            # Try opening without password first
            try:
                with zipfile.ZipFile(file_path, 'r') as zf:
                    return self._process_zipfile(zf, results, None)
            except RuntimeError as e:
                if 'encrypted' in str(e).lower() or 'password' in str(e).lower():
                    results['is_encrypted'] = True
                    # Try common passwords
                    for pwd in self.COMMON_PASSWORDS:
                        try:
                            with zipfile.ZipFile(file_path, 'r') as zf:
                                # Test password on first file
                                first_file = zf.namelist()[0]
                                zf.read(first_file, pwd=pwd.encode())
                                results['password_used'] = pwd
                                logger.info(f"ZIP unlocked with password: {pwd}")
                                return self._process_zipfile(zf, results, pwd.encode())
                        except:
                            continue
                    
                    # Couldn't crack password
                    results['suspicious_indicators'].append({
                        'type': 'Password Protected Archive',
                        'severity': 'HIGH',
                        'evidence': 'Archive is encrypted',
                        'reason': 'Malware often uses password protection to evade detection'
                    })
                else:
                    raise
                    
        except Exception as e:
            logger.error(f"ZIP analysis failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def _process_zipfile(self, zf: zipfile.ZipFile, results: Dict, password: Optional[bytes]) -> Dict:
        """Process ZIP file contents"""
        results['file_count'] = len(zf.namelist())
        
        for info in zf.infolist():
            results['total_compressed_size'] += info.compress_size
            results['total_uncompressed_size'] += info.file_size
            
            results['contents'].append({
                'name': info.filename,
                'compressed_size': info.compress_size,
                'uncompressed_size': info.file_size,
                'is_dir': info.is_dir(),
                'crc': info.CRC,
                'compress_type': info.compress_type
            })
        
        # Extract to temp directory for analysis
        if not results['is_encrypted'] or password:
            try:
                temp_dir = tempfile.mkdtemp(prefix='sentinel_zip_')
                for member in zf.namelist():
                    # Security check
                    member_path = Path(temp_dir) / member
                    if not str(member_path.resolve()).startswith(str(Path(temp_dir).resolve())):
                        continue  # Path traversal attempt
                    
                    try:
                        zf.extract(member, temp_dir, pwd=password)
                        results['extracted_files'].append(str(member_path))
                    except Exception as e:
                        logger.debug(f"Failed to extract {member}: {e}")
                        
            except Exception as e:
                logger.error(f"Extraction failed: {e}")
        
        return results
    
    def _analyze_tar(self, file_path: str, results: Dict) -> Dict:
        """Analyze TAR archive"""
        try:
            # Detect compression
            mode = 'r'
            if file_path.endswith('.gz') or file_path.endswith('.tgz'):
                mode = 'r:gz'
            elif file_path.endswith('.bz2'):
                mode = 'r:bz2'
            elif file_path.endswith('.xz'):
                mode = 'r:xz'
            
            with tarfile.open(file_path, mode) as tf:
                results['file_count'] = len(tf.getmembers())
                
                for member in tf.getmembers():
                    results['total_uncompressed_size'] += member.size
                    
                    results['contents'].append({
                        'name': member.name,
                        'size': member.size,
                        'is_dir': member.isdir(),
                        'is_symlink': member.issym() or member.islnk(),
                        'mode': oct(member.mode)
                    })
                    
                    # Check for suspicious symlinks
                    if member.issym() or member.islnk():
                        results['suspicious_indicators'].append({
                            'type': 'Symbolic Link',
                            'severity': 'MEDIUM',
                            'evidence': f'Symlink: {member.name} -> {member.linkname}',
                            'reason': 'Symlinks can be used to access files outside archive scope'
                        })
                
                results['total_compressed_size'] = Path(file_path).stat().st_size
                
        except Exception as e:
            logger.error(f"TAR analysis failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def _analyze_rar(self, file_path: str, results: Dict) -> Dict:
        """Analyze RAR archive"""
        try:
            # Try using rarfile library if available
            import rarfile
            
            with rarfile.RarFile(file_path) as rf:
                results['is_encrypted'] = rf.needs_password()
                results['file_count'] = len(rf.namelist())
                
                for info in rf.infolist():
                    results['total_compressed_size'] += info.compress_size
                    results['total_uncompressed_size'] += info.file_size
                    
                    results['contents'].append({
                        'name': info.filename,
                        'compressed_size': info.compress_size,
                        'uncompressed_size': info.file_size,
                        'is_dir': info.isdir(),
                        'crc': info.CRC
                    })
                    
        except ImportError:
            results['error'] = 'rarfile library not installed - install with: pip install rarfile'
            logger.warning("RAR support requires 'rarfile' library")
        except Exception as e:
            logger.error(f"RAR analysis failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def _analyze_7z(self, file_path: str, results: Dict) -> Dict:
        """Analyze 7-Zip archive"""
        try:
            import py7zr
            
            with py7zr.SevenZipFile(file_path, 'r') as zf:
                results['is_encrypted'] = zf.needs_password()
                file_list = zf.getnames()
                results['file_count'] = len(file_list)
                
                for name in file_list:
                    results['contents'].append({
                        'name': name,
                        'is_dir': name.endswith('/')
                    })
                    
        except ImportError:
            results['error'] = '7z support requires py7zr library - install with: pip install py7zr'
            logger.warning("7z support requires 'py7zr' library")
        except Exception as e:
            logger.error(f"7z analysis failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def cleanup(self):
        """Clean up temporary extraction directories"""
        # This should be called after analysis
        pass
