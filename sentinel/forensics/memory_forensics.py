"""
Sentinel Framework - Memory Forensics Engine
Advanced memory analysis, injection detection, and shellcode scanning
"""

import psutil
import struct
import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False


@dataclass
class MemoryRegion:
    """Memory region information"""
    base_address: int
    size: int
    protection: str
    type: str
    is_executable: bool
    is_writable: bool
    content: Optional[bytes] = None


@dataclass
class InjectionDetection:
    """Code injection detection result"""
    process_id: int
    process_name: str
    injection_type: str
    confidence: float
    evidence: List[str]
    memory_region: Optional[MemoryRegion] = None


class MemoryForensics:
    """
    Advanced memory forensics and analysis engine
    Detects code injection, shellcode, and malicious memory patterns
    """
    
    # Known shellcode patterns (simplified for demonstration)
    SHELLCODE_PATTERNS = [
        rb'\x55\x8b\xec',  # push ebp; mov ebp, esp
        rb'\x89\xe5',  # mov ebp, esp
        rb'\xeb\x00',  # jmp $+2 (common in polymorphic code)
        rb'\x90{10,}',  # NOP sleds
        rb'\x31\xc0',  # xor eax, eax
        rb'\x31\xdb',  # xor ebx, ebx
        rb'\x31\xc9',  # xor ecx, ecx
        rb'\x31\xd2',  # xor edx, edx
        rb'\x64\xa1\x30\x00\x00\x00',  # mov eax, fs:[0x30] (PEB access)
    ]
    
    # Suspicious API patterns in memory
    SUSPICIOUS_APIS = [
        'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect', 'VirtualProtectEx',
        'WriteProcessMemory', 'CreateRemoteThread', 'NtCreateThreadEx',
        'QueueUserAPC', 'SetThreadContext', 'ResumeThread',
        'LoadLibrary', 'GetProcAddress', 'CreateProcess',
        'WinExec', 'ShellExecute', 'NtUnmapViewOfSection'
    ]
    
    # Memory protection flags
    PROTECTION_FLAGS = {
        0x10: 'PAGE_EXECUTE',
        0x20: 'PAGE_EXECUTE_READ',
        0x40: 'PAGE_EXECUTE_READWRITE',
        0x80: 'PAGE_EXECUTE_WRITECOPY',
        0x01: 'PAGE_NOACCESS',
        0x02: 'PAGE_READONLY',
        0x04: 'PAGE_READWRITE',
        0x08: 'PAGE_WRITECOPY',
    }
    
    def __init__(self):
        """Initialize memory forensics engine"""
        self.detections: List[InjectionDetection] = []
    
    def analyze_process_memory(self, pid: int) -> Dict[str, Any]:
        """
        Comprehensive memory analysis for a process
        
        Args:
            pid: Process ID to analyze
        
        Returns:
            Analysis results including injection detections, suspicious regions, etc.
        """
        try:
            process = psutil.Process(pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            return {
                'success': False,
                'error': str(e),
                'pid': pid
            }
        
        results = {
            'success': True,
            'pid': pid,
            'process_name': process.name(),
            'executable_path': process.exe() if hasattr(process, 'exe') else None,
            'memory_info': self._get_memory_info(process),
            'suspicious_regions': [],
            'injection_detections': [],
            'loaded_modules': [],
            'suspicious_modules': [],
            'thread_analysis': []
        }
        
        # Analyze memory regions for suspicious patterns
        results['suspicious_regions'] = self._find_suspicious_regions(process)
        
        # Check for code injection indicators
        results['injection_detections'] = self._detect_code_injection(process)
        
        # Analyze loaded modules
        results['loaded_modules'], results['suspicious_modules'] = self._analyze_loaded_modules(process)
        
        # Thread analysis
        results['thread_analysis'] = self._analyze_threads(process)
        
        return results
    
    def _get_memory_info(self, process: psutil.Process) -> Dict[str, Any]:
        """Get basic memory information"""
        try:
            mem_info = process.memory_info()
            return {
                'rss': mem_info.rss,
                'vms': mem_info.vms,
                'rss_mb': mem_info.rss / (1024 * 1024),
                'vms_mb': mem_info.vms / (1024 * 1024),
            }
        except Exception:
            return {}
    
    def _find_suspicious_regions(self, process: psutil.Process) -> List[Dict[str, Any]]:
        """
        Find suspicious memory regions
        Focus on RWX (Read-Write-Execute) regions which are common in injection
        """
        suspicious = []
        
        try:
            # On Windows, we can use memory_maps
            if hasattr(process, 'memory_maps'):
                maps = process.memory_maps()
                for mmap in maps:
                    # Check for RWX permissions (highly suspicious)
                    perms = getattr(mmap, 'perms', '')
                    if 'r' in perms and 'w' in perms and 'x' in perms:
                        suspicious.append({
                            'path': getattr(mmap, 'path', 'unknown'),
                            'address': getattr(mmap, 'addr', 'unknown'),
                            'size': getattr(mmap, 'rss', 0),
                            'permissions': perms,
                            'reason': 'RWX permissions (Read-Write-Execute)',
                            'risk': 'high'
                        })
                    
                    # Check for executable heap/stack regions
                    path = getattr(mmap, 'path', '').lower()
                    if ('heap' in path or 'stack' in path) and 'x' in perms:
                        suspicious.append({
                            'path': path,
                            'address': getattr(mmap, 'addr', 'unknown'),
                            'size': getattr(mmap, 'rss', 0),
                            'permissions': perms,
                            'reason': 'Executable heap/stack region',
                            'risk': 'critical'
                        })
        except Exception:
            pass
        
        return suspicious
    
    def _detect_code_injection(self, process: psutil.Process) -> List[Dict[str, Any]]:
        """
        Detect various code injection techniques
        """
        detections = []
        
        # Check for CreateRemoteThread injection
        thread_injection = self._check_remote_thread_injection(process)
        if thread_injection:
            detections.append(thread_injection)
        
        # Check for DLL injection
        dll_injection = self._check_dll_injection(process)
        if dll_injection:
            detections.append(dll_injection)
        
        # Check for process hollowing
        hollowing = self._check_process_hollowing(process)
        if hollowing:
            detections.append(hollowing)
        
        # Check for APC injection
        apc_injection = self._check_apc_injection(process)
        if apc_injection:
            detections.append(apc_injection)
        
        return detections
    
    def _check_remote_thread_injection(self, process: psutil.Process) -> Optional[Dict[str, Any]]:
        """Check for CreateRemoteThread injection indicators"""
        try:
            threads = process.threads()
            
            # Look for threads with suspicious start addresses
            # (In a real implementation, we'd check if thread start address is in a suspicious region)
            suspicious_thread_count = 0
            
            for thread in threads:
                # Simplified check - in reality, would need to access thread start address
                # via Windows API and check if it's in an RWX region
                suspicious_thread_count += 0  # Placeholder
            
            if suspicious_thread_count > 0:
                return {
                    'type': 'CreateRemoteThread Injection',
                    'confidence': 0.7,
                    'evidence': [
                        f'Found {suspicious_thread_count} threads with suspicious start addresses',
                        'Threads starting in RWX memory regions',
                    ],
                    'severity': 'high'
                }
        except Exception:
            pass
        
        return None
    
    def _check_dll_injection(self, process: psutil.Process) -> Optional[Dict[str, Any]]:
        """Check for DLL injection indicators"""
        try:
            # Get loaded modules
            if hasattr(process, 'memory_maps'):
                maps = process.memory_maps()
                dll_paths = [m.path for m in maps if m.path.lower().endswith('.dll')]
                
                # Check for DLLs loaded from suspicious locations
                suspicious_locations = [
                    '\\temp\\',
                    '\\appdata\\local\\temp\\',
                    '\\programdata\\',
                    '\\users\\public\\',
                ]
                
                suspicious_dlls = []
                for dll_path in dll_paths:
                    dll_lower = dll_path.lower()
                    if any(loc in dll_lower for loc in suspicious_locations):
                        suspicious_dlls.append(dll_path)
                
                if suspicious_dlls:
                    return {
                        'type': 'DLL Injection',
                        'confidence': 0.65,
                        'evidence': [
                            f'Found {len(suspicious_dlls)} DLLs loaded from suspicious locations',
                            *suspicious_dlls[:5]  # Show first 5
                        ],
                        'severity': 'medium'
                    }
        except Exception:
            pass
        
        return None
    
    def _check_process_hollowing(self, process: psutil.Process) -> Optional[Dict[str, Any]]:
        """Check for process hollowing indicators"""
        try:
            # In process hollowing, the image base address is unmapped and replaced
            # Check if the main module's memory doesn't match the file on disk
            
            exe_path = process.exe() if hasattr(process, 'exe') else None
            if not exe_path or not Path(exe_path).exists():
                return None
            
            # Simplified check - in reality would compare in-memory PE headers
            # with on-disk PE headers
            if hasattr(process, 'memory_maps'):
                maps = process.memory_maps()
                main_module = next((m for m in maps if exe_path in m.path), None)
                
                if main_module:
                    # Check for discrepancies (placeholder logic)
                    # Real implementation would use ReadProcessMemory and compare headers
                    pass
        except Exception:
            pass
        
        return None
    
    def _check_apc_injection(self, process: psutil.Process) -> Optional[Dict[str, Any]]:
        """Check for APC (Asynchronous Procedure Call) injection"""
        try:
            threads = process.threads()
            
            # APC injection is harder to detect without kernel access
            # Look for alertable threads with suspicious patterns
            # This is a simplified placeholder
            
            if len(threads) > 10:  # Arbitrary threshold
                return {
                    'type': 'Possible APC Injection',
                    'confidence': 0.4,
                    'evidence': [
                        f'Process has {len(threads)} threads',
                        'Multiple threads could indicate APC injection',
                    ],
                    'severity': 'low'
                }
        except Exception:
            pass
        
        return None
    
    def _analyze_loaded_modules(self, process: psutil.Process) -> Tuple[List[str], List[Dict[str, Any]]]:
        """Analyze loaded modules (DLLs)"""
        loaded = []
        suspicious = []
        
        try:
            if hasattr(process, 'memory_maps'):
                maps = process.memory_maps()
                dll_paths = [m.path for m in maps if m.path.lower().endswith('.dll')]
                
                loaded = list(set(dll_paths))  # Unique paths
                
                # Check for suspicious modules
                for dll_path in loaded:
                    # Unsigned DLLs
                    # DLLs from temp directories
                    # DLLs with suspicious names
                    dll_lower = dll_path.lower()
                    dll_name = Path(dll_path).name.lower()
                    
                    reasons = []
                    
                    if '\\temp\\' in dll_lower or '\\tmp\\' in dll_lower:
                        reasons.append('Loaded from temporary directory')
                    
                    if not Path(dll_path).exists():
                        reasons.append('DLL file not found on disk (possible memory-only module)')
                    
                    # Check for suspicious keywords in name
                    suspicious_keywords = ['inject', 'hook', 'patch', 'crack', 'bypass']
                    if any(keyword in dll_name for keyword in suspicious_keywords):
                        reasons.append('Suspicious name pattern')
                    
                    if reasons:
                        suspicious.append({
                            'path': dll_path,
                            'name': dll_name,
                            'reasons': reasons,
                            'risk': 'medium'
                        })
        except Exception:
            pass
        
        return loaded, suspicious
    
    def _analyze_threads(self, process: psutil.Process) -> List[Dict[str, Any]]:
        """Analyze process threads"""
        thread_info = []
        
        try:
            threads = process.threads()
            
            for thread in threads:
                info = {
                    'id': thread.id,
                    'user_time': thread.user_time,
                    'system_time': thread.system_time,
                }
                thread_info.append(info)
        except Exception:
            pass
        
        return thread_info
    
    def scan_for_shellcode(self, memory_data: bytes) -> List[Dict[str, Any]]:
        """
        Scan memory data for shellcode patterns
        
        Args:
            memory_data: Raw memory bytes to scan
        
        Returns:
            List of potential shellcode detections
        """
        detections = []
        
        for pattern in self.SHELLCODE_PATTERNS:
            matches = list(re.finditer(pattern, memory_data))
            if matches:
                for match in matches[:10]:  # Limit results
                    detections.append({
                        'offset': match.start(),
                        'pattern': pattern.decode('latin-1', errors='ignore'),
                        'context': memory_data[max(0, match.start()-10):match.end()+10].hex(),
                        'confidence': 0.6,
                        'type': 'shellcode_pattern'
                    })
        
        # Check for NOP sleds (common in exploits)
        nop_sled = re.search(rb'\x90{20,}', memory_data)
        if nop_sled:
            detections.append({
                'offset': nop_sled.start(),
                'pattern': 'NOP sled',
                'length': nop_sled.end() - nop_sled.start(),
                'confidence': 0.8,
                'type': 'nop_sled'
            })
        
        # Check for suspicious API calls in memory
        for api_name in self.SUSPICIOUS_APIS:
            if api_name.encode('ascii') in memory_data:
                detections.append({
                    'api': api_name,
                    'confidence': 0.5,
                    'type': 'suspicious_api_reference'
                })
        
        return detections
    
    def dump_process_memory(self, pid: int, output_dir: str) -> Dict[str, Any]:
        """
        Dump process memory to files for offline analysis
        
        Args:
            pid: Process ID
            output_dir: Directory to save memory dumps
        
        Returns:
            Dump operation results
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        try:
            process = psutil.Process(pid)
            process_name = process.name()
            
            result = {
                'success': True,
                'pid': pid,
                'process_name': process_name,
                'dumps': [],
                'total_size': 0
            }
            
            # Note: Actual memory dumping requires platform-specific APIs
            # On Windows: ReadProcessMemory
            # On Linux: /proc/[pid]/mem
            # This is a placeholder implementation
            
            result['note'] = 'Memory dumping requires elevated privileges and platform-specific implementation'
            
            return result
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'pid': pid
            }
    
    def get_detection_summary(self) -> Dict[str, Any]:
        """Get summary of all detections"""
        return {
            'total_detections': len(self.detections),
            'by_type': self._group_by_type(),
            'high_confidence': [d for d in self.detections if d.confidence > 0.7],
            'detections': self.detections
        }
    
    def _group_by_type(self) -> Dict[str, int]:
        """Group detections by injection type"""
        groups = {}
        for detection in self.detections:
            injection_type = detection.injection_type
            groups[injection_type] = groups.get(injection_type, 0) + 1
        return groups
