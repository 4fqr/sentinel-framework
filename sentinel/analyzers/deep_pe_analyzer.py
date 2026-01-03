"""
Deep PE Analysis - Advanced executable analysis with entropy, packer detection, and more
"""

import pefile
import math
import hashlib
import struct
from pathlib import Path
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger(__name__)


class DeepPEAnalyzer:
    """Advanced PE file analysis"""
    
    # Known packer signatures
    PACKER_SIGNATURES = {
        'UPX': [b'UPX0', b'UPX1', b'UPX!'],
        'ASPack': [b'ASPack', b'.aspack'],
        'PECompact': [b'PECompact'],
        'Themida': [b'.themida'],
        'VMProtect': [b'VMProtect'],
        'Enigma': [b'Enigma'],
        'MPRESS': [b'.MPRESS'],
        'FSG': [b'FSG!'],
        'Petite': [b'Petite'],
        'NSPack': [b'NSPack'],
        'MEW': [b'MEW'],
        'WinUpack': [b'WinUpack'],
        'Armadillo': [b'Armadillo'],
        'ExeShield': [b'ExeShield'],
    }
    
    def analyze(self, file_path: str) -> Dict[str, Any]:
        """
        Perform deep PE analysis
        
        Args:
            file_path: Path to PE file
            
        Returns:
            Comprehensive analysis results
        """
        try:
            pe = pefile.PE(file_path)
            
            results = {
                'entropy_analysis': self._analyze_entropy(pe, file_path),
                'packer_detection': self._detect_packers(pe, file_path),
                'section_analysis': self._analyze_sections(pe),
                'overlay_analysis': self._analyze_overlay(pe, file_path),
                'resource_analysis': self._analyze_resources(pe),
                'import_analysis': self._analyze_imports(pe),
                'export_analysis': self._analyze_exports(pe),
                'certificate_analysis': self._analyze_certificate(pe),
                'anomaly_detection': self._detect_anomalies(pe),
                'rich_header': self._analyze_rich_header(pe),
                'tls_callbacks': self._analyze_tls_callbacks(pe),
            }
            
            pe.close()
            return results
            
        except Exception as e:
            logger.error(f"Deep PE analysis failed: {e}")
            return {'error': str(e)}
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        entropy = 0
        length = len(data)
        
        # Count byte frequencies
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        
        # Calculate entropy
        for count in freq:
            if count == 0:
                continue
            p = float(count) / length
            entropy -= p * math.log2(p)
        
        return entropy
    
    def _analyze_entropy(self, pe: pefile.PE, file_path: str) -> Dict[str, Any]:
        """Analyze file and section entropy"""
        results = {
            'sections': [],
            'overall_entropy': 0.0,
            'high_entropy_sections': []
        }
        
        try:
            # Calculate overall entropy
            with open(file_path, 'rb') as f:
                file_data = f.read()
                results['overall_entropy'] = self._calculate_entropy(file_data)
            
            # Analyze each section
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
                section_entropy = self._calculate_entropy(section.get_data())
                
                section_info = {
                    'name': section_name,
                    'entropy': round(section_entropy, 2),
                    'size': section.SizeOfRawData,
                    'virtual_size': section.Misc_VirtualSize,
                    'characteristics': hex(section.Characteristics)
                }
                
                results['sections'].append(section_info)
                
                # Flag high entropy (possible encryption/packing)
                if section_entropy > 7.0:
                    results['high_entropy_sections'].append({
                        'section': section_name,
                        'entropy': round(section_entropy, 2),
                        'reason': 'Possibly encrypted or packed'
                    })
            
        except Exception as e:
            logger.error(f"Entropy analysis failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def _detect_packers(self, pe: pefile.PE, file_path: str) -> Dict[str, Any]:
        """Detect known packers/protectors"""
        results = {
            'is_packed': False,
            'detected_packers': [],
            'indicators': []
        }
        
        try:
            # Check section names for packer signatures
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
                
                for packer_name, signatures in self.PACKER_SIGNATURES.items():
                    for sig in signatures:
                        if sig in section.Name:
                            results['detected_packers'].append(packer_name)
                            results['is_packed'] = True
                            results['indicators'].append(f'Section name: {section_name}')
            
            # Check for common packing indicators
            if len(pe.sections) < 3:
                results['indicators'].append('Low section count (possible packing)')
            
            # Check for high entropy sections
            for section in pe.sections:
                entropy = self._calculate_entropy(section.get_data())
                if entropy > 7.2:
                    results['indicators'].append(f'High entropy in {section.Name.decode(errors="ignore").rstrip(chr(0))} ({entropy:.2f})')
                    results['is_packed'] = True
            
            # Check for entry point in unusual section
            entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            for section in pe.sections:
                if (section.VirtualAddress <= entry_point < 
                    section.VirtualAddress + section.Misc_VirtualSize):
                    section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
                    if section_name not in ['.text', 'CODE']:
                        results['indicators'].append(f'Entry point in unusual section: {section_name}')
                        results['is_packed'] = True
            
            # Check for suspicious imports (or lack thereof)
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                import_count = len(pe.DIRECTORY_ENTRY_IMPORT)
                if import_count < 3:
                    results['indicators'].append(f'Very few imports ({import_count}) - possible runtime loading')
                    results['is_packed'] = True
            
            # Remove duplicates
            results['detected_packers'] = list(set(results['detected_packers']))
            
        except Exception as e:
            logger.error(f"Packer detection failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def _analyze_sections(self, pe: pefile.PE) -> List[Dict[str, Any]]:
        """Detailed section analysis"""
        sections = []
        
        try:
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
                
                # Parse characteristics flags
                characteristics = []
                flags = section.Characteristics
                if flags & 0x20:
                    characteristics.append('CODE')
                if flags & 0x40:
                    characteristics.append('INITIALIZED_DATA')
                if flags & 0x80:
                    characteristics.append('UNINITIALIZED_DATA')
                if flags & 0x20000000:
                    characteristics.append('EXECUTABLE')
                if flags & 0x40000000:
                    characteristics.append('READABLE')
                if flags & 0x80000000:
                    characteristics.append('WRITABLE')
                
                # Check for suspicious combinations
                suspicious = False
                reasons = []
                
                if 'WRITABLE' in characteristics and 'EXECUTABLE' in characteristics:
                    suspicious = True
                    reasons.append('Writable + Executable (DEP bypass risk)')
                
                if section.SizeOfRawData == 0 and section.Misc_VirtualSize > 0:
                    suspicious = True
                    reasons.append('No raw data but has virtual size (runtime allocation)')
                
                if section.Misc_VirtualSize > section.SizeOfRawData * 10:
                    suspicious = True
                    reasons.append('Virtual size much larger than raw size')
                
                sections.append({
                    'name': section_name,
                    'virtual_address': hex(section.VirtualAddress),
                    'virtual_size': section.Misc_VirtualSize,
                    'raw_size': section.SizeOfRawData,
                    'entropy': round(self._calculate_entropy(section.get_data()), 2),
                    'characteristics': characteristics,
                    'md5': hashlib.md5(section.get_data()).hexdigest(),
                    'suspicious': suspicious,
                    'suspicious_reasons': reasons
                })
        
        except Exception as e:
            logger.error(f"Section analysis failed: {e}")
        
        return sections
    
    def _analyze_overlay(self, pe: pefile.PE, file_path: str) -> Dict[str, Any]:
        """Analyze overlay data (data after PE)"""
        results = {
            'has_overlay': False,
            'size': 0,
            'entropy': 0.0,
            'md5': None
        }
        
        try:
            overlay_offset = pe.get_overlay_data_start_offset()
            if overlay_offset is not None:
                with open(file_path, 'rb') as f:
                    f.seek(overlay_offset)
                    overlay_data = f.read()
                    
                    if overlay_data:
                        results['has_overlay'] = True
                        results['size'] = len(overlay_data)
                        results['entropy'] = round(self._calculate_entropy(overlay_data), 2)
                        results['md5'] = hashlib.md5(overlay_data).hexdigest()
                        
                        # Check if overlay is suspicious
                        if results['entropy'] > 7.0:
                            results['suspicious'] = True
                            results['reason'] = 'High entropy overlay (possibly encrypted data)'
        
        except Exception as e:
            logger.error(f"Overlay analysis failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def _analyze_resources(self, pe: pefile.PE) -> Dict[str, Any]:
        """Analyze PE resources"""
        results = {
            'has_resources': False,
            'resource_types': [],
            'suspicious_resources': []
        }
        
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                results['has_resources'] = True
                
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    try:
                        if resource_type.name is not None:
                            type_name = str(resource_type.name)
                        else:
                            type_name = pefile.RESOURCE_TYPE.get(resource_type.struct.Id, 'UNKNOWN')
                        
                        results['resource_types'].append(type_name)
                        
                        # Check for suspicious resources
                        if hasattr(resource_type, 'directory'):
                            for resource_id in resource_type.directory.entries:
                                if hasattr(resource_id, 'directory'):
                                    for resource_lang in resource_id.directory.entries:
                                        data_rva = resource_lang.data.struct.OffsetToData
                                        size = resource_lang.data.struct.Size
                                        data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
                                        
                                        entropy = self._calculate_entropy(data)
                                        if entropy > 7.2:
                                            results['suspicious_resources'].append({
                                                'type': type_name,
                                                'size': size,
                                                'entropy': round(entropy, 2),
                                                'reason': 'High entropy resource (possibly encrypted)'
                                            })
                    except Exception as e:
                        logger.debug(f"Resource entry error: {e}")
                        continue
        
        except Exception as e:
            logger.error(f"Resource analysis failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def _analyze_imports(self, pe: pefile.PE) -> Dict[str, Any]:
        """Deep import analysis"""
        results = {
            'total_dlls': 0,
            'total_functions': 0,
            'suspicious_imports': [],
            'api_categories': {}
        }
        
        # Suspicious API categories
        dangerous_apis = {
            'Process Injection': ['CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx', 
                                 'NtCreateThreadEx', 'RtlCreateUserThread', 'QueueUserAPC'],
            'Code Execution': ['WinExec', 'ShellExecute', 'CreateProcess', 'LoadLibrary'],
            'Network': ['InternetOpen', 'InternetConnect', 'HttpSendRequest', 'send', 'recv', 
                       'WSAStartup', 'URLDownloadToFile'],
            'Crypto': ['CryptEncrypt', 'CryptDecrypt', 'CryptAcquireContext', 'CryptCreateHash'],
            'Registry': ['RegOpenKey', 'RegSetValue', 'RegDeleteKey', 'RegCreateKey'],
            'File System': ['DeleteFile', 'MoveFile', 'CopyFile', 'CreateFile'],
            'Keylogging': ['GetAsyncKeyState', 'GetKeyState', 'SetWindowsHookEx'],
            'Anti-Debug': ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess'],
            'Persistence': ['CreateService', 'StartService', 'RegSetValueEx'],
        }
        
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                results['total_dlls'] = len(pe.DIRECTORY_ENTRY_IMPORT)
                
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode('utf-8', errors='ignore')
                            results['total_functions'] += 1
                            
                            # Categorize API
                            for category, apis in dangerous_apis.items():
                                if any(api.lower() in func_name.lower() for api in apis):
                                    if category not in results['api_categories']:
                                        results['api_categories'][category] = []
                                    results['api_categories'][category].append(f'{dll_name}!{func_name}')
                                    
                                    results['suspicious_imports'].append({
                                        'function': func_name,
                                        'dll': dll_name,
                                        'category': category,
                                        'risk': 'HIGH' if category in ['Process Injection', 'Anti-Debug'] else 'MEDIUM'
                                    })
        
        except Exception as e:
            logger.error(f"Import analysis failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def _analyze_exports(self, pe: pefile.PE) -> Dict[str, Any]:
        """Analyze exported functions"""
        results = {
            'has_exports': False,
            'total_exports': 0,
            'exported_functions': []
        }
        
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                results['has_exports'] = True
                results['total_exports'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
                
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols[:20]:  # First 20
                    if exp.name:
                        results['exported_functions'].append(
                            exp.name.decode('utf-8', errors='ignore')
                        )
        
        except Exception as e:
            logger.error(f"Export analysis failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def _analyze_certificate(self, pe: pefile.PE) -> Dict[str, Any]:
        """Analyze digital signature"""
        results = {
            'is_signed': False,
            'valid': None,
            'signer': None,
            'issuer': None
        }
        
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
                results['is_signed'] = True
                # Full certificate parsing would require cryptography library
                results['note'] = 'Certificate present but not validated'
        
        except Exception as e:
            logger.error(f"Certificate analysis failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def _detect_anomalies(self, pe: pefile.PE) -> List[Dict[str, str]]:
        """Detect PE anomalies"""
        anomalies = []
        
        try:
            # Check timestamps
            timestamp = pe.FILE_HEADER.TimeDateStamp
            if timestamp == 0:
                anomalies.append({
                    'type': 'Timestamp',
                    'description': 'PE timestamp is zero (intentionally wiped)'
                })
            
            # Check subsystem
            subsystem = pe.OPTIONAL_HEADER.Subsystem
            if subsystem == 1:  # NATIVE
                anomalies.append({
                    'type': 'Subsystem',
                    'description': 'Native subsystem (kernel-mode driver)'
                })
            
            # Check image base
            image_base = pe.OPTIONAL_HEADER.ImageBase
            if image_base == 0:
                anomalies.append({
                    'type': 'ImageBase',
                    'description': 'Image base is zero (unusual)'
                })
            
            # Check section alignment
            file_align = pe.OPTIONAL_HEADER.FileAlignment
            section_align = pe.OPTIONAL_HEADER.SectionAlignment
            if file_align > section_align:
                anomalies.append({
                    'type': 'Alignment',
                    'description': f'File alignment ({file_align}) > Section alignment ({section_align})'
                })
        
        except Exception as e:
            logger.error(f"Anomaly detection failed: {e}")
        
        return anomalies
    
    def _analyze_rich_header(self, pe: pefile.PE) -> Dict[str, Any]:
        """Analyze Rich header"""
        results = {
            'has_rich_header': False,
            'md5': None
        }
        
        try:
            if hasattr(pe, 'RICH_HEADER'):
                results['has_rich_header'] = True
                if pe.RICH_HEADER:
                    rich_data = pe.RICH_HEADER.raw_data
                    results['md5'] = hashlib.md5(rich_data).hexdigest()
        
        except Exception as e:
            logger.error(f"Rich header analysis failed: {e}")
        
        return results
    
    def _analyze_tls_callbacks(self, pe: pefile.PE) -> Dict[str, Any]:
        """Analyze TLS callbacks (often used by malware)"""
        results = {
            'has_tls': False,
            'callback_count': 0,
            'callbacks': []
        }
        
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
                results['has_tls'] = True
                tls = pe.DIRECTORY_ENTRY_TLS.struct
                
                # TLS callbacks can execute before main entry point
                if hasattr(tls, 'AddressOfCallBacks'):
                    results['note'] = 'TLS callbacks present (can execute before EntryPoint)'
                    results['suspicious'] = True
        
        except Exception as e:
            logger.error(f"TLS analysis failed: {e}")
        
        return results
