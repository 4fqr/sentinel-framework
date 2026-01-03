"""
Document Analyzer - Detects malicious Office documents, PDFs, scripts
Analyzes: Word, Excel, PowerPoint, PDF, HTA, VBS, JS, PS1
"""

import logging
from typing import Dict, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class DocumentAnalyzer:
    """Analyzes documents for embedded malware and exploits"""
    
    DANGEROUS_MACROS = [
        'Auto_Open', 'AutoOpen', 'Document_Open', 'Workbook_Open',
        'Auto_Close', 'AutoClose', 'Document_Close',
        'Shell', 'WScript.Shell', 'CreateObject',
        'ExecuteExcel4Macro', 'CALL', 'REGISTER',
    ]
    
    DANGEROUS_PDF_FEATURES = [
        '/JavaScript', '/JS', '/Launch', '/SubmitForm',
        '/GoToR', '/GoToE', '/URI', '/OpenAction',
        '/AA', '/AcroForm', '/Names', '/EmbeddedFile'
    ]
    
    SCRIPT_OBFUSCATION = [
        'eval', 'unescape', 'fromCharCode', 'atob',
        'decode', 'decompress', 'inflate'
    ]
    
    def analyze(self, file_path: str) -> Dict[str, Any]:
        """Analyze document for malicious content"""
        results = {
            'document_type': self._detect_document_type(file_path),
            'is_malicious': False,
            'vulnerabilities': [],
            'suspicious_indicators': [],
            'embedded_files': [],
            'macros': [],
            'scripts': []
        }
        
        ext = Path(file_path).suffix.lower()
        
        try:
            if ext in ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.dot', '.xlt']:
                results = self._analyze_office(file_path, results)
            elif ext == '.pdf':
                results = self._analyze_pdf(file_path, results)
            elif ext in ['.hta', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh']:
                results = self._analyze_script(file_path, results)
            elif ext in ['.ps1', '.psm1', '.psd1']:
                results = self._analyze_powershell(file_path, results)
            elif ext in ['.rtf']:
                results = self._analyze_rtf(file_path, results)
                
        except Exception as e:
            logger.error(f"Document analysis failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def _detect_document_type(self, file_path: str) -> str:
        """Detect document type from magic bytes"""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(8)
                
                # Office OpenXML (ZIP-based)
                if header[:2] == b'PK':
                    return 'Office Open XML'
                # OLE/COM (Old Office)
                elif header[:8] == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
                    return 'Microsoft Office 97-2003'
                # PDF
                elif header[:4] == b'%PDF':
                    return 'PDF Document'
                # RTF
                elif header[:5] == b'{\\rtf':
                    return 'Rich Text Format'
                    
        except Exception:
            pass
        
        return Path(file_path).suffix.upper()
    
    def _analyze_office(self, file_path: str, results: Dict) -> Dict:
        """Analyze Office documents for macros and exploits"""
        try:
            # Try using oletools for macro analysis
            try:
                from oletools.olevba import VBA_Parser
                
                vbaparser = VBA_Parser(file_path)
                
                if vbaparser.detect_vba_macros():
                    results['macros'] = []
                    
                    for (filename, stream_path, vba_filename, vba_code) in vbaparser.extract_macros():
                        macro_info = {
                            'stream': stream_path,
                            'code_length': len(vba_code),
                            'suspicious_keywords': []
                        }
                        
                        # Check for dangerous keywords
                        for keyword in self.DANGEROUS_MACROS:
                            if keyword in vba_code:
                                macro_info['suspicious_keywords'].append(keyword)
                        
                        results['macros'].append(macro_info)
                        
                        # Add suspicious indicators
                        if macro_info['suspicious_keywords']:
                            results['suspicious_indicators'].append({
                                'type': 'Malicious VBA Macro',
                                'severity': 'CRITICAL',
                                'evidence': f'{len(macro_info["suspicious_keywords"])} dangerous keywords: {", ".join(macro_info["suspicious_keywords"][:5])}',
                                'reason': 'Macro contains code execution functions - likely malicious'
                            })
                    
                    # Check for auto-execution
                    auto_exec = ['Auto_Open', 'AutoOpen', 'Document_Open', 'Workbook_Open']
                    for macro in results['macros']:
                        if any(ae in macro['suspicious_keywords'] for ae in auto_exec):
                            results['vulnerabilities'].append({
                                'type': 'Auto-Executing Macro',
                                'severity': 'CRITICAL',
                                'description': 'Macro runs automatically when document opens',
                                'impact': 'Code execution without user interaction'
                            })
                
                vbaparser.close()
                
            except ImportError:
                results['warning'] = 'oletools not installed - limited Office analysis. Install: pip install oletools'
            
            # Check for embedded OLE objects
            try:
                import olefile
                
                if olefile.isOleFile(file_path):
                    ole = olefile.OleFileIO(file_path)
                    
                    # List all streams
                    streams = ole.listdir()
                    
                    # Check for suspicious streams
                    suspicious_streams = ['Macros', 'VBA', '_VBA_PROJECT', 'ObjectPool']
                    for stream in streams:
                        stream_name = '/'.join(stream)
                        if any(sus in stream_name for sus in suspicious_streams):
                            results['suspicious_indicators'].append({
                                'type': 'Suspicious OLE Stream',
                                'severity': 'HIGH',
                                'evidence': f'Stream: {stream_name}',
                                'reason': 'Contains macro or embedded object storage'
                            })
                    
                    ole.close()
                    
            except ImportError:
                pass
            except Exception as e:
                logger.debug(f"OLE analysis failed: {e}")
            
        except Exception as e:
            logger.error(f"Office analysis failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def _analyze_pdf(self, file_path: str, results: Dict) -> Dict:
        """Analyze PDF for malicious JavaScript and exploits"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                content_str = str(content)
                
                # Check for dangerous PDF features
                for feature in self.DANGEROUS_PDF_FEATURES:
                    if feature.encode() in content:
                        results['suspicious_indicators'].append({
                            'type': 'Dangerous PDF Feature',
                            'severity': 'HIGH',
                            'evidence': f'Feature: {feature}',
                            'reason': f'{feature} can execute code or launch external programs'
                        })
                
                # Check for JavaScript
                if b'/JavaScript' in content or b'/JS' in content:
                    results['vulnerabilities'].append({
                        'type': 'Embedded JavaScript',
                        'severity': 'HIGH',
                        'description': 'PDF contains executable JavaScript',
                        'impact': 'Can exploit PDF reader vulnerabilities or phish credentials'
                    })
                
                # Check for Launch actions
                if b'/Launch' in content:
                    results['vulnerabilities'].append({
                        'type': 'Launch Action',
                        'severity': 'CRITICAL',
                        'description': 'PDF can launch external programs',
                        'impact': 'Direct code execution - can run any program'
                    })
                
                # Check for auto-actions
                if b'/OpenAction' in content or b'/AA' in content:
                    results['vulnerabilities'].append({
                        'type': 'Auto-Action',
                        'severity': 'CRITICAL',
                        'description': 'PDF executes actions automatically on open',
                        'impact': 'Code runs without user interaction'
                    })
                
                # Check for embedded files
                if b'/EmbeddedFile' in content:
                    results['suspicious_indicators'].append({
                        'type': 'Embedded File',
                        'severity': 'MEDIUM',
                        'evidence': 'PDF contains embedded files',
                        'reason': 'Embedded files may contain malware'
                    })
                
        except Exception as e:
            logger.error(f"PDF analysis failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def _analyze_script(self, file_path: str, results: Dict) -> Dict:
        """Analyze VBS/JS/HTA scripts"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                script_content = f.read()
            
            results['script_size'] = len(script_content)
            
            # Check for obfuscation
            obfuscation_count = sum(1 for keyword in self.SCRIPT_OBFUSCATION if keyword in script_content.lower())
            
            if obfuscation_count >= 2:
                results['suspicious_indicators'].append({
                    'type': 'Obfuscated Script',
                    'severity': 'HIGH',
                    'evidence': f'{obfuscation_count} obfuscation techniques detected',
                    'reason': 'Script is heavily obfuscated to hide malicious intent'
                })
            
            # Check for download functions
            download_keywords = ['DownloadFile', 'DownloadString', 'URLDownloadToFile', 'MSXML2.XMLHTTP', 'WinHttp.WinHttpRequest']
            for keyword in download_keywords:
                if keyword in script_content:
                    results['vulnerabilities'].append({
                        'type': 'Download Capability',
                        'severity': 'HIGH',
                        'description': f'Script can download files from internet: {keyword}',
                        'impact': 'Downloads additional malware payloads'
                    })
            
            # Check for execution functions
            exec_keywords = ['WScript.Shell', 'Shell.Application', 'CreateObject', '.Run', '.Exec']
            exec_found = [kw for kw in exec_keywords if kw in script_content]
            if exec_found:
                results['vulnerabilities'].append({
                    'type': 'Code Execution',
                    'severity': 'CRITICAL',
                    'description': f'Script can execute commands: {", ".join(exec_found)}',
                    'impact': 'Full system compromise possible'
                })
            
        except Exception as e:
            logger.error(f"Script analysis failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def _analyze_powershell(self, file_path: str, results: Dict) -> Dict:
        """Analyze PowerShell scripts"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                script_content = f.read()
            
            # Check for dangerous cmdlets
            dangerous_cmdlets = [
                'Invoke-Expression', 'IEX', 'Invoke-Command',
                'Start-Process', 'New-Object', 'DownloadString',
                'DownloadFile', 'FromBase64String', 'EncodedCommand',
                'Bypass', 'Hidden', 'WindowStyle'
            ]
            
            found_cmdlets = [cmd for cmd in dangerous_cmdlets if cmd in script_content]
            
            if found_cmdlets:
                results['suspicious_indicators'].append({
                    'type': 'Dangerous PowerShell Cmdlets',
                    'severity': 'HIGH',
                    'evidence': f'{len(found_cmdlets)} dangerous cmdlets: {", ".join(found_cmdlets[:5])}',
                    'reason': 'Uses PowerShell functions commonly seen in malware'
                })
            
            # Check for base64 encoding (common obfuscation)
            if 'FromBase64String' in script_content or '-EncodedCommand' in script_content:
                results['vulnerabilities'].append({
                    'type': 'Base64 Obfuscation',
                    'severity': 'HIGH',
                    'description': 'PowerShell script uses Base64 encoding',
                    'impact': 'Hides malicious payload from analysis'
                })
            
            # Check for execution policy bypass
            if 'ExecutionPolicy Bypass' in script_content or '-ep bypass' in script_content.lower():
                results['vulnerabilities'].append({
                    'type': 'Execution Policy Bypass',
                    'severity': 'HIGH',
                    'description': 'Bypasses PowerShell security restrictions',
                    'impact': 'Allows unsigned malicious scripts to run'
                })
            
        except Exception as e:
            logger.error(f"PowerShell analysis failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def _analyze_rtf(self, file_path: str, results: Dict) -> Dict:
        """Analyze RTF documents for exploits"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Check for embedded objects
            if b'\\object' in content:
                results['suspicious_indicators'].append({
                    'type': 'Embedded Object',
                    'severity': 'HIGH',
                    'evidence': 'RTF contains embedded OLE objects',
                    'reason': 'Embedded objects can exploit Office vulnerabilities'
                })
            
            # Check for known exploit patterns
            if b'CVE-2017-11882' in content or b'Equation' in content:
                results['vulnerabilities'].append({
                    'type': 'Equation Editor Exploit (CVE-2017-11882)',
                    'severity': 'CRITICAL',
                    'description': 'RTF exploits Microsoft Equation Editor vulnerability',
                    'impact': 'Remote code execution without user interaction'
                })
            
        except Exception as e:
            logger.error(f"RTF analysis failed: {e}")
            results['error'] = str(e)
        
        return results
