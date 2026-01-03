"""
Sentinel Framework - Malware Analyzer
Orchestrates static and dynamic analysis with threat detection
"""

import time
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

from sentinel.core.sandbox import SandboxEngine, SandboxResult
from sentinel.core.monitor import BehaviorMonitor
from sentinel.core.events import BehaviorEvent
from sentinel.detectors.ransomware import RansomwareDetector
from sentinel.detectors.c2 import C2Detector
from sentinel.detectors.injection import InjectionDetector
from sentinel.detectors.persistence import PersistenceDetector
from sentinel.detectors.evasion import EvasionDetector
from sentinel.utils.logger import get_logger
from sentinel.utils.helpers import get_file_hashes, get_file_type, format_bytes
from sentinel.config import config


logger = get_logger(__name__)


@dataclass
class AnalysisResult:
    """Complete analysis results"""
    sample_path: str
    sample_hash: str
    file_type: str
    file_size: int
    analysis_time: float
    sandbox_result: Optional[SandboxResult] = None
    static_analysis: Dict[str, Any] = field(default_factory=dict)
    behavioral_events: List[Dict[str, Any]] = field(default_factory=list)
    threat_detections: List[Dict[str, Any]] = field(default_factory=list)
    verdict: str = "Unknown"
    risk_score: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'sample_path': self.sample_path,
            'sample_hash': self.sample_hash,
            'file_type': self.file_type,
            'file_size': self.file_size,
            'analysis_time': self.analysis_time,
            'sandbox_result': self.sandbox_result.to_dict() if self.sandbox_result else None,
            'static_analysis': self.static_analysis,
            'behavioral_events_count': len(self.behavioral_events),
            'threat_detections': self.threat_detections,
            'verdict': self.verdict,
            'risk_score': self.risk_score,
        }


class MalwareAnalyzer:
    """
    Comprehensive malware analysis engine
    Coordinates static analysis, dynamic execution, and threat detection
    """
    
    def __init__(self):
        """Initialize malware analyzer"""
        self.config = config.analysis_config
        self.sandbox = SandboxEngine()
        self.monitor = BehaviorMonitor()
        
        # Initialize detectors
        self.detectors = []
        self._initialize_detectors()
        
        logger.info("Malware analyzer initialized")
    
    def _initialize_detectors(self) -> None:
        """Initialize threat detection engines"""
        detection_config = self.config.get('detection', {})
        
        if detection_config.get('ransomware', {}).get('enabled', True):
            self.detectors.append(RansomwareDetector())
            logger.debug("Ransomware detector initialized")
        
        if detection_config.get('c2_communication', {}).get('enabled', True):
            self.detectors.append(C2Detector())
            logger.debug("C2 detector initialized")
        
        if detection_config.get('code_injection', {}).get('enabled', True):
            self.detectors.append(InjectionDetector())
            logger.debug("Injection detector initialized")
        
        if detection_config.get('persistence', {}).get('enabled', True):
            self.detectors.append(PersistenceDetector())
            logger.debug("Persistence detector initialized")
        
        if detection_config.get('evasion', {}).get('enabled', True):
            self.detectors.append(EvasionDetector())
            logger.debug("Evasion detector initialized")
    
    def analyze(
        self,
        sample_path: str,
        enable_static: Optional[bool] = None,
        enable_dynamic: Optional[bool] = None,
        timeout: Optional[int] = None
    ) -> AnalysisResult:
        """
        Perform comprehensive malware analysis
        
        Args:
            sample_path: Path to sample file
            enable_static: Enable static analysis (default from config)
            enable_dynamic: Enable dynamic analysis (default from config)
            timeout: Analysis timeout in seconds
        
        Returns:
            AnalysisResult containing complete analysis
        """
        logger.info(f"Starting analysis: {sample_path}")
        start_time = time.time()
        
        # Get file information
        try:
            file_hashes = get_file_hashes(sample_path)
            file_type = get_file_type(sample_path)
            file_size = Path(sample_path).stat().st_size
        except Exception as e:
            logger.error(f"Failed to read sample file: {e}")
            return AnalysisResult(
                sample_path=sample_path,
                sample_hash="error",
                file_type="error",
                file_size=0,
                analysis_time=0,
                verdict=f"Error: {str(e)}"
            )
        
        # Initialize result
        result = AnalysisResult(
            sample_path=sample_path,
            sample_hash=file_hashes['sha256'],
            file_type=file_type,
            file_size=file_size,
            analysis_time=0
        )
        
        # Static analysis
        if enable_static or (enable_static is None and self.config.get('static_analysis', True)):
            logger.info("Performing static analysis")
            result.static_analysis = self._perform_static_analysis(sample_path, file_hashes)
        
        # Dynamic analysis
        if enable_dynamic or (enable_dynamic is None and self.config.get('dynamic_analysis', True)):
            logger.info("Performing dynamic analysis")
            
            # Start behavioral monitoring
            self.monitor.start()
            
            # Execute in sandbox
            sandbox_result = self.sandbox.execute(sample_path, timeout=timeout)
            result.sandbox_result = sandbox_result
            
            # Stop monitoring
            time.sleep(2)  # Allow time for final events
            self.monitor.stop()
            
            # Get behavioral events
            result.behavioral_events = [
                event.to_dict() for event in self.monitor.get_events()
            ]
        
        # Threat detection
        logger.info("Running threat detection")
        result.threat_detections = self._detect_threats(result)
        
        # Calculate verdict and risk score
        result.verdict, result.risk_score = self._calculate_verdict(result)
        
        result.analysis_time = time.time() - start_time
        logger.info(f"Analysis completed in {result.analysis_time:.2f}s - Verdict: {result.verdict}")
        
        return result
    
    def _perform_static_analysis(
        self,
        sample_path: str,
        file_hashes: Dict[str, str]
    ) -> Dict[str, Any]:
        """
        Perform static analysis on sample
        
        Args:
            sample_path: Path to sample
            file_hashes: Pre-calculated file hashes
        
        Returns:
            Dictionary with static analysis results
        """
        static_info = {
            'hashes': file_hashes,
            'file_type': get_file_type(sample_path),
            'file_size': format_bytes(Path(sample_path).stat().st_size),
        }
        
        # PE analysis for Windows executables
        if sample_path.lower().endswith(('.exe', '.dll')):
            try:
                import pefile
                pe = pefile.PE(sample_path)
                
                static_info['pe_info'] = {
                    'imphash': pe.get_imphash(),
                    'timestamp': pe.FILE_HEADER.TimeDateStamp,
                    'sections': len(pe.sections),
                    'imports': len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0,
                }
                
                # Extract suspicious imports
                suspicious_imports = []
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        for imp in entry.imports:
                            if imp.name:
                                name = imp.name.decode() if isinstance(imp.name, bytes) else imp.name
                                if self._is_suspicious_import(name):
                                    suspicious_imports.append(name)
                
                static_info['suspicious_imports'] = suspicious_imports
                
            except Exception as e:
                logger.error(f"PE analysis failed: {e}")
                static_info['pe_error'] = str(e)
        
        # String extraction
        try:
            with open(sample_path, 'rb') as f:
                data = f.read()
                from sentinel.utils.helpers import extract_strings, is_suspicious_string
                strings = extract_strings(data, min_length=6)
                suspicious_strings = [s for s in strings if is_suspicious_string(s)]
                
                static_info['strings'] = {
                    'total': len(strings),
                    'suspicious': suspicious_strings[:20]  # Top 20
                }
        except Exception as e:
            logger.error(f"String extraction failed: {e}")
        
        return static_info
    
    def _is_suspicious_import(self, import_name: str) -> bool:
        """Check if import is suspicious"""
        suspicious = [
            'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',
            'OpenProcess', 'GetProcAddress', 'LoadLibrary',
            'SetWindowsHookEx', 'CallNextHookEx',
            'RegSetValueEx', 'RegCreateKeyEx',
            'InternetOpen', 'InternetConnect', 'HttpSendRequest',
            'CryptEncrypt', 'CryptDecrypt',
        ]
        
        return any(susp.lower() in import_name.lower() for susp in suspicious)
    
    def _detect_threats(self, result: AnalysisResult) -> List[Dict[str, Any]]:
        """
        Run all threat detectors on analysis results
        
        Args:
            result: Analysis result to check
        
        Returns:
            List of threat detections
        """
        all_detections = []
        
        events = self.monitor.get_events()
        
        for detector in self.detectors:
            try:
                detections = detector.detect(events, result)
                all_detections.extend(detections)
            except Exception as e:
                logger.error(f"Detector {detector.__class__.__name__} failed: {e}")
        
        return all_detections
    
    def _calculate_verdict(self, result: AnalysisResult) -> tuple[str, int]:
        """
        Calculate final verdict and risk score
        
        Args:
            result: Analysis result
        
        Returns:
            Tuple of (verdict, risk_score)
        """
        risk_score = 0
        
        # Base score from detections
        for detection in result.threat_detections:
            confidence = detection.get('confidence', 0)
            severity = detection.get('severity', 'low')
            
            severity_multiplier = {
                'low': 1,
                'medium': 2,
                'high': 3,
                'critical': 4
            }.get(severity, 1)
            
            risk_score += int(confidence * severity_multiplier)
        
        # Score from suspicious imports
        if result.static_analysis.get('suspicious_imports'):
            risk_score += len(result.static_analysis['suspicious_imports']) * 5
        
        # Score from suspicious strings
        if result.static_analysis.get('strings', {}).get('suspicious'):
            risk_score += len(result.static_analysis['strings']['suspicious']) * 2
        
        # Determine verdict
        if risk_score >= 80:
            verdict = "Malicious"
        elif risk_score >= 50:
            verdict = "Suspicious"
        elif risk_score >= 20:
            verdict = "Potentially Unwanted"
        else:
            verdict = "Clean"
        
        return verdict, min(risk_score, 100)
    
    def cleanup(self) -> None:
        """Cleanup analyzer resources"""
        logger.info("Cleaning up analyzer resources")
        self.sandbox.cleanup()
        self.monitor.clear_events()
