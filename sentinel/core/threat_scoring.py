"""
Sentinel Framework - Intelligent Threat Scoring Engine
Evidence-based scoring with multi-indicator correlation to eliminate false positives
"""

from typing import Dict, List, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum

from sentinel.core.events import BehaviorEvent, EventSeverity


class ThreatLevel(Enum):
    """Threat level classification"""
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    LIKELY_MALICIOUS = "likely_malicious"
    MALICIOUS = "malicious"
    CRITICAL = "critical"


@dataclass
class ThreatEvidence:
    """Evidence for threat detection"""
    category: str
    description: str
    confidence: float  # 0.0 to 1.0
    severity: str
    indicators: List[str] = field(default_factory=list)
    weight: float = 1.0


class ThreatScorer:
    """
    Intelligent threat scoring engine with multi-indicator correlation
    Designed to provide accurate assessments without false positives
    """
    
    # Evidence weight multipliers
    WEIGHTS = {
        'critical_api_combination': 5.0,  # Multiple dangerous APIs together
        'packer_with_suspicious_behavior': 4.0,  # Packed + malicious activity
        'multiple_persistence_methods': 3.5,  # Several persistence techniques
        'c2_communication': 3.0,  # Network C2 patterns
        'encryption_with_deletion': 3.0,  # Ransomware-like behavior
        'injection_with_persistence': 2.5,  # Code injection + staying power
        'anti_analysis_evasion': 2.0,  # VM/debugger detection
        'suspicious_api_calls': 1.5,  # Individual suspicious APIs
        'high_entropy_section': 1.2,  # Packed/encrypted sections
        'registry_modification': 1.0,  # Registry changes
        'file_operations': 0.8,  # Normal file activity
        'network_connection': 0.7,  # Normal network activity
    }
    
    # Confidence thresholds for verdicts
    VERDICT_THRESHOLDS = {
        ThreatLevel.CRITICAL: 85,  # Very high confidence, multiple severe indicators
        ThreatLevel.MALICIOUS: 70,  # High confidence, clear malicious intent
        ThreatLevel.LIKELY_MALICIOUS: 50,  # Moderate confidence, suspicious patterns
        ThreatLevel.SUSPICIOUS: 30,  # Low confidence, some concerning behaviors
        ThreatLevel.CLEAN: 0,  # Below 30 = clean
    }
    
    # Indicator correlation rules
    CORRELATION_RULES = {
        'ransomware': {
            'required': ['file_encryption', 'mass_file_modification'],
            'supporting': ['extension_change', 'ransom_note', 'crypto_api'],
            'score_boost': 25,
            'confidence_threshold': 0.7
        },
        'trojan': {
            'required': ['network_beacon', 'command_execution'],
            'supporting': ['persistence', 'keylogging', 'screenshot'],
            'score_boost': 20,
            'confidence_threshold': 0.6
        },
        'rootkit': {
            'required': ['code_injection', 'driver_load'],
            'supporting': ['anti_debug', 'process_hiding', 'file_hiding'],
            'score_boost': 30,
            'confidence_threshold': 0.8
        },
        'spyware': {
            'required': ['data_collection', 'network_exfiltration'],
            'supporting': ['keylogging', 'screenshot', 'clipboard'],
            'score_boost': 18,
            'confidence_threshold': 0.65
        },
        'advanced_packing': {
            'required': ['high_entropy', 'packer_signature'],
            'supporting': ['anti_debug', 'vm_detection', 'obfuscation'],
            'score_boost': 15,
            'confidence_threshold': 0.6
        }
    }
    
    def __init__(self):
        """Initialize threat scorer"""
        self.evidence: List[ThreatEvidence] = []
        self.behavioral_patterns: Dict[str, int] = {}
        self.static_indicators: Dict[str, Any] = {}
        self.detections: List[Dict[str, Any]] = []
    
    def add_evidence(self, evidence: ThreatEvidence):
        """Add evidence to scoring calculation"""
        self.evidence.append(evidence)
    
    def add_detection(self, detection: Dict[str, Any]):
        """Add threat detection"""
        self.detections.append(detection)
        
        # Extract evidence from detection
        category = detection.get('threat_name', 'unknown').lower().replace(' ', '_')
        confidence = detection.get('confidence', 0) / 100.0
        severity = detection.get('severity', 'medium')
        
        evidence = ThreatEvidence(
            category=category,
            description=detection.get('description', ''),
            confidence=confidence,
            severity=severity,
            indicators=detection.get('evidence', []),
            weight=self._get_category_weight(category)
        )
        self.add_evidence(evidence)
    
    def add_behavioral_pattern(self, pattern: str):
        """Track behavioral pattern"""
        self.behavioral_patterns[pattern] = self.behavioral_patterns.get(pattern, 0) + 1
    
    def set_static_indicators(self, indicators: Dict[str, Any]):
        """Set static analysis indicators"""
        self.static_indicators = indicators
    
    def calculate_score(self) -> Tuple[int, ThreatLevel, float]:
        """
        Calculate final threat score with intelligence
        
        Returns:
            (score, threat_level, confidence)
        """
        if not self.evidence and not self.detections:
            return 0, ThreatLevel.CLEAN, 1.0
        
        # Base score from evidence
        base_score = self._calculate_base_score()
        
        # Apply correlation analysis
        correlation_boost = self._analyze_correlations()
        
        # Apply static analysis multipliers
        static_multiplier = self._calculate_static_multiplier()
        
        # Calculate final score
        raw_score = (base_score + correlation_boost) * static_multiplier
        final_score = min(int(raw_score), 100)
        
        # Determine threat level and confidence
        threat_level, confidence = self._determine_threat_level(final_score)
        
        # Apply false positive filters
        if self._is_likely_false_positive():
            final_score = max(0, final_score - 40)
            threat_level = ThreatLevel.CLEAN if final_score < 30 else ThreatLevel.SUSPICIOUS
            confidence *= 0.5
        
        return final_score, threat_level, confidence
    
    def _calculate_base_score(self) -> float:
        """Calculate base score from evidence"""
        score = 0.0
        
        for evidence in self.evidence:
            # Weight by confidence and severity
            severity_multiplier = {
                'critical': 1.0,
                'high': 0.7,
                'medium': 0.4,
                'low': 0.2,
                'info': 0.1
            }.get(evidence.severity, 0.3)
            
            evidence_score = (
                evidence.confidence * 
                evidence.weight * 
                severity_multiplier * 
                20  # Base points per evidence
            )
            
            score += evidence_score
        
        return score
    
    def _analyze_correlations(self) -> float:
        """Analyze indicator correlations for pattern matching"""
        boost = 0.0
        
        # Check each correlation rule
        for malware_type, rule in self.CORRELATION_RULES.items():
            required_count = sum(
                1 for req in rule['required']
                if req in self.behavioral_patterns or 
                any(req in e.category for e in self.evidence)
            )
            
            supporting_count = sum(
                1 for sup in rule['supporting']
                if sup in self.behavioral_patterns or
                any(sup in e.category for e in self.evidence)
            )
            
            # Must have all required indicators
            if required_count == len(rule['required']):
                # Calculate confidence based on supporting indicators
                support_ratio = supporting_count / len(rule['supporting']) if rule['supporting'] else 1.0
                
                if support_ratio >= rule['confidence_threshold']:
                    boost += rule['score_boost'] * support_ratio
        
        return boost
    
    def _calculate_static_multiplier(self) -> float:
        """Calculate multiplier from static analysis indicators"""
        multiplier = 1.0
        
        # Packer detection
        if self.static_indicators.get('packer_detected'):
            multiplier *= 1.3
        
        # High entropy
        if self.static_indicators.get('high_entropy_sections'):
            multiplier *= 1.2
        
        # Suspicious imports
        suspicious_apis = self.static_indicators.get('suspicious_api_count', 0)
        if suspicious_apis > 10:
            multiplier *= 1.4
        elif suspicious_apis > 5:
            multiplier *= 1.2
        
        # No digital signature
        if not self.static_indicators.get('has_signature'):
            multiplier *= 1.1
        
        # Suspicious strings
        suspicious_strings = self.static_indicators.get('suspicious_string_count', 0)
        if suspicious_strings > 5:
            multiplier *= 1.15
        
        return multiplier
    
    def _determine_threat_level(self, score: int) -> Tuple[ThreatLevel, float]:
        """Determine threat level from score"""
        # Calculate confidence based on evidence quality
        avg_confidence = sum(e.confidence for e in self.evidence) / len(self.evidence) if self.evidence else 0.5
        
        # Determine level
        for level in [ThreatLevel.CRITICAL, ThreatLevel.MALICIOUS, 
                      ThreatLevel.LIKELY_MALICIOUS, ThreatLevel.SUSPICIOUS]:
            if score >= self.VERDICT_THRESHOLDS[level]:
                return level, avg_confidence
        
        return ThreatLevel.CLEAN, avg_confidence
    
    def _is_likely_false_positive(self) -> bool:
        """Check for false positive indicators"""
        # Legitimate software patterns
        has_signature = self.static_indicators.get('has_signature', False)
        is_packed = self.static_indicators.get('packer_detected', False)
        
        # If digitally signed and not packed, less likely to be malicious
        if has_signature and not is_packed:
            # Check if only low-severity detections
            high_severity_count = sum(
                1 for e in self.evidence 
                if e.severity in ['critical', 'high']
            )
            if high_severity_count == 0:
                return True
        
        # Only registry/file operations without other suspicious behavior
        if len(self.evidence) <= 2:
            categories = [e.category for e in self.evidence]
            if all(cat in ['registry_modification', 'file_operations', 'network_connection'] 
                   for cat in categories):
                return True
        
        return False
    
    def _get_category_weight(self, category: str) -> float:
        """Get weight for evidence category"""
        for key, weight in self.WEIGHTS.items():
            if key in category:
                return weight
        return 1.0
    
    def get_detailed_breakdown(self) -> Dict[str, Any]:
        """Get detailed scoring breakdown for reporting"""
        score, level, confidence = self.calculate_score()
        
        return {
            'final_score': score,
            'threat_level': level.value,
            'confidence': confidence,
            'evidence_count': len(self.evidence),
            'detection_count': len(self.detections),
            'behavioral_patterns': dict(self.behavioral_patterns),
            'evidence_by_severity': self._group_evidence_by_severity(),
            'correlation_matches': self._get_correlation_matches(),
            'static_indicators': self.static_indicators
        }
    
    def _group_evidence_by_severity(self) -> Dict[str, int]:
        """Group evidence by severity level"""
        groups = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for evidence in self.evidence:
            groups[evidence.severity] = groups.get(evidence.severity, 0) + 1
        return groups
    
    def _get_correlation_matches(self) -> List[str]:
        """Get list of matched correlation patterns"""
        matches = []
        
        for malware_type, rule in self.CORRELATION_RULES.items():
            required_count = sum(
                1 for req in rule['required']
                if req in self.behavioral_patterns or 
                any(req in e.category for e in self.evidence)
            )
            
            if required_count == len(rule['required']):
                matches.append(malware_type)
        
        return matches
