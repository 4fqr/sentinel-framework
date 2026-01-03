"""
Example: Custom threat detection with Sentinel Framework
"""

from sentinel.core.analyzer import MalwareAnalyzer
from sentinel.core.monitor import BehaviorEvent, EventType
from typing import List, Dict, Any


class CustomDetector:
    """Example custom threat detector"""
    
    def detect(self, events: List[BehaviorEvent], analysis_result: Any) -> List[Dict[str, Any]]:
        """Implement custom detection logic"""
        detections = []
        
        # Example: Detect Bitcoin wallet addresses in created files
        for event in events:
            if event.event_type == EventType.FILE_CREATED:
                path = event.data.get('path', '')
                if 'bitcoin' in path.lower() or 'wallet' in path.lower():
                    detections.append({
                        'threat_type': 'Cryptocurrency',
                        'technique': 'Wallet File Creation',
                        'description': f'Detected potential cryptocurrency wallet file: {path}',
                        'confidence': 70,
                        'severity': 'medium',
                        'indicators': {'file': path}
                    })
        
        return detections


def main():
    """Custom detector example"""
    
    # Initialize analyzer
    analyzer = MalwareAnalyzer()
    
    # Add custom detector
    custom_detector = CustomDetector()
    analyzer.detectors.append(custom_detector)
    
    # Analyze sample
    result = analyzer.analyze("path/to/sample.exe")
    
    # Display detections
    print(f"Total detections: {len(result.threat_detections)}")
    for detection in result.threat_detections:
        print(f"- {detection['threat_type']}: {detection['technique']}")
    
    # Cleanup
    analyzer.cleanup()


if __name__ == '__main__':
    main()
