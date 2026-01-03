"""
Example: Simple malware analysis with Sentinel Framework
"""

from sentinel.core.analyzer import MalwareAnalyzer
from sentinel.core.reporter import ReportGenerator


def main():
    """Simple analysis example"""
    
    # Initialize analyzer
    analyzer = MalwareAnalyzer()
    
    # Analyze sample
    sample_path = "path/to/suspicious_file.exe"
    result = analyzer.analyze(sample_path)
    
    # Display verdict
    print(f"Verdict: {result.verdict}")
    print(f"Risk Score: {result.risk_score}/100")
    
    # Generate report
    reporter = ReportGenerator()
    report_path = reporter.generate(result, format='html')
    print(f"Report: {report_path}")
    
    # Cleanup
    analyzer.cleanup()


if __name__ == '__main__':
    main()
