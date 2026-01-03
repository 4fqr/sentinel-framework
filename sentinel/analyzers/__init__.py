"""
File-specific analyzers for comprehensive malware detection
"""

from .pe_analyzer import PEAnalyzer
from .archive_analyzer import ArchiveAnalyzer
from .document_analyzer import DocumentAnalyzer
from .script_analyzer import ScriptAnalyzer

__all__ = ['PEAnalyzer', 'ArchiveAnalyzer', 'DocumentAnalyzer', 'ScriptAnalyzer']
