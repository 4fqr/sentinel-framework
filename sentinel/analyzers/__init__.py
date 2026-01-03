"""
File-specific analyzers for comprehensive malware detection
"""

from .archive_analyzer import ArchiveAnalyzer
from .document_analyzer import DocumentAnalyzer

__all__ = ['ArchiveAnalyzer', 'DocumentAnalyzer']
