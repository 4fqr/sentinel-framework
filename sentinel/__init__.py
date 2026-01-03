"""
Sentinel Framework - Open-source malware analysis sandbox
"""

__version__ = "1.0.0"
__author__ = "Sentinel Framework Contributors"
__license__ = "MIT"

from sentinel.core.sandbox import SandboxEngine
from sentinel.core.monitor import BehaviorMonitor
from sentinel.core.analyzer import MalwareAnalyzer
from sentinel.core.reporter import ReportGenerator
from sentinel.core.events import BehaviorEvent, EventType, EventSeverity

__all__ = [
    "SandboxEngine",
    "BehaviorMonitor",
    "MalwareAnalyzer",
    "ReportGenerator",
    "BehaviorEvent",
    "EventType",
    "EventSeverity",
]
