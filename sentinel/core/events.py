"""
Sentinel Framework - Event Types
Event definitions used across monitoring subsystems
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class EventType(Enum):
    """Types of behavioral events"""
    FILE_CREATED = "file_created"
    FILE_MODIFIED = "file_modified"
    FILE_DELETED = "file_deleted"
    FILE_RENAMED = "file_renamed"
    PROCESS_CREATED = "process_created"
    PROCESS_TERMINATED = "process_terminated"
    PROCESS_INJECTION = "process_injection"
    REGISTRY_CREATED = "registry_created"
    REGISTRY_MODIFIED = "registry_modified"
    REGISTRY_DELETED = "registry_deleted"
    NETWORK_CONNECTION = "network_connection"
    NETWORK_DNS = "network_dns"
    NETWORK_HTTP = "network_http"


class EventSeverity(Enum):
    """Event severity levels"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class BehaviorEvent:
    """Represents a single behavioral event"""
    event_type: EventType
    timestamp: float
    severity: EventSeverity
    data: Dict[str, Any]
    process_id: Optional[int] = None
    process_name: Optional[str] = None
    description: str = ""
    tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary"""
        return {
            'event_type': self.event_type.value,
            'timestamp': self.timestamp,
            'datetime': datetime.fromtimestamp(self.timestamp).isoformat(),
            'severity': self.severity.value,
            'process_id': self.process_id,
            'process_name': self.process_name,
            'description': self.description,
            'data': self.data,
            'tags': self.tags,
        }
