"""Unit tests for Sentinel Framework"""

import pytest
from sentinel.core.sandbox import SandboxEngine, SandboxState
from sentinel.core.monitor import BehaviorMonitor, EventType, EventSeverity
from sentinel.config import config


class TestSandbox:
    """Test sandbox engine"""
    
    def test_initialization(self):
        """Test sandbox initialization"""
        sandbox = SandboxEngine()
        assert sandbox.state == SandboxState.IDLE
        assert sandbox.timeout > 0
    
    def test_get_status(self):
        """Test status retrieval"""
        sandbox = SandboxEngine()
        status = sandbox.get_status()
        assert 'type' in status
        assert 'state' in status


class TestMonitor:
    """Test behavior monitor"""
    
    def test_initialization(self):
        """Test monitor initialization"""
        monitor = BehaviorMonitor()
        assert not monitor.is_monitoring
        assert len(monitor.events) == 0
    
    def test_start_stop(self):
        """Test starting and stopping monitor"""
        monitor = BehaviorMonitor()
        monitor.start()
        assert monitor.is_monitoring
        monitor.stop()
        assert not monitor.is_monitoring
    
    def test_event_filtering(self):
        """Test event filtering"""
        monitor = BehaviorMonitor()
        # Add test events here
        events = monitor.get_events(severity=EventSeverity.HIGH)
        assert isinstance(events, list)


class TestConfig:
    """Test configuration"""
    
    def test_config_loading(self):
        """Test configuration loading"""
        sandbox_config = config.sandbox_config
        assert 'type' in sandbox_config
        assert 'timeout' in sandbox_config
    
    def test_config_get(self):
        """Test configuration getter"""
        timeout = config.get('sandbox.timeout', 300)
        assert isinstance(timeout, int)
        assert timeout > 0


if __name__ == '__main__':
    pytest.main([__file__])
