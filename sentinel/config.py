"""
Sentinel Framework - Configuration Manager
Handles loading and validation of configuration settings
"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
import logging


class ConfigurationError(Exception):
    """Raised when configuration is invalid or missing"""
    pass


class Config:
    """Centralized configuration management for Sentinel Framework"""
    
    _instance: Optional['Config'] = None
    _config: Dict[str, Any] = {}
    
    def __new__(cls) -> 'Config':
        """Singleton pattern to ensure single configuration instance"""
        if cls._instance is None:
            cls._instance = super(Config, cls).__new__(cls)
        return cls._instance
    
    def __init__(self) -> None:
        """Initialize configuration manager"""
        if not self._config:
            self.load_config()
    
    def load_config(self, config_path: Optional[str] = None) -> None:
        """
        Load configuration from YAML file
        
        Args:
            config_path: Path to configuration file. If None, uses default path.
        
        Raises:
            ConfigurationError: If configuration file is invalid or missing
        """
        if config_path is None:
            # Try multiple default locations
            possible_paths = [
                Path(__file__).parent.parent.parent / "config" / "sentinel.yaml",
                Path.cwd() / "config" / "sentinel.yaml",
                Path.home() / ".sentinel" / "config.yaml",
            ]
            
            for path in possible_paths:
                if path.exists():
                    config_path = str(path)
                    break
            else:
                # Use default configuration
                self._config = self._get_default_config()
                logging.warning("No config file found, using default configuration")
                return
        
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                self._config = yaml.safe_load(f)
            
            self._validate_config()
            logging.info(f"Configuration loaded from {config_path}")
            
        except Exception as e:
            raise ConfigurationError(f"Failed to load configuration: {e}")
    
    def _validate_config(self) -> None:
        """Validate configuration structure and values"""
        required_sections = ['sandbox', 'monitoring', 'analysis', 'reporting']
        
        for section in required_sections:
            if section not in self._config:
                raise ConfigurationError(f"Missing required section: {section}")
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Return default configuration"""
        return {
            'sandbox': {
                'type': 'docker',
                'timeout': 300,
                'network_mode': 'isolated',
                'snapshot_enabled': True,
                'restore_on_exit': True,
            },
            'monitoring': {
                'file_system': {'enabled': True},
                'process': {'enabled': True},
                'registry': {'enabled': True},
                'network': {'enabled': True},
            },
            'analysis': {
                'static_analysis': True,
                'dynamic_analysis': True,
                'detection': {
                    'ransomware': {'enabled': True},
                    'c2_communication': {'enabled': True},
                    'code_injection': {'enabled': True},
                },
            },
            'reporting': {
                'format': 'html',
                'output_dir': 'reports',
                'verbosity': 'detailed',
            },
            'logging': {
                'level': 'INFO',
                'file': 'logs/sentinel.log',
            },
        }
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation
        
        Args:
            key: Configuration key (e.g., 'sandbox.timeout')
            default: Default value if key not found
        
        Returns:
            Configuration value
        """
        keys = key.split('.')
        value = self._config
        
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
                if value is None:
                    return default
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any) -> None:
        """
        Set configuration value using dot notation
        
        Args:
            key: Configuration key (e.g., 'sandbox.timeout')
            value: Value to set
        """
        keys = key.split('.')
        config = self._config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
    
    def get_section(self, section: str) -> Dict[str, Any]:
        """
        Get entire configuration section
        
        Args:
            section: Section name (e.g., 'sandbox')
        
        Returns:
            Dictionary containing section configuration
        """
        return self._config.get(section, {})
    
    @property
    def sandbox_config(self) -> Dict[str, Any]:
        """Get sandbox configuration"""
        return self.get_section('sandbox')
    
    @property
    def monitoring_config(self) -> Dict[str, Any]:
        """Get monitoring configuration"""
        return self.get_section('monitoring')
    
    @property
    def analysis_config(self) -> Dict[str, Any]:
        """Get analysis configuration"""
        return self.get_section('analysis')
    
    @property
    def reporting_config(self) -> Dict[str, Any]:
        """Get reporting configuration"""
        return self.get_section('reporting')
    
    @property
    def logging_config(self) -> Dict[str, Any]:
        """Get logging configuration"""
        return self.get_section('logging')


# Global configuration instance
config = Config()
