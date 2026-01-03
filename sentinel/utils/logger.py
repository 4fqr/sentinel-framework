"""
Sentinel Framework - Logging System
Configurable logging with rich formatting and file rotation
"""

import logging
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler
from typing import Optional
from rich.logging import RichHandler
from rich.console import Console

from sentinel.config import config


class SentinelLogger:
    """Centralized logging system for Sentinel Framework"""
    
    _initialized: bool = False
    
    @classmethod
    def setup(cls, log_level: Optional[str] = None) -> None:
        """
        Setup logging system with file and console handlers
        
        Args:
            log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
        """
        if cls._initialized:
            return
        
        # Get configuration
        log_config = config.logging_config
        level = log_level or log_config.get('level', 'INFO')
        log_file = log_config.get('file', 'logs/sentinel.log')
        max_size_mb = log_config.get('max_size_mb', 100)
        backup_count = log_config.get('backup_count', 5)
        
        # Create logs directory
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(getattr(logging, level))
        
        # Remove existing handlers
        root_logger.handlers.clear()
        
        # Create console handler with rich formatting
        console_handler = RichHandler(
            console=Console(stderr=True),
            show_time=True,
            show_path=False,
            markup=True,
            rich_tracebacks=True,
            tracebacks_show_locals=True,
        )
        console_handler.setLevel(getattr(logging, level))
        console_format = logging.Formatter(
            "%(message)s",
            datefmt="[%X]"
        )
        console_handler.setFormatter(console_format)
        
        # Create file handler with rotation
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_size_mb * 1024 * 1024,
            backupCount=backup_count,
            encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)
        file_format = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_format)
        
        # Add handlers
        root_logger.addHandler(console_handler)
        root_logger.addHandler(file_handler)
        
        cls._initialized = True
        
        logging.info("Sentinel Framework logging system initialized")
    
    @classmethod
    def get_logger(cls, name: str) -> logging.Logger:
        """
        Get logger instance for module
        
        Args:
            name: Logger name (typically __name__)
        
        Returns:
            Logger instance
        """
        if not cls._initialized:
            cls.setup()
        
        return logging.getLogger(name)


def get_logger(name: str) -> logging.Logger:
    """
    Convenience function to get logger
    
    Args:
        name: Logger name
    
    Returns:
        Logger instance
    """
    return SentinelLogger.get_logger(name)
