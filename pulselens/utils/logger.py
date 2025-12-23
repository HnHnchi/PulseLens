#!/usr/bin/env python3
"""
PulseLens Logging Utility
Provides centralized logging configuration and utilities
"""

import logging
import logging.handlers
import sys
import os
from pathlib import Path
from datetime import datetime
from typing import Optional
import json


class PulseLensLogger:
    """Centralized logging system for PulseLens."""
    
    def __init__(self, name: str = "pulselens", log_level: str = "INFO", 
                 log_file: Optional[str] = None, max_log_size: int = 10*1024*1024):
        """
        Initialize the logger.
        
        Args:
            name: Logger name
            log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            log_file: Optional log file path
            max_log_size: Maximum log file size in bytes before rotation
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, log_level.upper()))
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # Create formatters
        self.detailed_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(module)s:%(lineno)d - %(message)s'
        )
        self.simple_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(getattr(logging, log_level.upper()))
        console_handler.setFormatter(self.simple_formatter)
        self.logger.addHandler(console_handler)
        
        # File handler with rotation
        if log_file:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            file_handler = logging.handlers.RotatingFileHandler(
                log_file, maxBytes=max_log_size, backupCount=5
            )
            file_handler.setLevel(logging.DEBUG)  # Always log DEBUG to file
            file_handler.setFormatter(self.detailed_formatter)
            self.logger.addHandler(file_handler)
    
    def get_logger(self) -> logging.Logger:
        """Get the configured logger instance."""
        return self.logger
    
    def log_api_request(self, method: str, endpoint: str, status_code: int, 
                       duration: float, user_agent: str = ""):
        """Log API request details."""
        self.logger.info(
            f"API Request: {method} {endpoint} - {status_code} - {duration:.3f}s - {user_agent}"
        )
    
    def log_ioc_processing(self, ioc_count: int, processing_time: float, 
                          errors: int = 0):
        """Log IOC processing metrics."""
        self.logger.info(
            f"IOC Processing: {ioc_count} IOCs processed in {processing_time:.3f}s - {errors} errors"
        )
    
    def log_database_operation(self, operation: str, table: str, 
                              affected_rows: int = 0, duration: float = 0):
        """Log database operations."""
        self.logger.debug(
            f"DB Operation: {operation} on {table} - {affected_rows} rows in {duration:.3f}s"
        )
    
    def log_error_with_context(self, error: Exception, context: dict = None):
        """Log error with additional context."""
        error_info = {
            "error_type": type(error).__name__,
            "error_message": str(error),
            "timestamp": datetime.now().isoformat()
        }
        
        if context:
            error_info.update(context)
        
        self.logger.error(f"Error occurred: {json.dumps(error_info, indent=2)}")
    
    def log_performance_metric(self, metric_name: str, value: float, unit: str = ""):
        """Log performance metrics."""
        self.logger.info(f"Performance: {metric_name} = {value}{unit}")


class StructuredLogger:
    """Structured JSON logger for machine-readable logs."""
    
    def __init__(self, name: str = "pulselens_structured"):
        """Initialize structured logger."""
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        
        # Create JSON formatter
        self.formatter = logging.Formatter(
            '%(message)s'  # Only the JSON message
        )
        
        # Console handler for structured logs
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(self.formatter)
        self.logger.addHandler(handler)
    
    def log(self, level: str, event: str, data: dict = None):
        """Log structured event."""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "event": event,
            "level": level.lower()
        }
        
        if data:
            log_entry.update(data)
        
        getattr(self.logger, level.lower())(json.dumps(log_entry))
    
    def info(self, event: str, data: dict = None):
        """Log info level structured event."""
        self.log("INFO", event, data)
    
    def error(self, event: str, data: dict = None):
        """Log error level structured event."""
        self.log("ERROR", event, data)
    
    def warning(self, event: str, data: dict = None):
        """Log warning level structured event."""
        self.log("WARNING", event, data)


# Global logger instances
_pulselens_logger = None
_structured_logger = None


def get_logger(name: str = "pulselens") -> logging.Logger:
    """Get global PulseLens logger."""
    global _pulselens_logger
    if _pulselens_logger is None:
        try:
            import sys
            from pathlib import Path
            sys.path.insert(0, str(Path(__file__).parent.parent.parent))
            import config
            LOG_LEVEL = getattr(config, 'LOG_LEVEL', 'INFO')
            LOG_FILE = getattr(config, 'LOG_FILE', None)
        except ImportError:
            LOG_LEVEL = 'INFO'
            LOG_FILE = None
        
        _pulselens_logger = PulseLensLogger(
            name=name, 
            log_level=LOG_LEVEL, 
            log_file=LOG_FILE
        )
    return _pulselens_logger.get_logger()


def get_structured_logger() -> StructuredLogger:
    """Get global structured logger."""
    global _structured_logger
    if _structured_logger is None:
        _structured_logger = StructuredLogger()
    return _structured_logger


def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None):
    """Setup global logging configuration."""
    global _pulselens_logger, _structured_logger
    _pulselens_logger = PulseLensLogger(log_level=log_level, log_file=log_file)
    _structured_logger = StructuredLogger()


# Decorator for automatic error logging
def log_errors(logger: Optional[logging.Logger] = None):
    """Decorator to automatically log function errors."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                log = logger or get_logger()
                log.log_error_with_context(e, {
                    "function": func.__name__,
                    "args_count": len(args),
                    "kwargs_keys": list(kwargs.keys())
                })
                raise
        return wrapper
    return decorator


# Context manager for performance logging
class PerformanceLogger:
    """Context manager for timing operations."""
    
    def __init__(self, operation_name: str, logger: Optional[logging.Logger] = None):
        self.operation_name = operation_name
        self.logger = logger or get_logger()
        self.start_time = None
    
    def __enter__(self):
        self.start_time = datetime.now()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = (datetime.now() - self.start_time).total_seconds()
        
        if hasattr(self.logger, 'log_performance_metric'):
            self.logger.log_performance_metric(self.operation_name, duration, "s")
        else:
            self.logger.info(f"Performance: {self.operation_name} = {duration}s")
        
        if exc_type:
            if hasattr(self.logger, 'error'):
                self.logger.error(f"Operation '{self.operation_name}' failed after {duration:.3f}s")
            else:
                print(f"Operation '{self.operation_name}' failed after {duration:.3f}s")
        else:
            if hasattr(self.logger, 'info'):
                self.logger.info(f"Operation '{self.operation_name}' completed in {duration:.3f}s")
            else:
                print(f"Operation '{self.operation_name}' completed in {duration:.3f}s")
