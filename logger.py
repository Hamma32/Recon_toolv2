"""
Advanced Logging System for Recon Tool
Provides structured logging with rotation, session management, and export capabilities
"""

import logging
import os
import json
import csv
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path


class ReconLogger:
    """Centralized logging system with multiple handlers and export capabilities"""
    
    def __init__(self, log_dir="logs", max_bytes=10*1024*1024, backup_count=5):
        """
        Initialize the logging system
        
        Args:
            log_dir: Directory to store log files
            max_bytes: Maximum size per log file (default 10MB)
            backup_count: Number of backup files to keep
        """
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        # Create session-based log filename
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = self.log_dir / f"session_{self.session_id}.log"
        
        # Setup logger
        self.logger = logging.getLogger("ReconTool")
        self.logger.setLevel(logging.DEBUG)
        self.logger.handlers.clear()  # Clear any existing handlers
        
        # File handler with rotation
        file_handler = RotatingFileHandler(
            self.log_file,
            maxBytes=max_bytes,
            backupCount=backup_count
        )
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        self.logger.addHandler(file_handler)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter(
            '%(levelname)s: %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
        # Event storage for export
        self.events = []
        
        self.logger.info(f"Logging session started: {self.session_id}")
    
    def log_event(self, level, category, message, **kwargs):
        """
        Log an event with structured data
        
        Args:
            level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            category: Event category (SCAN, ATTACK, NETWORK, UI, SYSTEM)
            message: Log message
            **kwargs: Additional structured data
        """
        event = {
            'timestamp': datetime.now().isoformat(),
            'level': level,
            'category': category,
            'message': message,
            **kwargs
        }
        self.events.append(event)
        
        # Log to standard logger
        log_func = getattr(self.logger, level.lower())
        log_func(f"[{category}] {message}")
    
    def debug(self, category, message, **kwargs):
        """Log debug message"""
        self.log_event('DEBUG', category, message, **kwargs)
    
    def info(self, category, message, **kwargs):
        """Log info message"""
        self.log_event('INFO', category, message, **kwargs)
    
    def warning(self, category, message, **kwargs):
        """Log warning message"""
        self.log_event('WARNING', category, message, **kwargs)
    
    def error(self, category, message, **kwargs):
        """Log error message"""
        self.log_event('ERROR', category, message, **kwargs)
    
    def critical(self, category, message, **kwargs):
        """Log critical message"""
        self.log_event('CRITICAL', category, message, **kwargs)
    
    def export_to_json(self, filepath=None):
        """
        Export logs to JSON format
        
        Args:
            filepath: Output file path (default: logs/session_ID_export.json)
        """
        if filepath is None:
            filepath = self.log_dir / f"session_{self.session_id}_export.json"
        
        with open(filepath, 'w') as f:
            json.dump({
                'session_id': self.session_id,
                'events': self.events
            }, f, indent=2)
        
        self.logger.info(f"Logs exported to JSON: {filepath}")
        return filepath
    
    def export_to_csv(self, filepath=None):
        """
        Export logs to CSV format
        
        Args:
            filepath: Output file path (default: logs/session_ID_export.csv)
        """
        if filepath is None:
            filepath = self.log_dir / f"session_{self.session_id}_export.csv"
        
        if not self.events:
            self.logger.warning("No events to export")
            return None
        
        # Get all unique keys from events
        fieldnames = set()
        for event in self.events:
            fieldnames.update(event.keys())
        fieldnames = sorted(list(fieldnames))
        
        with open(filepath, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(self.events)
        
        self.logger.info(f"Logs exported to CSV: {filepath}")
        return filepath
    
    def get_events_by_category(self, category):
        """Get all events for a specific category"""
        return [e for e in self.events if e.get('category') == category]
    
    def get_events_by_level(self, level):
        """Get all events for a specific level"""
        return [e for e in self.events if e.get('level') == level]
    
    def get_recent_events(self, count=50):
        """Get the most recent N events"""
        return self.events[-count:]
    
    def clear_events(self):
        """Clear stored events (keeps file logs)"""
        self.events.clear()
        self.logger.info("Event buffer cleared")


# Global logger instance
_global_logger = None

def get_logger():
    """Get or create the global logger instance"""
    global _global_logger
    if _global_logger is None:
        _global_logger = ReconLogger()
    return _global_logger

def init_logger(log_dir="logs", max_bytes=10*1024*1024, backup_count=5):
    """Initialize the global logger with custom settings"""
    global _global_logger
    _global_logger = ReconLogger(log_dir, max_bytes, backup_count)
    return _global_logger
