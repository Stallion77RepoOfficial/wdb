#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Utility functions for WDB - Performance monitoring, validation, and helper functions"""

import os
import time
import psutil
import hashlib
from typing import Dict, Any, Optional, Union
from pathlib import Path


class PerformanceMonitor:
    """Monitor performance metrics during debugging sessions"""
    
    def __init__(self):
        self.start_time = time.time()
        self.metrics = {
            'events_processed': 0,
            'memory_reads': 0,
            'pe_parses': 0,
            'exports_cached': 0,
            'peak_memory_mb': 0,
            'total_memory_read_bytes': 0
        }
        self.process = psutil.Process()
    
    def update_memory_usage(self):
        """Update peak memory usage"""
        try:
            memory_mb = self.process.memory_info().rss / 1024 / 1024
            self.metrics['peak_memory_mb'] = max(self.metrics['peak_memory_mb'], memory_mb)
        except Exception:
            pass
    
    def increment(self, metric: str, value: int = 1):
        """Increment a metric counter"""
        if metric in self.metrics:
            self.metrics[metric] += value
    
    def get_summary(self) -> Dict[str, Any]:
        """Get performance summary"""
        runtime = time.time() - self.start_time
        self.update_memory_usage()
        
        return {
            'runtime_seconds': round(runtime, 2),
            'events_per_second': round(self.metrics['events_processed'] / max(runtime, 0.1), 2),
            'memory_efficiency_mb_per_event': round(
                self.metrics['peak_memory_mb'] / max(self.metrics['events_processed'], 1), 3
            ),
            **self.metrics
        }


class PathValidator:
    """Validate and normalize file paths"""
    
    @staticmethod
    def is_safe_path(path: str, base_path: Optional[str] = None) -> bool:
        """Check if path is safe (no directory traversal)"""
        try:
            if base_path:
                abs_path = os.path.abspath(os.path.join(base_path, path))
                abs_base = os.path.abspath(base_path)
                return abs_path.startswith(abs_base)
            else:
                # Basic checks for suspicious patterns
                suspicious = ['../', '..\\', '/etc/', '/proc/', 'C:\\Windows\\System32']
                return not any(pattern in path.lower() for pattern in suspicious)
        except Exception:
            return False
    
    @staticmethod
    def normalize_wine_path(path: str) -> str:
        """Convert Unix path to Windows path for Wine"""
        if not path:
            return path
        
        # Handle drive_c paths
        if '/drive_c/' in path.lower():
            after = path.split('drive_c/', 1)[1]
            return f"C:\\{after.replace('/', '\\')}"
        
        # Handle other Unix-style paths
        if path.startswith('/') and '\\' not in path:
            return f"Z:{path.replace('/', '\\')}"
        
        return path
    
    @staticmethod
    def validate_executable_path(path: str) -> bool:
        """Validate that path points to a potential executable"""
        if not path:
            return False
        
        lower_path = path.lower()
        valid_extensions = ['.exe', '.com', '.bat', '.cmd', '.scr']
        return any(lower_path.endswith(ext) for ext in valid_extensions)


class FileHasher:
    """Compute file hashes for caching and integrity checking"""
    
    @staticmethod
    def compute_file_hash(filepath: str, algorithm: str = 'sha256') -> Optional[str]:
        """Compute hash of file contents"""
        try:
            hash_obj = hashlib.new(algorithm)
            with open(filepath, 'rb') as f:
                while chunk := f.read(8192):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except Exception:
            return None
    
    @staticmethod
    def compute_pe_header_hash(filepath: str) -> Optional[str]:
        """Compute hash of PE header for quick PE file identification"""
        try:
            with open(filepath, 'rb') as f:
                # Read DOS header + PE header (first 1KB should be enough)
                header_data = f.read(1024)
                if len(header_data) < 64 or header_data[:2] != b'MZ':
                    return None
                return hashlib.sha256(header_data).hexdigest()[:16]
        except Exception:
            return None


class ResourceMonitor:
    """Monitor system resources during debugging"""
    
    def __init__(self, wine_pid: Optional[int] = None):
        self.wine_pid = wine_pid
        self.initial_stats = self._get_stats()
    
    def _get_stats(self) -> Dict[str, Any]:
        """Get current system stats"""
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            stats = {
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'memory_available_mb': memory.available / 1024 / 1024,
                'disk_free_gb': disk.free / 1024 / 1024 / 1024
            }
            
            # Add Wine process stats if available
            if self.wine_pid:
                try:
                    wine_process = psutil.Process(self.wine_pid)
                    stats['wine_memory_mb'] = wine_process.memory_info().rss / 1024 / 1024
                    stats['wine_cpu_percent'] = wine_process.cpu_percent()
                except Exception:
                    pass
            
            return stats
        except Exception:
            return {}
    
    def get_resource_usage(self) -> Dict[str, Any]:
        """Get current resource usage vs initial"""
        current = self._get_stats()
        if not self.initial_stats or not current:
            return current
        
        # Calculate deltas
        result = current.copy()
        for key in ['memory_percent', 'cpu_percent']:
            if key in self.initial_stats and key in current:
                result[f'{key}_delta'] = current[key] - self.initial_stats[key]
        
        return result
    
    def check_resource_limits(self) -> Dict[str, bool]:
        """Check if resource usage exceeds safe limits"""
        stats = self._get_stats()
        if not stats:
            return {}
        
        return {
            'memory_critical': stats.get('memory_percent', 0) > 90,
            'cpu_high': stats.get('cpu_percent', 0) > 80,
            'disk_low': stats.get('disk_free_gb', float('inf')) < 1.0,
            'wine_memory_high': stats.get('wine_memory_mb', 0) > 1024
        }


def format_bytes(bytes_count: int) -> str:
    """Format byte count in human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_count < 1024:
            return f"{bytes_count:.1f} {unit}"
        bytes_count /= 1024
    return f"{bytes_count:.1f} TB"


def format_duration(seconds: float) -> str:
    """Format duration in human readable format"""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{int(seconds // 60)}m {int(seconds % 60)}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"


def validate_wine_environment() -> Dict[str, bool]:
    """Validate Wine environment prerequisites"""
    checks = {}
    
    # Check if Wine is installed
    try:
        import subprocess
        result = subprocess.run(['wine', '--version'], capture_output=True, text=True, timeout=10)
        checks['wine_installed'] = result.returncode == 0
        if checks['wine_installed']:
            checks['wine_version'] = result.stdout.strip()
    except Exception:
        checks['wine_installed'] = False
    
    # Check if required Python modules are available
    required_modules = ['ctypes', 'json', 'datetime', 'csv']
    checks['python_modules'] = all(
        __import__(module) for module in required_modules 
        if not module.startswith('_')
    )
    
    return checks


def estimate_memory_usage(max_events: int, mem_bytes: int, stack_bytes: int, 
                         code_window: int, resolve_exports: bool) -> Dict[str, int]:
    """Estimate memory usage for debugging session"""
    base_event_size = 1024  # Base JSON event size in bytes
    
    # Event storage
    event_memory = max_events * base_event_size
    
    # Memory dumps
    memory_dump_size = max_events * mem_bytes if mem_bytes > 0 else 0
    stack_dump_size = max_events * stack_bytes if stack_bytes > 0 else 0
    code_window_size = max_events * code_window if code_window > 0 else 0
    
    # Export cache (estimated)
    export_cache_size = 50 * 1024 * 1024 if resolve_exports else 0  # 50MB estimate
    
    total_mb = (
        event_memory + memory_dump_size + stack_dump_size + 
        code_window_size + export_cache_size
    ) / 1024 / 1024
    
    return {
        'total_mb': int(total_mb),
        'events_mb': int(event_memory / 1024 / 1024),
        'memory_dumps_mb': int(memory_dump_size / 1024 / 1024),
        'stack_dumps_mb': int(stack_dump_size / 1024 / 1024),
        'code_windows_mb': int(code_window_size / 1024 / 1024),
        'export_cache_mb': int(export_cache_size / 1024 / 1024)
    }
