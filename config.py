#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Configuration loader for WDB
"""

import os
import configparser
import logging
from typing import Dict, Any, Optional


class Config:
    """Enhanced configuration manager with validation and caching."""

    def __init__(self, config_path: str = "wdb.conf"):
        self.config_path = config_path
        self.config = configparser.ConfigParser()
        self._cache = {}  # Cache for expensive operations
        self._setup_logging()
        self._load_config()

    def _setup_logging(self):
        """Setup basic logging for config operations"""
        logging.basicConfig(level=logging.WARNING, format='%(levelname)s: %(message)s')
        self.logger = logging.getLogger(__name__)

    def _load_config(self):
        """Load configuration with error handling"""
        self._defaults()
        if os.path.exists(self.config_path):
            try:
                self.config.read(self.config_path, encoding='utf-8')
                self._validate_config()
            except configparser.Error as e:
                self.logger.warning(f"Config file error: {e}")
            except Exception as e:
                self.logger.warning(f"Failed to read config: {e}")
        else:
            self.save()

    def _validate_config(self):
        """Validate configuration values"""
        try:
            # Validate wine_prefix exists
            wine_prefix = self.get_wine_prefix()
            if not os.path.exists(wine_prefix):
                self.logger.warning(f"Wine prefix path does not exist: {wine_prefix}")
            
            # Validate Python executable path format
            python_exe = self.get_wine_python()
            if not python_exe.endswith('.exe'):
                self.logger.warning(f"Wine Python path should end with .exe: {python_exe}")
                
        except Exception as e:
            self.logger.warning(f"Config validation error: {e}")

    def _defaults(self):
        """Set default configuration values"""
        sections = {
            'wine': {
                'wine_prefix': '~/.wine-wdb',
                'wine_python': 'C:\\Python311\\python.exe',
                'wine_path': '/usr/local/bin/wine'
            },
            'debug': {
                'output_file': 'events.jsonl',
                'timeout': '1000',
                'max_events': '50'
            },
            'logging': {
                'verbose': 'false',
                'log_file': 'wdb.log'
            },
            'performance': {
                'cache_exports': 'true',
                'max_memory_dump': '1048576',
                'max_code_window': '4096'
            }
        }
        
        for section_name, options in sections.items():
            if not self.config.has_section(section_name):
                self.config.add_section(section_name)
            for key, value in options.items():
                self.config.set(section_name, key, value)

    def save(self):
        """Save configuration with error handling"""
        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                self.config.write(f)
        except Exception as e:
            self.logger.error(f"Failed to save config: {e}")

    def get_wine_prefix(self) -> str:
        """Get Wine prefix path with caching"""
        cache_key = 'wine_prefix'
        if cache_key not in self._cache:
            path = self.config.get('wine', 'wine_prefix', fallback='~/.wine-wdb')
            self._cache[cache_key] = os.path.expanduser(path)
        return self._cache[cache_key]

    def get_wine_python(self) -> str:
        return self.config.get('wine', 'wine_python', fallback='C:\\Python311\\python.exe')

    def get_wine_path(self) -> str:
        return self.config.get('wine', 'wine_path', fallback='/usr/local/bin/wine')

    def get_output_file(self) -> str:
        return self.config.get('debug', 'output_file', fallback='events.jsonl')

    def get_timeout(self) -> int:
        return self.config.getint('debug', 'timeout', fallback=1000)

    def get_max_events(self) -> int:
        return self.config.getint('debug', 'max_events', fallback=50)

    def get_verbose(self) -> bool:
        return self.config.getboolean('logging', 'verbose', fallback=False)

    def get_log_file(self) -> Optional[str]:
        return self.config.get('logging', 'log_file', fallback=None)

    def get_cache_exports(self) -> bool:
        return self.config.getboolean('performance', 'cache_exports', fallback=True)

    def get_max_memory_dump(self) -> int:
        return self.config.getint('performance', 'max_memory_dump', fallback=1048576)

    def get_max_code_window(self) -> int:
        return self.config.getint('performance', 'max_code_window', fallback=4096)

    def set_verbose(self, value: bool):
        self.config.set('logging', 'verbose', 'true' if value else 'false')
        self.save()

    def update_setting(self, section: str, key: str, value: str):
        """Update a configuration setting"""
        if not self.config.has_section(section):
            self.config.add_section(section)
        self.config.set(section, key, value)
        # Clear cache for affected settings
        self._cache.clear()
        self.save()
