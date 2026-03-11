"""
Configuration Loader Module

Loads and validates system configuration from YAML file.
"""

import yaml
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)


class ConfigLoader:
    """Loads and validates configuration from YAML file."""
    
    @staticmethod
    def load(config_path: str) -> Dict[str, Any]:
        """
        Load configuration from YAML file.
        
        Args:
            config_path: Path to config.yaml file
        
        Returns:
            Configuration dictionary
        
        Raises:
            FileNotFoundError: If config file doesn't exist
            yaml.YAMLError: If config file is invalid YAML
            ValueError: If required configuration is missing
        """
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            # Validate required sections
            required_sections = ['database', 'wifi_networks', 'intrusion_detection', 'system']
            for section in required_sections:
                if section not in config:
                    raise ValueError(f"Missing required configuration section: {section}")
            
            logger.info(f"Configuration loaded from {config_path}")
            return config
        
        except FileNotFoundError:
            logger.error(f"Configuration file not found: {config_path}")
            raise
        except yaml.YAMLError as e:
            logger.error(f"Invalid YAML in configuration file: {e}")
            raise
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            raise
