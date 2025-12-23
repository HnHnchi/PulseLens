#!/usr/bin/env python3
"""
PulseLens Configuration Validation and Setup Script
Validates configuration and sets up the environment
"""

import os
import sys
import json
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from pulselens.utils.logger import get_logger


class ConfigValidator:
    """Validates PulseLens configuration and environment."""
    
    def __init__(self):
        """Initialize the validator."""
        self.logger = get_logger()
        self.project_root = project_root
        self.config_file = self.project_root / "config.py"
        self.required_dirs = ["data", "reports", "logs"]
        self.required_files = ["main.py", "config.py"]
        self.errors = []
        self.warnings = []
    
    def validate_config(self) -> Dict:
        """
        Validate the configuration file.
        
        Returns:
            Validation results dictionary
        """
        results = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'config_values': {}
        }
        
        try:
            # Import config
            import config
            
            # Validate required config values
            required_configs = [
                'DATABASE_PATH',
                'CACHE_EXPIRY_HOURS',
                'FLASK_SECRET_KEY',
                'DASHBOARD_HOST',
                'DASHBOARD_PORT'
            ]
            
            for config_name in required_configs:
                if not hasattr(config, config_name):
                    results['errors'].append(f"Missing required config: {config_name}")
                    results['valid'] = False
                else:
                    value = getattr(config, config_name)
                    results['config_values'][config_name] = str(value)
                    
                    # Validate specific config values
                    if config_name == 'DATABASE_PATH':
                        self._validate_database_path(value, results)
                    elif config_name == 'CACHE_EXPIRY_HOURS':
                        self._validate_cache_expiry(value, results)
                    elif config_name == 'DASHBOARD_PORT':
                        self._validate_port(value, results)
            
            # Validate optional configs
            optional_configs = ['OTX_API_KEY', 'OTX_BASE_URL', 'SEVERITY_THRESHOLDS']
            for config_name in optional_configs:
                if hasattr(config, config_name):
                    value = getattr(config, config_name)
                    results['config_values'][config_name] = str(value)
                    
                    if config_name == 'OTX_API_KEY':
                        self._validate_otx_key(value, results)
            
            # Check for sensitive data exposure
            self._check_sensitive_data(results)
            
        except ImportError as e:
            results['errors'].append(f"Failed to import config: {str(e)}")
            results['valid'] = False
        
        return results
    
    def _validate_database_path(self, db_path: str, results: Dict):
        """Validate database path configuration."""
        if not db_path:
            results['errors'].append("DATABASE_PATH cannot be empty")
            results['valid'] = False
            return
        
        path = Path(db_path)
        
        # Check if directory exists or can be created
        if not path.parent.exists():
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                results['warnings'].append(f"Created database directory: {path.parent}")
            except Exception as e:
                results['errors'].append(f"Cannot create database directory {path.parent}: {str(e)}")
                results['valid'] = False
        
        # Test database connection
        try:
            conn = sqlite3.connect(db_path)
            conn.close()
            results['warnings'].append("Database connection successful")
        except Exception as e:
            results['errors'].append(f"Database connection failed: {str(e)}")
            results['valid'] = False
    
    def _validate_cache_expiry(self, cache_hours: int, results: Dict):
        """Validate cache expiry configuration."""
        if not isinstance(cache_hours, int) or cache_hours < 1:
            results['errors'].append("CACHE_EXPIRY_HOURS must be a positive integer")
            results['valid'] = False
        elif cache_hours > 168:  # 7 days
            results['warnings'].append("CACHE_EXPIRY_HOURS is very high (>7 days)")
    
    def _validate_port(self, port: int, results: Dict):
        """Validate port configuration."""
        if not isinstance(port, int) or port < 1 or port > 65535:
            results['errors'].append("DASHBOARD_PORT must be between 1 and 65535")
            results['valid'] = False
        elif port < 1024:
            results['warnings'].append("DASHBOARD_PORT is below 1024 (requires root privileges)")
        elif port in [4000, 5000, 8000, 8080]:
            results['warnings'].append(f"DASHBOARD_PORT {port} is commonly used")
    
    def _validate_otx_key(self, api_key: str, results: Dict):
        """Validate OTX API key."""
        if not api_key:
            results['warnings'].append("OTX_API_KEY not set - threat intelligence will be limited")
        elif len(api_key) < 10:
            results['errors'].append("OTX_API_KEY appears to be invalid (too short)")
            results['valid'] = False
    
    def _check_sensitive_data(self, results: Dict):
        """Check for sensitive data exposure in config."""
        sensitive_patterns = ['password', 'secret', 'key', 'token']
        
        try:
            with open(self.config_file, 'r') as f:
                config_content = f.read()
                
            for pattern in sensitive_patterns:
                if pattern in config_content.lower():
                    # Check if it's hardcoded (not in quotes or comments)
                    lines = config_content.split('\n')
                    for i, line in enumerate(lines, 1):
                        if pattern in line.lower() and '=' in line and not line.strip().startswith('#'):
                            if not line.strip().endswith("'") and not line.strip().endswith('"'):
                                results['warnings'].append(f"Line {i}: Possible hardcoded sensitive data")
        except Exception as e:
            results['warnings'].append(f"Could not check for sensitive data: {str(e)}")
    
    def validate_environment(self) -> Dict:
        """
        Validate the environment setup.
        
        Returns:
            Environment validation results
        """
        results = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'python_version': sys.version,
            'project_structure': {}
        }
        
        # Check Python version
        if sys.version_info < (3, 8):
            results['errors'].append("Python 3.8+ required")
            results['valid'] = False
        elif sys.version_info < (3, 10):
            results['warnings'].append("Python 3.10+ recommended")
        
        # Check project structure
        for dir_name in self.required_dirs:
            dir_path = self.project_root / dir_name
            if not dir_path.exists():
                try:
                    dir_path.mkdir(parents=True, exist_ok=True)
                    results['warnings'].append(f"Created directory: {dir_name}")
                except Exception as e:
                    results['errors'].append(f"Cannot create directory {dir_name}: {str(e)}")
                    results['valid'] = False
            
            results['project_structure'][dir_name] = str(dir_path.exists())
        
        # Check required files
        for file_name in self.required_files:
            file_path = self.project_root / file_name
            if not file_path.exists():
                results['errors'].append(f"Missing required file: {file_name}")
                results['valid'] = False
            
            results['project_structure'][file_name] = str(file_path.exists())
        
        # Check Python dependencies
        missing_deps = self._check_dependencies()
        if missing_deps:
            results['errors'].extend([f"Missing dependency: {dep}" for dep in missing_deps])
            results['valid'] = False
        
        return results
    
    def _check_dependencies(self) -> List[str]:
        """Check for required Python dependencies."""
        required_deps = [
            'flask',
            'requests',
            'sqlite3',  # Built-in
            'pathlib',  # Built-in
            'json',     # Built-in
            'datetime', # Built-in
        ]
        
        optional_deps = [
            'pdfkit',
            'networkx',
            'validators',
            'tldextract',
            'ipaddress',  # Built-in
        ]
        
        missing = []
        
        for dep in required_deps:
            try:
                __import__(dep)
            except ImportError:
                missing.append(dep)
        
        # Check optional dependencies and add warnings
        for dep in optional_deps:
            try:
                __import__(dep)
            except ImportError:
                self.warnings.append(f"Optional dependency not available: {dep}")
        
        return missing
    
    def create_sample_config(self) -> str:
        """
        Create a sample configuration file.
        
        Returns:
            Path to created config file
        """
        sample_config = '''#!/usr/bin/env python3
"""
PulseLens Configuration File
Copy this to config.py and modify as needed
"""

# Database Configuration
DATABASE_PATH = "data/cache.db"
CACHE_EXPIRY_HOURS = 24

# Flask Dashboard Configuration
FLASK_SECRET_KEY = "pulselens-secret-key-change-in-production"
DASHBOARD_HOST = "127.0.0.1"
DASHBOARD_PORT = 4000
DASHBOARD_DEBUG = False

# OTX API Configuration
# Get your API key from: https://otx.alienvault.com/api/v1
OTX_API_KEY = ""  # Add your OTX API key here
OTX_BASE_URL = "https://otx.alienvault.com/api/v1"
OTX_RATE_LIMIT = 60  # Requests per minute

# Severity Classification Configuration
SEVERITY_THRESHOLDS = {
    "critical": 8.0,
    "high": 6.0,
    "medium": 4.0,
    "low": 2.0,
    "info": 0.0
}

# IOC Type Weights
IOC_TYPE_WEIGHTS = {
    "ip": 1.0,
    "domain": 0.9,
    "url": 0.8,
    "hash": 0.7,
    "email": 0.6
}

# Default Configuration
DEFAULT_CONFIDENCE = "medium"
AUTO_CLEANUP_CACHE = True

# Logging Configuration
LOG_LEVEL = "INFO"
LOG_FILE = "logs/pulselens.log"
'''
        
        sample_config_path = self.project_root / "config_sample.py"
        
        try:
            with open(sample_config_path, 'w') as f:
                f.write(sample_config)
            
            self.logger.info(f"Sample configuration created: {sample_config_path}")
            return str(sample_config_path)
            
        except Exception as e:
            self.logger.error(f"Failed to create sample config: {str(e)}")
            raise
    
    def setup_environment(self) -> Dict:
        """
        Set up the PulseLens environment.
        
        Returns:
            Setup results
        """
        results = {
            'success': True,
            'actions_taken': [],
            'errors': []
        }
        
        try:
            # Create required directories
            for dir_name in self.required_dirs:
                dir_path = self.project_root / dir_name
                if not dir_path.exists():
                    dir_path.mkdir(parents=True, exist_ok=True)
                    results['actions_taken'].append(f"Created directory: {dir_name}")
            
            # Initialize database
            db_path = self.project_root / "data" / "cache.db"
            if not db_path.exists():
                conn = sqlite3.connect(str(db_path))
                conn.close()
                results['actions_taken'].append("Initialized database")
            
            # Create sample config if needed
            if not self.config_file.exists():
                sample_path = self.create_sample_config()
                results['actions_taken'].append(f"Created sample config: {sample_path}")
            
            # Create requirements.txt if needed
            req_file = self.project_root / "requirements.txt"
            if not req_file.exists():
                self._create_requirements_file()
                results['actions_taken'].append("Created requirements.txt")
            
        except Exception as e:
            results['success'] = False
            results['errors'].append(str(e))
        
        return results
    
    def _create_requirements_file(self):
        """Create requirements.txt file."""
        requirements = '''# PulseLens Requirements
flask>=2.0.0
flask-cors>=3.0.0
requests>=2.25.0
validators>=0.20.0
tldextract>=3.1.0

# Optional dependencies for enhanced functionality
# pdfkit>=1.0.0  # For PDF reporting
# networkx>=2.6   # For IOC correlation
# neo4j>=4.0      # For graph database (optional)
'''
        
        req_file = self.project_root / "requirements.txt"
        with open(req_file, 'w') as f:
            f.write(requirements)
    
    def run_full_validation(self) -> Dict:
        """
        Run complete validation of configuration and environment.
        
        Returns:
            Complete validation results
        """
        self.logger.info("Starting full PulseLens validation...")
        
        config_results = self.validate_config()
        env_results = self.validate_environment()
        
        combined_results = {
            'overall_valid': config_results['valid'] and env_results['valid'],
            'timestamp': datetime.now().isoformat(),
            'config_validation': config_results,
            'environment_validation': env_results,
            'recommendations': self._generate_recommendations(config_results, env_results)
        }
        
        return combined_results
    
    def _generate_recommendations(self, config_results: Dict, env_results: Dict) -> List[str]:
        """Generate setup recommendations."""
        recommendations = []
        
        # Config recommendations
        if not config_results['config_values'].get('OTX_API_KEY'):
            recommendations.append("Set OTX_API_KEY to enable threat intelligence enrichment")
        
        if env_results['python_version'].startswith('3.7'):
            recommendations.append("Upgrade to Python 3.8+ for better performance")
        
        # Security recommendations
        if config_results['config_values'].get('FLASK_SECRET_KEY') == 'pulselens-secret-key-change-in-production':
            recommendations.append("Change FLASK_SECRET_KEY for production deployment")
        
        # Performance recommendations
        recommendations.append("Consider using Redis for caching in production")
        recommendations.append("Set up automated backups for the database")
        
        return recommendations


def main():
    """Main entry point for setup validation."""
    import argparse
    
    parser = argparse.ArgumentParser(description='PulseLens Setup Validation')
    parser.add_argument('--mode', choices=['validate', 'setup', 'full'], default='full',
                       help='Validation mode')
    parser.add_argument('--fix', action='store_true', help='Attempt to fix issues')
    parser.add_argument('--output', help='Output file for results')
    
    args = parser.parse_args()
    
    try:
        validator = ConfigValidator()
        
        if args.mode == 'validate':
            results = validator.run_full_validation()
        elif args.mode == 'setup':
            results = validator.setup_environment()
        elif args.mode == 'full':
            results = validator.run_full_validation()
            
            # Attempt setup if validation fails
            if not results['overall_valid'] and args.fix:
                setup_results = validator.setup_environment()
                results['setup_attempted'] = setup_results
        
        # Output results
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"Results saved to: {args.output}")
        else:
            print(json.dumps(results, indent=2, default=str))
        
        # Exit with appropriate code
        sys.exit(0 if results.get('overall_valid', results.get('success', True)) else 1)
        
    except Exception as e:
        print(f"Validation failed: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
