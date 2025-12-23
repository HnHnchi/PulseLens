#!/usr/bin/env python3
"""
PulseLens Unified Startup Script
Comprehensive launcher for all PulseLens services including:
- Backend API Server (port 4000)
- Frontend Web Server (port 6000)
- Database initialization
- Service health monitoring
"""

import sys
import os
import threading
import time
import webbrowser
import subprocess
import signal
import json
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Import configuration
import config

# Import dashboard app
from pulselens.dashboard.app import PulseLensDashboard

def start_backend():
    """Start the backend API server."""
    print("Starting Backend API Server...")
    print("=" * 50)
    
    # Load configuration
    config_dict = {
        'DATABASE_PATH': getattr(config, 'DATABASE_PATH', 'data/cache.db'),
        'CACHE_EXPIRY_HOURS': getattr(config, 'CACHE_EXPIRY_HOURS', 24),
        'FLASK_SECRET_KEY': getattr(config, 'FLASK_SECRET_KEY', 'pulselens-secret-key-change-in-production'),
        'OTX_API_KEY': getattr(config, 'OTX_API_KEY', ''),
        'OTX_BASE_URL': getattr(config, 'OTX_BASE_URL', 'https://otx.alienvault.com/api/v1'),
        'OTX_RATE_LIMIT': getattr(config, 'OTX_RATE_LIMIT', 60),
        'VIRUSTOTAL_ENABLED': getattr(config, 'VIRUSTOTAL_ENABLED', True),
        'VIRUSTOTAL_API_KEY': getattr(config, 'VIRUSTOTAL_API_KEY', ''),
        'VIRUSTOTAL_BASE_URL': getattr(config, 'VIRUSTOTAL_BASE_URL', 'https://www.virustotal.com/vtapi/v2'),
        'VIRUSTOTAL_RATE_LIMIT': getattr(config, 'VIRUSTOTAL_RATE_LIMIT', 4),
        'URLHAUS_ENABLED': getattr(config, 'URLHAUS_ENABLED', True),
        'URLHAUS_BASE_URL': getattr(config, 'URLHAUS_BASE_URL', 'https://urlhaus-api.abuse.ch/v1'),
        'URLHAUS_RATE_LIMIT': getattr(config, 'URLHAUS_RATE_LIMIT', 60),
        'URLHAUS_API_KEY': getattr(config, 'URLHAUS_API_KEY', ''),
        'THREATFOX_ENABLED': getattr(config, 'THREATFOX_ENABLED', True),
        'THREATFOX_BASE_URL': getattr(config, 'THREATFOX_BASE_URL', 'https://threatfox-api.abuse.ch/api/v1/'),
        'THREATFOX_RATE_LIMIT': getattr(config, 'THREATFOX_RATE_LIMIT', 60),
        'THREATFOX_API_KEY': getattr(config, 'THREATFOX_API_KEY', ''),
        'DASHBOARD_HOST': getattr(config, 'DASHBOARD_HOST', '127.0.0.1'),
        'DASHBOARD_PORT': getattr(config, 'DASHBOARD_PORT', 4000),
        'DASHBOARD_DEBUG': getattr(config, 'DASHBOARD_DEBUG', False),
        'SEVERITY_THRESHOLDS': getattr(config, 'SEVERITY_THRESHOLDS', {}),
        'IOC_TYPE_WEIGHTS': getattr(config, 'IOC_TYPE_WEIGHTS', {}),
        'DEFAULT_CONFIDENCE': getattr(config, 'DEFAULT_CONFIDENCE', 'medium'),
        'AUTO_CLEANUP_CACHE': getattr(config, 'AUTO_CLEANUP_CACHE', True)
    }
    
    # Display backend configuration
    print(f"Backend Host: {config_dict['DASHBOARD_HOST']}")
    print(f"Backend Port: {config_dict['DASHBOARD_PORT']}")
    print(f"Database Path: {config_dict['DATABASE_PATH']}")
    print(f"OTX API Key: {'Set' if config_dict['OTX_API_KEY'] else 'Not set'}")
    print(f"Debug Mode: {config_dict['DASHBOARD_DEBUG']}")
    print("=" * 50)
    
    try:
        dashboard = PulseLensDashboard(config_dict)
        print("Backend API initialized successfully!")
        print(f"Backend API running at: http://{config_dict['DASHBOARD_HOST']}:{config_dict['DASHBOARD_PORT']}/api")
        print("=" * 50)
        
        dashboard.run(
            host=config_dict['DASHBOARD_HOST'],
            port=config_dict['DASHBOARD_PORT'],
            debug=config_dict['DASHBOARD_DEBUG']
        )
        
    except KeyboardInterrupt:
        print("\nBackend server stopped by user")
    except Exception as e:
        print(f"Error starting backend: {e}")
        sys.exit(1)

def start_frontend():
    """Start the frontend development server."""
    import subprocess
    
    print("Starting Frontend Server...")
    print("=" * 50)
    
    frontend_host = getattr(config, 'FRONTEND_HOST', '127.0.0.1')
    frontend_port = getattr(config, 'FRONTEND_PORT', 6000)
    
    print(f"Frontend Host: {frontend_host}")
    print(f"Frontend Port: {frontend_port}")
    print(f"Backend API: http://127.0.0.1:4000/api")
    print("=" * 50)
    
    try:
        # Start frontend server in subprocess
        subprocess.run([
            sys.executable, 
            str(project_root / 'frontend_server.py')
        ], cwd=project_root)
        
    except KeyboardInterrupt:
        print("\nFrontend server stopped by user")
    except Exception as e:
        print(f"Error starting frontend: {e}")

class PulseLensServiceManager:
    """Manages all PulseLens services."""
    
    def __init__(self):
        self.services = {}
        self.running = True
        
    def initialize_database(self):
        """Initialize database if needed."""
        print("Initializing database...")
        try:
            from pulselens.storage.db import IOCDatabase
            db_path = getattr(config, 'DATABASE_PATH', 'data/cache.db')
            cache_expiry = getattr(config, 'CACHE_EXPIRY_HOURS', 24)
            
            db = IOCDatabase(db_path=db_path, cache_expiry_hours=cache_expiry)
            print(f"Database initialized: {db_path}")
            return True
        except Exception as e:
            print(f"Database initialization failed: {e}")
            return False
    
    def check_service_health(self, url, service_name):
        """Check if a service is healthy."""
        try:
            import urllib.request
            with urllib.request.urlopen(url, timeout=5) as response:
                return response.status == 200
        except:
            return False
    
    def monitor_services(self):
        """Monitor service health in background."""
        while self.running:
            time.sleep(30)  # Check every 30 seconds
            
            backend_healthy = self.check_service_health(
                f"http://{getattr(config, 'DASHBOARD_HOST', '127.0.0.1')}:{getattr(config, 'DASHBOARD_PORT', 4000)}/api/stats",
                "Backend API"
            )
            
            frontend_healthy = self.check_service_health(
                f"http://{getattr(config, 'FRONTEND_HOST', '127.0.0.1')}:{getattr(config, 'FRONTEND_PORT', 6000)}",
                "Frontend Server"
            )
            
            if not backend_healthy or not frontend_healthy:
                print(f"Service health check - Backend: {'OK' if backend_healthy else 'FAIL'}, Frontend: {'OK' if frontend_healthy else 'FAIL'}")
    
    def start_all_services(self):
        """Start all PulseLens services."""
        print("Starting PulseLens Services...")
        print("=" * 60)
        
        # Initialize database
        if not self.initialize_database():
            print("WARNING: Database initialization failed, continuing anyway...")
        
        # Start backend
        print("Starting Backend API Server...")
        backend_thread = threading.Thread(target=start_backend, daemon=True)
        backend_thread.start()
        
        # Wait for backend to start
        time.sleep(3)
        
        # Start frontend
        print("Starting Frontend Server...")
        frontend_thread = threading.Thread(target=start_frontend, daemon=True)
        frontend_thread.start()
        
        # Wait for frontend to start
        time.sleep(2)
        
        # Start service monitoring
        monitor_thread = threading.Thread(target=self.monitor_services, daemon=True)
        monitor_thread.start()
        
        # Display service URLs
        backend_host = getattr(config, 'DASHBOARD_HOST', '127.0.0.1')
        backend_port = getattr(config, 'DASHBOARD_PORT', 4000)
        frontend_host = getattr(config, 'FRONTEND_HOST', '127.0.0.1')
        frontend_port = getattr(config, 'FRONTEND_PORT', 6000)
        
        print("=" * 60)
        print("PulseLens Services Started Successfully!")
        print(f"Backend API:    http://{backend_host}:{backend_port}/api")
        print(f"Frontend Web:   http://{frontend_host}:{frontend_port}")
        print(f"Database:       {getattr(config, 'DATABASE_PATH', 'data/cache.db')}")
        print("=" * 60)
        print("Press Ctrl+C to stop all services")
        
        # Open browser automatically
        try:
            webbrowser.open(f"http://{backend_host}:{backend_port}")
            print("Opened dashboard in default browser")
        except:
            print("Could not open browser automatically")
        
        # Keep main thread alive
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down PulseLens services...")
            self.running = False
            print("All services stopped")

def main():
    """Main entry point for PulseLens startup."""
    manager = PulseLensServiceManager()
    manager.start_all_services()

if __name__ == "__main__":
    main()
