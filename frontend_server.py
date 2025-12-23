#!/usr/bin/env python3
"""
PulseLens Frontend Development Server
Serves the frontend static files on port 6000
"""

import os
import sys
from pathlib import Path
from http.server import HTTPServer, SimpleHTTPRequestHandler
import webbrowser
import threading
import time

class FrontendHandler(SimpleHTTPRequestHandler):
    """Custom handler for frontend static files."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(Path(__file__).parent / 'pulselens' / 'dashboard' / 'templates'), **kwargs)
    
    def end_headers(self):
        """Add CORS headers to allow frontend to talk to backend."""
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        super().end_headers()
    
    def do_OPTIONS(self):
        """Handle preflight requests."""
        self.send_response(200)
        self.end_headers()

def start_frontend_server(host='127.0.0.1', port=6000):
    """Start the frontend development server."""
    print(f"Starting Frontend Server...")
    print("=" * 50)
    print(f"Frontend Host: {host}")
    print(f"Frontend Port: {port}")
    print(f"Backend API: http://127.0.0.1:4000/api")
    print("=" * 50)
    
    server = HTTPServer((host, port), FrontendHandler)
    print(f"Frontend server running at http://{host}:{port}")
    print("Press Ctrl+C to stop the frontend server")
    print("=" * 50)
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nFrontend server stopped by user")
        server.shutdown()

if __name__ == "__main__":
    start_frontend_server()
