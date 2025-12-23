#!/usr/bin/env python3
"""
SSH-based IOC Action Execution Engine for PulseLens
Implements secure, restricted SSH command execution for IOC containment actions.
"""

import paramiko
import json
import logging
import subprocess
import os
import shlex
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from datetime import datetime
import time

class SSHActionExecutor:
    """SSH-based IOC action execution system."""
    
    def __init__(self, config_path: Path = None):
        """Initialize the SSH executor."""
        self.logger = logging.getLogger(__name__)
        
        # Load configuration
        if config_path is None:
            config_path = Path(__file__).parent.parent.parent / "config" / "ssh_config.json"
        
        self.config = self._load_config(config_path)
        self.ssh_key_path = self.config.get('ssh_key_path', '~/.ssh/id_ed25519')
        
        # Security: Rate limiting
        self.execution_history = {}  # host -> list of timestamps
        self.max_executions_per_host_per_minute = 5
        self.cooldown_period = 60  # seconds
        
        # Security: Critical actions requiring additional approval
        self.CRITICAL_ACTIONS = {
            'isolate_endpoint', 'kill_process', 'stop_networking', 
            'shutdown_system', 'reboot_system', 'format_disk'
        }
        
        # Security: Allowed script paths (instead of here-documents)
        self.allowed_scripts = {
            'block_ip': '/usr/local/soar/block_ip.sh',
            'unblock_ip': '/usr/local/soar/unblock_ip.sh', 
            'block_domain': '/usr/local/soar/block_domain.sh',
            'unblock_domain': '/usr/local/soar/unblock_domain.sh',
            'quarantine_file': '/usr/local/soar/quarantine_file.sh',
            'unquarantine_file': '/usr/local/soar/unquarantine_file.sh'
        }
        
        # Action-to-SSH command mappings
        self.action_mappings = {
            'block_ip': {
                'command': 'sudo iptables -A INPUT -s {ioc_value} -j DROP',
                'verification': 'sudo iptables -L INPUT | grep {ioc_value}',
                'rollback': 'sudo iptables -D INPUT -s {ioc_value} -j DROP'
            },
            'block_domain': {
                'command': 'echo "0.0.0.0 {ioc_value}" | sudo tee -a /etc/hosts',
                'verification': 'grep {ioc_value} /etc/hosts',
                'rollback': 'sudo sed -i "/{ioc_value}/d" /etc/hosts'
            },
            'quarantine_file': {
                'command': 'sudo mkdir -p /quarantine && sudo mv {ioc_value} /quarantine/',
                'verification': 'ls -la /quarantine/$(basename {ioc_value})',
                'rollback': 'sudo mv /quarantine/$(basename {ioc_value}) {ioc_value}'
            },
            'kill_process': {
                'command': 'sudo kill -9 {ioc_value}',
                'verification': '! ps -p {ioc_value}',
                'rollback': 'echo "Process kill cannot be rolled back"'
            },
            'isolate_endpoint': {
                'command': 'sudo systemctl stop networking',
                'verification': '! ping -c 1 8.8.8.8',
                'rollback': 'sudo systemctl start networking'
            },
            'disable_user': {
                'command': 'sudo usermod -L {ioc_value}',
                'verification': 'sudo passwd -S {ioc_value} | grep -q L',
                'rollback': 'sudo usermod -U {ioc_value}'
            }
        }
        
        # IOC type to action mappings
        self.ioc_type_actions = {
            'ip': ['block_ip'],
            'domain': ['block_domain'],
            'hash': ['quarantine_file'],
            'url': ['block_domain'],
            'email': ['disable_user'],
            'process': ['kill_process'],
            'endpoint': ['isolate_endpoint']
        }
    
    def _load_config(self, config_path: Path) -> Dict:
        """Load SSH configuration."""
        try:
            if config_path.exists():
                with open(config_path, 'r') as f:
                    return json.load(f)
        except Exception as e:
            self.logger.warning(f"Could not load SSH config: {e}")
        
        # Default configuration
        return {
            'ssh_key_path': '~/.ssh/id_ed25519',
            'ssh_user': 'ioc_agent',
            'default_timeout': 30,
            'endpoints': {}
        }
    
    def _get_ssh_connection(self, host: str) -> paramiko.SSHClient:
        """Establish SSH connection to target host."""
        ssh = paramiko.SSHClient()
        # Security: Load known hosts and reject unknown keys
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
        
        try:
            ssh.connect(
                hostname=host,
                username=self.config.get('ssh_user', 'ioc_agent'),
                key_filename=str(Path(self.ssh_key_path).expanduser()),
                timeout=self.config.get('default_timeout', 30),
                allow_agent=False,
                look_for_keys=False
            )
            return ssh
        except Exception as e:
            self.logger.error(f"SSH connection failed to {host}: {e}")
            raise
    
    def _execute_command(self, ssh: paramiko.SSHClient, command: str) -> Tuple[str, str, int]:
        """Execute SSH command and return output, error, and exit code."""
        try:
            stdin, stdout, stderr = ssh.exec_command(command, timeout=30)
            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()
            exit_code = stdout.channel.recv_exit_status()
            
            return output, error, exit_code
        except Exception as e:
            self.logger.error(f"Command execution failed: {e}")
            return "", str(e), -1
    
    def _verify_ioc_exists(self, host: str, ioc: Dict) -> bool:
        """Verify IOC exists on target system before action."""
        ioc_value = ioc.get('ioc_value')
        ioc_type = ioc.get('ioc_type')
        
        if ioc_type == 'hash':
            # Find file by hash
            cmd = f"find / -type f -exec sha256sum {{}} + 2>/dev/null | grep -q {ioc_value}"
        elif ioc_type == 'ip':
            # Check if IP is connected
            cmd = f"netstat -antp 2>/dev/null | grep -q {ioc_value}"
        elif ioc_type == 'domain':
            # Check DNS resolution
            cmd = f"nslookup {ioc_value} >/dev/null 2>&1 && echo 'FOUND' || echo 'NOT_FOUND'"
        elif ioc_type == 'process':
            # Check if process exists
            cmd = f"ps -p {ioc_value} >/dev/null 2>&1 && echo 'FOUND' || echo 'NOT_FOUND'"
        else:
            # For other types, assume existence
            return True
        
        try:
            ssh = self._get_ssh_connection(host)
            output, error, exit_code = self._execute_command(ssh, cmd)
            ssh.close()
            
            return "FOUND" in output or exit_code == 0
        except Exception as e:
            self.logger.error(f"IOC verification failed: {e}")
            return False
    
    def execute_action(self, ioc: Dict, action: str, host: str = None) -> Dict:
        """Execute IOC action on target host."""
        result = {
            'success': False,
            'action': action,
            'ioc_value': ioc.get('ioc_value'),
            'ioc_type': ioc.get('ioc_type'),
            'host': host,
            'timestamp': datetime.now().isoformat(),
            'command': None,
            'output': None,
            'error': None,
            'verified': False
        }
        
        # Use default host if not specified
        if not host:
            host = self.config.get('endpoints', {}).get('default')
            if not host:
                result['error'] = "No target host specified and no default configured"
                return result
        
        # Security: Rate limiting check
        if not self._check_rate_limit(host):
            result['error'] = f"Rate limit exceeded for host {host}"
            return result
        
        # Security: Critical action check
        if action in self.CRITICAL_ACTIONS:
            result['error'] = f"Critical action {action} requires additional approval"
            return result
        
        # Get action mapping
        action_config = self.action_mappings.get(action)
        if not action_config:
            result['error'] = f"Unknown action: {action}"
            return result
        
        # Security: Validate IOC value
        ioc_value = ioc.get('ioc_value')
        if not self._validate_ioc_value(ioc_value, action):
            result['error'] = f"Invalid IOC value: {ioc_value}"
            return result
        
        # Verify IOC exists (if applicable)
        if not self._verify_ioc_exists(host, ioc):
            result['error'] = f"IOC {ioc.get('ioc_value')} not found on target system"
            return result
        
        try:
            # Establish SSH connection
            ssh = self._get_ssh_connection(host)
            
            # Security: Use script-based execution instead of command interpolation
            if action in self.allowed_scripts:
                command = f"{self.allowed_scripts[action]} {shlex.quote(ioc_value)}"
            else:
                # Fallback: Use secure shell escaping
                command = action_config['command'].format(ioc_value=shlex.quote(ioc_value))
            result['command'] = command
            
            # Execute action
            output, error, exit_code = self._execute_command(ssh, command)
            result['output'] = output
            result['error'] = error
            
            # Verify action was successful
            if action_config.get('verification'):
                verify_cmd = action_config['verification'].format(ioc_value=shlex.quote(ioc_value))
                verify_output, verify_error, verify_exit_code = self._execute_command(ssh, verify_cmd)
                result['verified'] = verify_exit_code == 0
            
            # Close connection
            ssh.close()
            
            # Determine success
            result['success'] = exit_code == 0 and result['verified']
            
        except Exception as e:
            result['error'] = str(e)
            self.logger.error(f"Action execution failed: {e}")
        
        return result
    
    def rollback_action(self, ioc: Dict, action: str, host: str = None) -> Dict:
        """Rollback IOC action on target host."""
        result = {
            'success': False,
            'action': f"{action}_rollback",
            'ioc_value': ioc.get('ioc_value'),
            'ioc_type': ioc.get('ioc_type'),
            'host': host,
            'timestamp': datetime.now().isoformat(),
            'command': None,
            'output': None,
            'error': None
        }
        
        # Use default host if not specified
        if not host:
            host = self.config.get('endpoints', {}).get('default')
            if not host:
                result['error'] = "No target host specified and no default configured"
                return result
        
        # Get action mapping
        action_config = self.action_mappings.get(action)
        if not action_config or not action_config.get('rollback'):
            result['error'] = f"Rollback not available for action: {action}"
            return result
        
        try:
            # Establish SSH connection
            ssh = self._get_ssh_connection(host)
            
            # Format rollback command
            rollback_cmd = action_config['rollback'].format(ioc_value=ioc.get('ioc_value'))
            result['command'] = rollback_cmd
            
            # Execute rollback
            output, error, exit_code = self._execute_command(ssh, rollback_cmd)
            result['output'] = output
            result['error'] = error
            
            # Close connection
            ssh.close()
            
            # Determine success
            result['success'] = exit_code == 0
            
        except Exception as e:
            result['error'] = str(e)
            self.logger.error(f"Rollback failed: {e}")
        
        return result
    
    # SECURITY NOTE: _deploy_ssh_key function removed for production security
        # This function was dangerous because:
        # 1. Used AutoAddPolicy() (MITM risk)
        # 2. Handled plaintext passwords
        # 3. Performed remote key deployment
        # 
        # SSH key provisioning should be done out-of-band through secure channels
        # Never deploy keys automatically in production SOAR systems
    
    def _check_rate_limit(self, host: str) -> bool:
        """Check if host has exceeded rate limit."""
        now = time.time()
        
        # Clean old entries
        if host in self.execution_history:
            self.execution_history[host] = [
                timestamp for timestamp in self.execution_history[host]
                if now - timestamp < self.cooldown_period
            ]
        else:
            self.execution_history[host] = []
        
        # Check limit
        if len(self.execution_history[host]) >= self.max_executions_per_host_per_minute:
            return False
        
        # Record this execution
        self.execution_history[host].append(now)
        return True
    
    def _validate_ioc_value(self, ioc_value: str, action: str) -> bool:
        """Validate IOC value based on action type."""
        if not ioc_value or not isinstance(ioc_value, str):
            return False
        
        # Security: Prevent command injection
        dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', '"', "'"]
        if any(char in ioc_value for char in dangerous_chars):
            return False
        
        # Action-specific validation
        if action in ['block_ip', 'unblock_ip']:
            # IP address validation
            import ipaddress
            try:
                ipaddress.ip_address(ioc_value)
                return True
            except ValueError:
                return False
        
        elif action in ['block_domain', 'unblock_domain']:
            # Domain validation
            if len(ioc_value) > 253 or '..' in ioc_value or ioc_value.startswith('.'):
                return False
            # Basic domain format check
            import re
            domain_pattern = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')
            return bool(domain_pattern.match(ioc_value))
        
        elif action in ['quarantine_file', 'unquarantine_file']:
            # File path validation (hash should be handled separately)
            if len(ioc_value) == 64 and all(c in '0123456789abcdefABCDEF' for c in ioc_value):
                # SHA256 hash - need to find file by hash, not use as path
                return True
            else:
                # For file paths, prevent directory traversal
                if '..' in ioc_value or ioc_value.startswith('/'):
                    return False
                return True
        
        elif action == 'kill_process':
            # PID validation
            try:
                pid = int(ioc_value)
                return 1 <= pid <= 99999  # Reasonable PID range
            except ValueError:
                return False
        
        return False
    
    def _generate_ssh_key(self, key_type: str = 'ed25519', comment: str = 'pulselens@localhost') -> Dict:
        """Generate new SSH key pair."""
        result = {
            'success': False,
            'message': '',
            'public_key': '',
            'key_path': '',
            'error': None
        }
        
        try:
            # Create .ssh directory if it doesn't exist
            ssh_dir = Path.home() / '.ssh'
            ssh_dir.mkdir(exist_ok=True)
            ssh_dir.chmod(0o700)
            
            # Generate key filename
            key_name = f'pulselens_{key_type}_{datetime.now().strftime("%Y%m%d_%H%M%S")}'
            private_key_path = ssh_dir / key_name
            public_key_path = ssh_dir / f'{key_name}.pub'
            
            # Generate SSH key using subprocess
            cmd = ['ssh-keygen', '-t', key_type, '-f', str(private_key_path), '-N', '', '-C', comment]
            
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if process.returncode != 0:
                result['error'] = f'Key generation failed: {process.stderr}'
                return result
            
            # Read public key
            with open(public_key_path, 'r') as f:
                public_key = f.read().strip()
            
            # Update SSH configuration to use new key
            self.ssh_key_path = str(private_key_path)
            self.config['ssh_key_path'] = str(private_key_path)
            self._save_config()
            
            result['success'] = True
            result['message'] = f'SSH key generated successfully'
            result['public_key'] = public_key
            result['key_path'] = str(private_key_path)
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _check_rate_limit(self, host: str) -> bool:
        """Check if host has exceeded rate limit."""
        now = time.time()
        
        # Clean old entries
        if host in self.execution_history:
            self.execution_history[host] = [
                timestamp for timestamp in self.execution_history[host]
                if now - timestamp < self.cooldown_period
            ]
        else:
            self.execution_history[host] = []
        
        # Check limit
        if len(self.execution_history[host]) >= self.max_executions_per_host_per_minute:
            return False
        
        # Record this execution
        self.execution_history[host].append(now)
        return True
    
    def _validate_ioc_value(self, ioc_value: str, action: str) -> bool:
        """Validate IOC value based on action type."""
        if not ioc_value or not isinstance(ioc_value, str):
            return False
        
        # Security: Prevent command injection
        dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', '"', "'"]
        if any(char in ioc_value for char in dangerous_chars):
            return False
        
        # Action-specific validation
        if action in ['block_ip', 'unblock_ip']:
            # IP address validation
            import ipaddress
            try:
                ipaddress.ip_address(ioc_value)
                return True
            except ValueError:
                return False
        
        elif action in ['block_domain', 'unblock_domain']:
            # Domain validation
            if len(ioc_value) > 253 or '..' in ioc_value or ioc_value.startswith('.'):
                return False
            # Basic domain format check
            import re
            domain_pattern = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')
            return bool(domain_pattern.match(ioc_value))
        
        elif action in ['quarantine_file', 'unquarantine_file']:
            # File path validation (hash should be handled separately)
            if len(ioc_value) == 64 and all(c in '0123456789abcdefABCDEF' for c in ioc_value):
                # SHA256 hash - need to find file by hash, not use as path
                return True
            else:
                # For file paths, prevent directory traversal
                if '..' in ioc_value or ioc_value.startswith('/'):
                    return False
                return True
        
        elif action == 'kill_process':
            # PID validation
            try:
                pid = int(ioc_value)
                return 1 <= pid <= 99999  # Reasonable PID range
            except ValueError:
                return False
        
        return False
    
    def _import_ssh_key(self, public_key: str, private_key: str, key_name: str = 'imported_key') -> Dict:
        """Import existing SSH key pair."""
        result = {
            'success': False,
            'message': '',
            'key_path': '',
            'error': None
        }
        
        try:
            # Create .ssh directory if it doesn't exist
            ssh_dir = Path.home() / '.ssh'
            ssh_dir.mkdir(exist_ok=True)
            ssh_dir.chmod(0o700)
            
            # Generate key filename
            private_key_path = ssh_dir / key_name
            public_key_path = ssh_dir / f'{key_name}.pub'
            
            # Validate key format
            if not public_key.strip().startswith(('ssh-rsa', 'ssh-dss', 'ssh-ed25519', 'ecdsa-sha2')):
                result['error'] = 'Invalid public key format'
                return result
            
            # Write private key
            with open(private_key_path, 'w') as f:
                f.write(private_key.strip())
            private_key_path.chmod(0o600)
            
            # Write public key
            with open(public_key_path, 'w') as f:
                f.write(public_key.strip())
            public_key_path.chmod(0o644)
            
            # Update SSH configuration to use imported key
            self.ssh_key_path = str(private_key_path)
            self.config['ssh_key_path'] = str(private_key_path)
            self._save_config()
            
            result['success'] = True
            result['message'] = f'SSH key imported successfully'
            result['key_path'] = str(private_key_path)
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _check_rate_limit(self, host: str) -> bool:
        """Check if host has exceeded rate limit."""
        now = time.time()
        
        # Clean old entries
        if host in self.execution_history:
            self.execution_history[host] = [
                timestamp for timestamp in self.execution_history[host]
                if now - timestamp < self.cooldown_period
            ]
        else:
            self.execution_history[host] = []
        
        # Check limit
        if len(self.execution_history[host]) >= self.max_executions_per_host_per_minute:
            return False
        
        # Record this execution
        self.execution_history[host].append(now)
        return True
    
    def _validate_ioc_value(self, ioc_value: str, action: str) -> bool:
        """Validate IOC value based on action type."""
        if not ioc_value or not isinstance(ioc_value, str):
            return False
        
        # Security: Prevent command injection
        dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', '"', "'"]
        if any(char in ioc_value for char in dangerous_chars):
            return False
        
        # Action-specific validation
        if action in ['block_ip', 'unblock_ip']:
            # IP address validation
            import ipaddress
            try:
                ipaddress.ip_address(ioc_value)
                return True
            except ValueError:
                return False
        
        elif action in ['block_domain', 'unblock_domain']:
            # Domain validation
            if len(ioc_value) > 253 or '..' in ioc_value or ioc_value.startswith('.'):
                return False
            # Basic domain format check
            import re
            domain_pattern = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')
            return bool(domain_pattern.match(ioc_value))
        
        elif action in ['quarantine_file', 'unquarantine_file']:
            # File path validation (hash should be handled separately)
            if len(ioc_value) == 64 and all(c in '0123456789abcdefABCDEF' for c in ioc_value):
                # SHA256 hash - need to find file by hash, not use as path
                return True
            else:
                # For file paths, prevent directory traversal
                if '..' in ioc_value or ioc_value.startswith('/'):
                    return False
                return True
        
        elif action == 'kill_process':
            # PID validation
            try:
                pid = int(ioc_value)
                return 1 <= pid <= 99999  # Reasonable PID range
            except ValueError:
                return False
        
        return False
    
    def _save_config(self):
        """Save SSH configuration to file."""
        try:
            config_path = Path(__file__).parent.parent.parent / "config" / "ssh_config.json"
            with open(config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            self.logger.warning(f"Could not save SSH config: {e}")
    
    def get_available_actions(self, ioc_type: str) -> List[str]:
        """Get available actions for IOC type."""
        return self.ioc_type_actions.get(ioc_type, [])
    
    def test_connection(self, host: str) -> Dict:
        """Test SSH connection to target host."""
        result = {
            'host': host,
            'connected': False,
            'timestamp': datetime.now().isoformat(),
            'error': None
        }
        
        try:
            ssh = self._get_ssh_connection(host)
            output, error, exit_code = self._execute_command(ssh, 'whoami')
            ssh.close()
            
            result['connected'] = exit_code == 0
            result['user'] = output.strip()
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _check_rate_limit(self, host: str) -> bool:
        """Check if host has exceeded rate limit."""
        now = time.time()
        
        # Clean old entries
        if host in self.execution_history:
            self.execution_history[host] = [
                timestamp for timestamp in self.execution_history[host]
                if now - timestamp < self.cooldown_period
            ]
        else:
            self.execution_history[host] = []
        
        # Check limit
        if len(self.execution_history[host]) >= self.max_executions_per_host_per_minute:
            return False
        
        # Record this execution
        self.execution_history[host].append(now)
        return True
    
    def _validate_ioc_value(self, ioc_value: str, action: str) -> bool:
        """Validate IOC value based on action type."""
        if not ioc_value or not isinstance(ioc_value, str):
            return False
        
        # Security: Prevent command injection
        dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', '"', "'"]
        if any(char in ioc_value for char in dangerous_chars):
            return False
        
        # Action-specific validation
        if action in ['block_ip', 'unblock_ip']:
            # IP address validation
            import ipaddress
            try:
                ipaddress.ip_address(ioc_value)
                return True
            except ValueError:
                return False
        
        elif action in ['block_domain', 'unblock_domain']:
            # Domain validation
            if len(ioc_value) > 253 or '..' in ioc_value or ioc_value.startswith('.'):
                return False
            # Basic domain format check
            import re
            domain_pattern = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')
            return bool(domain_pattern.match(ioc_value))
        
        elif action in ['quarantine_file', 'unquarantine_file']:
            # File path validation (hash should be handled separately)
            if len(ioc_value) == 64 and all(c in '0123456789abcdefABCDEF' for c in ioc_value):
                # SHA256 hash - need to find file by hash, not use as path
                return True
            else:
                # For file paths, prevent directory traversal
                if '..' in ioc_value or ioc_value.startswith('/'):
                    return False
                return True
        
        elif action == 'kill_process':
            # PID validation
            try:
                pid = int(ioc_value)
                return 1 <= pid <= 99999  # Reasonable PID range
            except ValueError:
                return False
        
        return False
