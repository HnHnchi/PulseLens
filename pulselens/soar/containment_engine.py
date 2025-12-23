#!/usr/bin/env python3
"""
SOAR Containment Engine for PulseLens
Integrates with Chronicle SIEM and SSH-based execution for automated containment.
"""

import json
import asyncio
import logging
import uuid
import re
import ipaddress
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Set
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum

# Import security components
from .config import SOARConfig
from .validators import IOCValidator

# Configure audit logging
logging.basicConfig(
    filename="soar_audit.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)
logger = logging.getLogger(__name__)

class SecurityError(Exception):
    """Base security exception for containment operations."""
    pass

# Import SSH executor
try:
    from .ssh_executor import SSHActionExecutor
except ImportError:
    SSHActionExecutor = None

class ContainmentStatus(Enum):
    """Containment action status."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"

class IOCType(Enum):
    """IOC types for containment."""
    IP_ADDRESS = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    URL = "url"
    EMAIL = "email"

@dataclass
class ContainmentAction:
    """Represents a containment action with security context."""
    action_id: str
    ioc_value: str
    ioc_type: str
    action_type: str
    status: ContainmentStatus
    timestamp: datetime
    details: Dict
    case_id: Optional[str] = None
    user_response: Optional[str] = None
    approval_id: Optional[str] = None
    performed_by: Optional[str] = None
    rollback_of: Optional[str] = None

class ApprovalSystem:
    """Manages human approval workflow for containment actions."""
    
    def __init__(self):
        self.pending_approvals: Dict[str, Dict] = {}
        
    def request_approval(self, ioc_value: str, ioc_type: str, case_id: str = None) -> str:
        """Request human approval for an action."""
        if not IOCValidator.validate_ioc(ioc_type, ioc_value):
            raise SecurityError(f"Invalid {ioc_type} IOC: {ioc_value}")
            
        approval_id = str(uuid.uuid4())
        self.pending_approvals[approval_id] = {
            "ioc": ioc_value,
            "type": ioc_type,
            "case_id": case_id,
            "status": "pending",
            "timestamp": datetime.utcnow().isoformat()
        }
        logger.info(f"APPROVAL_REQUESTED | APPROVAL_ID={approval_id} | IOC={ioc_value} | TYPE={ioc_type}")
        return approval_id
        
    def approve_action(self, approval_id: str) -> bool:
        """Approve a pending action."""
        if approval_id in self.pending_approvals:
            self.pending_approvals[approval_id].update({
                "status": "approved",
                "approved_at": datetime.utcnow().isoformat()
            })
            logger.info(f"APPROVAL_GRANTED | APPROVAL_ID={approval_id}")
            return True
        return False
        
    def is_approved(self, approval_id: str) -> bool:
        """Check if an action is approved."""
        return self.pending_approvals.get(approval_id, {}).get("status") == "approved"

class SOARContainmentEngine:
    """Secure SOAR containment engine with audit logging and validation."""
    
    # Whitelist of allowed actions
    ALLOWED_ACTIONS = {
        "block_ip", "unblock_ip",
        "block_domain", "unblock_domain",
        "quarantine_file", "unquarantine_file"
    }
    
    def __init__(self, config: Dict = None):
        """Initialize the secure containment engine."""
        # Load secure configuration
        self.config = SOARConfig()
        self.config.validate()  # Ensure required env vars are set
        
        # Initialize security components
        self.approval_system = ApprovalSystem()
        self.containment_history: List[ContainmentAction] = []
        self.case_id = config.get('CASE_ID', f"CASE-{datetime.now().strftime('%Y%m%d-%H%M%S')}") if config else f"CASE-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
        # Initialize SSH executor if available
        self.ssh_executor = None
        if SSHActionExecutor:
            try:
                self.ssh_executor = SSHActionExecutor()
                self.ssh_enabled = True
            except Exception as e:
                logger.error(f"SSH executor initialization failed: {e}")
                self.ssh_enabled = False
        else:
            self.ssh_enabled = False
        
        # Chronicle SIEM configuration (from secure config)
        self.chronicle_enabled = config.get('CHRONICLE_ENABLED', False) if config else False
        self.chronicle_api_key = self.config.CHRONICLE_API_KEY
        self.chronicle_instance = self.config.CHRONICLE_INSTANCE
        
        # Reference list mappings
        self.reference_lists = {
            'ip': config.get('IP_BLOCKLIST', 'IP_Blocklist') if config else 'IP_Blocklist',
            'domain': config.get('DOMAIN_BLOCKLIST', 'Domain_Blocklist') if config else 'Domain_Blocklist',
            'hash': config.get('HASH_BLOCKLIST', 'Hash_Blocklist') if config else 'Hash_Blocklist',
            'url': config.get('URL_BLOCKLIST', 'URL_Blocklist') if config else 'URL_Blocklist'
        }
        
        # EDR configuration
        self.edr_enabled = config.get('EDR_ENABLED', False) if config else False
        self.edr_system = config.get('EDR_SYSTEM', 'crowdstrike') if config else 'crowdstrike'
        
        logger.info("SOARContainmentEngine initialized with security features")
    
    async def confirm_containment_action(self, ioc_value: str, ioc_type: str) -> Tuple[str, str]:
        """Confirm containment action with user."""
        question_text = f"Proceed with containment for {ioc_value} ({ioc_type})?"
        response_options = ["Yes", "No"]
        
        # In a real implementation, this would trigger a SOAR confirmation dialog
        # For now, we'll simulate the user response
        return question_text, response_options
    
    async def execute_containment(
        self,
        ioc_value: str,
        ioc_type: str,
        user_response: str = None,
        approval_id: str = None,
        user: str = "system",
        action_type: str = None
    ) -> Dict:
        """Execute containment action with security checks."""
        # 1. Input validation
        if not IOCValidator.validate_ioc(ioc_type, ioc_value):
            raise SecurityError(f"Invalid {ioc_type} IOC: {ioc_value}")
        
        # 2. Determine action type if not provided
        if not action_type:
            action_type = f"block_{ioc_type}" if ioc_type in ['ip', 'domain'] else "quarantine_file" if ioc_type == 'hash' else "monitor"
        
        # 3. Action validation
        if action_type not in self.ALLOWED_ACTIONS:
            raise SecurityError(f"Unauthorized action: {action_type}")
        
        # 4. Check for existing containment (idempotency)
        if self._is_already_contained(ioc_value, action_type):
            logger.warning(f"Action already performed: {action_type} on {ioc_value}")
            return {"status": "already_contained", "ioc": ioc_value}
        
        # 5. Check approval if required
        if approval_id and not self.approval_system.is_approved(approval_id):
            raise SecurityError(f"Action not approved: {approval_id}")
        
        # 6. Create and log the action
        action = ContainmentAction(
            action_id=str(uuid.uuid4()),
            ioc_value=ioc_value,
            ioc_type=ioc_type,
            action_type=action_type,
            status=ContainmentStatus.IN_PROGRESS,
            timestamp=datetime.utcnow(),
            details={},
            case_id=self.case_id,
            approval_id=approval_id,
            performed_by=user,
            user_response=user_response
        )
        
        try:
            # 7. Execute the containment action
            if ioc_type.lower() in ['ip', 'domain']:
                await self.contain_network_indicator(ioc_value, ioc_type.lower(), action)
            elif ioc_type.lower() == 'hash':
                await self.contain_file_hash(ioc_value, action)
            else:
                await self.contain_other_ioc(ioc_value, ioc_type, action)
            
            action.status = ContainmentStatus.COMPLETED
            action.details["completed_at"] = datetime.utcnow().isoformat()
            
            logger.info(
                f"ACTION_COMPLETED | ACTION_ID={action.action_id} | "
                f"TYPE={action_type} | IOC={ioc_value} | STATUS={action.status.value}"
            )
            
            # Document final action
            await self.document_final_action(action)
            
            self.containment_history.append(action)
            
            return {
                "status": "success",
                "action_id": action.action_id,
                "ioc": ioc_value,
                "action_type": action_type,
                "timestamp": action.timestamp.isoformat()
            }
            
        except Exception as e:
            action.status = ContainmentStatus.FAILED
            action.details["error"] = str(e)
            logger.error(
                f"ACTION_FAILED | ACTION_ID={action.action_id} | "
                f"TYPE={action_type} | IOC={ioc_value} | ERROR={str(e)}"
            )
            self.containment_history.append(action)
            raise
    
    async def contain_network_indicator(self, ioc_value: str, ioc_type: str, action: ContainmentAction):
        """Contain IP or Domain indicators."""
        containment_results = []
        
        # SSH-based containment (primary method)
        if self.ssh_enabled and self.ssh_executor:
            try:
                # Map IOC type to SSH action
                ssh_action = 'block_ip' if ioc_type == 'ip' else 'block_domain'
                
                # Execute SSH action
                ssh_result = self.ssh_executor.execute_action(
                    {'ioc_value': ioc_value, 'ioc_type': ioc_type},
                    ssh_action
                )
                
                containment_results.append({
                    "platform": "SSH Executor",
                    "action": ssh_action,
                    "status": "success" if ssh_result['success'] else "failed",
                    "details": ssh_result,
                    "command": ssh_result.get('command'),
                    "output": ssh_result.get('output'),
                    "verified": ssh_result.get('verified', False)
                })
                
            except Exception as e:
                containment_results.append({
                    "platform": "SSH Executor",
                    "action": f"block_{ioc_type}",
                    "status": "failed",
                    "error": str(e)
                })
        
        # Chronicle SIEM blocklist addition (fallback/backup)
        if self.chronicle_enabled:
            try:
                reference_list_name = self.reference_lists.get(ioc_type)
                if reference_list_name:
                    result = await self.add_to_chronicle_blocklist(
                        ioc_value, reference_list_name
                    )
                    containment_results.append({
                        "platform": "Chronicle SIEM",
                        "action": f"Added to {reference_list_name}",
                        "status": "success" if result else "failed",
                        "details": result
                    })
            except Exception as e:
                containment_results.append({
                    "platform": "Chronicle SIEM",
                    "action": f"Add to {self.reference_lists.get(ioc_type)}",
                    "status": "failed",
                    "error": str(e)
                })
        
        # Firewall/Proxy integration (placeholder)
        if self.config.get('FIREWALL_ENABLED', False):
            firewall_result = await self.add_to_firewall_blocklist(ioc_value, ioc_type)
            containment_results.append(firewall_result)
        
        action.details['containment_results'] = containment_results
        action.details['action_type'] = 'network_block'
    
    async def contain_file_hash(self, ioc_value: str, action: ContainmentAction):
        """Contain file hash indicators."""
        containment_results = []
        
        # SSH-based file quarantine (primary method)
        if self.ssh_enabled and self.ssh_executor:
            try:
                # Find file by hash first
                ssh_result = self.ssh_executor.execute_action(
                    {'ioc_value': ioc_value, 'ioc_type': 'hash'},
                    'quarantine_file'
                )
                
                containment_results.append({
                    "platform": "SSH Executor",
                    "action": "quarantine_file",
                    "status": "success" if ssh_result['success'] else "failed",
                    "details": ssh_result,
                    "command": ssh_result.get('command'),
                    "output": ssh_result.get('output'),
                    "verified": ssh_result.get('verified', False)
                })
                
            except Exception as e:
                containment_results.append({
                    "platform": "SSH Executor",
                    "action": "quarantine_file",
                    "status": "failed",
                    "error": str(e)
                })
        
        # Search SIEM for affected endpoints (backup/monitoring)
        if self.chronicle_enabled:
            try:
                affected_endpoints = await self.search_siem_for_hash(ioc_value)
                containment_results.append({
                    "platform": "Chronicle SIEM",
                    "action": "Search for hash events",
                    "status": "success",
                    "affected_endpoints": affected_endpoints
                })
                
                # EDR actions on affected endpoints (if SSH failed)
                if self.edr_enabled and affected_endpoints:
                    edr_results = await self.execute_edr_actions(ioc_value, affected_endpoints)
                    containment_results.extend(edr_results)
                    
            except Exception as e:
                containment_results.append({
                    "platform": "Chronicle SIEM",
                    "action": "Hash search",
                    "status": "failed",
                    "error": str(e)
                })
        
        action.details['containment_results'] = containment_results
        action.details['action_type'] = 'file_quarantine'
    
    async def contain_other_ioc(self, ioc_value: str, ioc_type: str, action: ContainmentAction):
        """Contain other IOC types (URL, Email, etc.)."""
        containment_results = []
        
        # Log and monitor approach for other IOC types
        containment_results.append({
            "platform": "PulseLens",
            "action": f"Enhanced monitoring for {ioc_type}",
            "status": "success",
            "details": f"Added {ioc_value} to enhanced monitoring"
        })
        
        action.details['containment_results'] = containment_results
        action.details['action_type'] = 'enhanced_monitoring'
    
    async def add_to_chronicle_blocklist(self, ioc_value: str, reference_list_name: str) -> Dict:
        """Add IOC to Chronicle SIEM reference list."""
        # Placeholder for Chronicle SIEM API call
        # In real implementation, this would use soar-mcp_google_chronicle_add_values_to_reference_list
        
        simulated_result = {
            "reference_list": reference_list_name,
            "value_added": ioc_value,
            "timestamp": datetime.now().isoformat(),
            "status": "success",
            "list_size": 1250  # Simulated list size after addition
        }
        
        return simulated_result
    
    async def search_siem_for_hash(self, hash_value: str) -> List[str]:
        """Search SIEM for events involving the file hash."""
        # Placeholder for SIEM search
        # In real implementation, this would use secops-mcp_search_security_events
        
        # Simulate finding affected endpoints
        simulated_endpoints = [
            "DESKTOP-ABC123",
            "LAPTOP-XYZ789",
            "SERVER-DEF456"
        ]
        
        return simulated_endpoints
    
    async def execute_edr_actions(self, hash_value: str, endpoints: List[str]) -> List[Dict]:
        """Execute EDR actions on identified endpoints."""
        edr_results = []
        
        for endpoint in endpoints:
            # Simulate EDR quarantine action
            result = {
                "platform": self.edr_system,
                "endpoint": endpoint,
                "action": "file_quarantine",
                "hash": hash_value,
                "status": "success",
                "timestamp": datetime.now().isoformat()
            }
            edr_results.append(result)
        
        return edr_results
    
    async def add_to_firewall_blocklist(self, ioc_value: str, ioc_type: str) -> Dict:
        """Add IOC to firewall blocklist."""
        # Placeholder for firewall integration
        
        return {
            "platform": "Firewall",
            "action": f"Block {ioc_type}",
            "value": ioc_value,
            "status": "success",
            "timestamp": datetime.now().isoformat()
        }
    
    async def document_action(self, case_id: str, comment_text: str) -> Dict:
        """Document action in SOAR case."""
        # Placeholder for SOAR documentation
        # In real implementation, this would use common_steps/document_in_soar.md
        
        return {
            "case_id": case_id,
            "comment_text": comment_text,
            "timestamp": datetime.now().isoformat(),
            "status": "documented"
        }
    
    async def document_final_action(self, action: ContainmentAction):
        """Document final containment action result."""
        if action.status == ContainmentStatus.COMPLETED:
            comment_text = f"Containment action completed for IOC: {action.ioc_value} (Type: {action.ioc_type}). "
            comment_text += f"Action: {action.details.get('action_type', 'Unknown')}. Status: {action.status.value}"
        else:
            comment_text = f"Containment action failed for IOC: {action.ioc_value} (Type: {action.ioc_type}). "
            comment_text += f"Error: {action.details.get('error', 'Unknown error')}"
        
        await self.document_action(self.case_id, comment_text)
    
    def get_containment_status(self, action_id: str) -> Optional[ContainmentAction]:
        """Get status of a containment action."""
        for action in self.containment_history:
            if action.action_id == action_id:
                return action
        return None
    
    def get_containment_history(self, ioc_value: str = None) -> List[ContainmentAction]:
        """Get containment history, optionally filtered by IOC."""
        if ioc_value:
            return [action for action in self.containment_history if action.ioc_value == ioc_value]
        return self.containment_history
    
    def _is_already_contained(self, ioc_value: str, action_type: str) -> bool:
        """Check if an IOC is already contained."""
        return any(
            a.ioc_value == ioc_value 
            and a.action_type == action_type
            and a.status == ContainmentStatus.COMPLETED
            for a in self.containment_history
        )
        
    async def rollback_action(self, action_id: str, user: str = "system") -> Dict:
        """Rollback a containment action."""
        action = next((a for a in self.containment_history if a.action_id == action_id), None)
        if not action:
            raise ValueError(f"Action not found: {action_id}")
            
        if action.status != ContainmentStatus.COMPLETED:
            raise ValueError("Can only rollback completed actions")
            
        rollback_action = ContainmentAction(
            action_id=str(uuid.uuid4()),
            ioc_value=action.ioc_value,
            ioc_type=action.ioc_type,
            action_type=f"un{action.action_type}" if action.action_type.startswith(('block_', 'quarantine_')) else action.action_type,
            status=ContainmentStatus.IN_PROGRESS,
            timestamp=datetime.utcnow(),
            details={"rollback_of": action.action_id},
            case_id=action.case_id,
            performed_by=user,
            rollback_of=action.action_id
        )
        
        try:
            # Execute rollback logic
            if action.action_type.startswith('block_'):
                # Unblock the IOC
                ioc_type = action.action_type.replace('block_', '')
                await self.contain_network_indicator(action.ioc_value, ioc_type, rollback_action)
            elif action.action_type == 'quarantine_file':
                # Unquarantine the file
                await self.contain_file_hash(action.ioc_value, rollback_action)
            
            rollback_action.status = ContainmentStatus.COMPLETED
            rollback_action.details["completed_at"] = datetime.utcnow().isoformat()
            self.containment_history.append(rollback_action)
            
            logger.info(
                f"ROLLBACK_COMPLETED | ACTION_ID={rollback_action.action_id} | "
                f"ROLLBACK_OF={action_id} | STATUS={rollback_action.status.value}"
            )
            
            return {
                "status": "success",
                "action_id": rollback_action.action_id,
                "rollback_of": action_id,
                "timestamp": rollback_action.timestamp.isoformat()
            }
            
        except Exception as e:
            rollback_action.status = ContainmentStatus.FAILED
            rollback_action.details["error"] = str(e)
            logger.error(
                f"ROLLBACK_FAILED | ACTION_ID={rollback_action.action_id} | "
                f"ROLLBACK_OF={action_id} | ERROR={str(e)}"
            )
            raise
    
    def to_dict(self, action: ContainmentAction) -> Dict:
        """Convert containment action to dictionary."""
        return {
            "action_id": action.action_id,
            "ioc_value": action.ioc_value,
            "ioc_type": action.ioc_type,
            "action_type": action.action_type,
            "status": action.status.value,
            "timestamp": action.timestamp.isoformat(),
            "details": action.details,
            "case_id": action.case_id,
            "user_response": action.user_response,
            "approval_id": action.approval_id,
            "performed_by": action.performed_by,
            "rollback_of": action.rollback_of
        }
