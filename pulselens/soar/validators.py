"""
IOC validation utilities for SOAR containment actions.
"""
import re
import ipaddress
from typing import Callable, Dict

class IOCValidator:
    """Validates IOCs to prevent injection and malformed inputs."""
    
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """Validate IP address format."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_domain(domain: str) -> bool:
        """Validate domain name format."""
        if not domain or len(domain) > 253:
            return False
        return bool(re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$', domain))
    
    @staticmethod
    def validate_hash(hash_value: str) -> bool:
        """Validate hash format (MD5, SHA-1, SHA-256)."""
        hash_length = len(hash_value)
        return hash_length in {32, 40, 64} and all(c in '0123456789abcdef' for c in hash_value.lower())
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """Validate URL format."""
        try:
            domain = url.split('//')[-1].split('/')[0]
            return IOCValidator.validate_domain(domain)
        except (IndexError, AttributeError):
            return False
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email address format."""
        return bool(re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email))
    
    # Map of IOC types to their validation functions
    VALIDATORS: Dict[str, Callable[[str], bool]] = {
        'ip': validate_ip.__func__,
        'domain': validate_domain.__func__,
        'hash': validate_hash.__func__,
        'url': validate_url.__func__,
        'email': validate_email.__func__
    }
    
    @classmethod
    def validate_ioc(cls, ioc_type: str, value: str) -> bool:
        """Validate an IOC based on its type."""
        validator = cls.VALIDATORS.get(ioc_type)
        if not validator:
            return False
        return validator(value)
