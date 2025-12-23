import re
import ipaddress
import hashlib
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse
import validators
import tldextract

class IOCValidator:
    """Validates and categorizes Indicators of Compromise (IOCs)."""
    
    def __init__(self):
        self.hash_patterns = {
            'md5': re.compile(r'^[a-fA-F0-9]{32}$'),
            'sha1': re.compile(r'^[a-fA-F0-9]{40}$'),
            'sha256': re.compile(r'^[a-fA-F0-9]{64}$'),
            'sha512': re.compile(r'^[a-fA-F0-9]{128}$')
        }
        
    def validate_ioc(self, ioc: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Validate an IOC and return its type and normalized value.
        
        Args:
            ioc: The IOC string to validate
            
        Returns:
            Tuple of (is_valid, ioc_type, normalized_value)
        """
        ioc = ioc.strip()
        
        # Check for empty IOC
        if not ioc:
            return False, None, None
        
        # Try hash validation first (before dangerous input check)
        is_hash, hash_type, normalized_hash = self._validate_hash(ioc)
        if is_hash:
            return True, 'hash', normalized_hash
        
        # Security: Check for potentially dangerous inputs (only for non-hash IOCs)
        if self._is_dangerous_input(ioc):
            return False, None, None
            
        # Try IP validation
        is_ip, normalized_ip = self._validate_ip(ioc)
        if is_ip:
            return True, 'ip', normalized_ip
            
        # Try domain validation
        is_domain, normalized_domain = self._validate_domain(ioc)
        if is_domain:
            return True, 'domain', normalized_domain
            
        # Try URL validation
        is_url, normalized_url = self._validate_url(ioc)
        if is_url:
            return True, 'url', normalized_url
            
        # Try email validation
        is_email, normalized_email = self._validate_email(ioc)
        if is_email:
            return True, 'email', normalized_email
            
        return False, None, None
    
    def _validate_hash(self, ioc: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """Validate hash IOC."""
        ioc_lower = ioc.lower()
        
        for hash_type, pattern in self.hash_patterns.items():
            if pattern.match(ioc_lower):
                return True, hash_type, ioc_lower
                
        return False, None, None
    
    def _validate_ip(self, ioc: str) -> Tuple[bool, Optional[str]]:
        """Validate IP address IOC."""
        try:
            ip = ipaddress.ip_address(ioc)
            return True, str(ip)
        except ValueError:
            return False, None
    
    def _validate_domain(self, ioc: str) -> Tuple[bool, Optional[str]]:
        """Validate domain IOC."""
        # Remove common protocols and paths
        clean_ioc = ioc
        if '://' in clean_ioc:
            clean_ioc = clean_ioc.split('://', 1)[1]
        clean_ioc = clean_ioc.split('/')[0]
        
        # Remove www. prefix for consistency
        if clean_ioc.startswith('www.'):
            clean_ioc = clean_ioc[4:]
            
        # Use tldextract for better domain validation
        extracted = tldextract.extract(clean_ioc)
        if extracted.domain and extracted.suffix:
            if extracted.subdomain:
                domain = f'{extracted.subdomain}.{extracted.domain}.{extracted.suffix}'
            else:
                domain = f'{extracted.domain}.{extracted.suffix}'
            return True, domain.lower()
            
        return False, None
    
    def _validate_url(self, ioc: str) -> Tuple[bool, Optional[str]]:
        """Validate URL IOC."""
        try:
            result = urlparse(ioc)
            if result.scheme and result.netloc:
                # Normalize URL
                normalized = f'{result.scheme}://{result.netloc.lower()}'
                if result.path:
                    normalized += result.path
                if result.query:
                    normalized += f'?{result.query}'
                return True, normalized
        except Exception:
            pass
            
        return False, None
    
    def _validate_email(self, ioc: str) -> Tuple[bool, Optional[str]]:
        """Validate email IOC."""
        if validators.email(ioc):
            return True, ioc.lower()
        return False, None
    
    def _is_dangerous_input(self, ioc: str) -> bool:
        """
        Check for potentially dangerous or invalid inputs that should be rejected.
        
        Args:
            ioc: The IOC string to check
            
        Returns:
            True if input is dangerous and should be rejected, False otherwise
        """
        ioc_lower = ioc.lower()
        
        # Check for suspicious patterns that could indicate attacks
        dangerous_patterns = [
            '../', '..\\',  # Path traversal
            '<script', '</script>',  # XSS attempts
            'javascript:',  # JavaScript URLs
            'data:',  # Data URLs
            'vbscript:',  # VBScript URLs
            'file:',  # File protocol
            'ftp:',  # FTP protocol (not a valid IOC)
            'ldap:',  # LDAP protocol
            'mailto:',  # Mailto protocol (not an email IOC)
            'tel:',  # Telephone protocol
            'sms:',  # SMS protocol
        ]
        
        for pattern in dangerous_patterns:
            if pattern in ioc_lower:
                return True
        
        # Check for extremely long inputs (potential DoS)
        if len(ioc) > 2048:
            return True
        
        # Check for null bytes
        if '\x00' in ioc:
            return True
        
        # Check for control characters (except common whitespace)
        for char in ioc:
            if ord(char) < 32 and char not in ['\t', '\n', '\r']:
                return True
        
        # Check for suspicious domain patterns
        if self._is_suspicious_domain_pattern(ioc):
            return True
        
        return False
    
    def _is_suspicious_domain_pattern(self, ioc: str) -> bool:
        """
        Check for suspicious domain patterns that might indicate attacks.
        
        Args:
            ioc: The IOC string to check
            
        Returns:
            True if pattern is suspicious, False otherwise
        """
        # Remove protocol if present
        clean_ioc = ioc
        if '://' in clean_ioc:
            clean_ioc = clean_ioc.split('://', 1)[1]
        clean_ioc = clean_ioc.split('/')[0]
        
        # Check for punycode domains (potential homograph attacks)
        if 'xn--' in clean_ioc.lower():
            return True
        
        # Check for domains with excessive subdomains
        parts = clean_ioc.split('.')
        if len(parts) > 10:  # More than 10 subdomains is suspicious
            return True
        
        # Check for domains with very long labels
        for part in parts:
            if len(part) > 63:  # DNS label limit
                return True
        
        # Check for domains with suspicious character patterns
        suspicious_chars = ['<', '>', '"', "'", '&', '|', ';', '`', '$', '%', '(', ')', '{', '}']
        for char in suspicious_chars:
            if char in clean_ioc:
                return True
        
        return False
    
    def validate_batch(self, iocs: List[str]) -> Dict[str, List[Dict]]:
        """
        Validate multiple IOCs and categorize them.
        
        Args:
            iocs: List of IOC strings
            
        Returns:
            Dictionary with 'valid' and 'invalid' keys containing lists of IOCs
        """
        results = {'valid': [], 'invalid': []}
        
        for ioc in iocs:
            is_valid, ioc_type, normalized_value = self.validate_ioc(ioc)
            
            if is_valid:
                results['valid'].append({
                    'original': ioc,
                    'type': ioc_type,
                    'value': normalized_value
                })
            else:
                # Determine reason for rejection
                reason = self._get_rejection_reason(ioc)
                results['invalid'].append({
                    'original': ioc,
                    'reason': reason
                })
                
        return results
    
    def _get_rejection_reason(self, ioc: str) -> str:
        """
        Get the reason why an IOC was rejected.
        
        Args:
            ioc: The IOC string that was rejected
            
        Returns:
            String explaining why the IOC was rejected
        """
        ioc_stripped = ioc.strip()
        
        if not ioc_stripped:
            return 'Empty IOC'
        
        if self._is_dangerous_input(ioc_stripped):
            # More specific dangerous input detection
            ioc_lower = ioc_stripped.lower()
            
            dangerous_patterns = {
                '../': 'Path traversal attempt',
                '..\\': 'Path traversal attempt',
                '<script': 'XSS attempt',
                '</script': 'XSS attempt',
                'javascript:': 'JavaScript URL',
                'data:': 'Data URL',
                'vbscript:': 'VBScript URL',
                'file:': 'File protocol',
                'ftp:': 'FTP protocol (not a valid IOC)',
                'ldap:': 'LDAP protocol (not a valid IOC)',
                'mailto:': 'Mailto protocol (not an email IOC)',
                'tel:': 'Telephone protocol (not a valid IOC)',
                'sms:': 'SMS protocol (not a valid IOC)',
            }
            
            for pattern, reason in dangerous_patterns.items():
                if pattern in ioc_lower:
                    return reason
            
            if len(ioc_stripped) > 2048:
                return 'Input too long (potential DoS)'
            
            if '\x00' in ioc_stripped:
                return 'Contains null bytes'
            
            for char in ioc_stripped:
                if ord(char) < 32 and char not in ['\t', '\n', '\r']:
                    return 'Contains control characters'
            
            if self._is_suspicious_domain_pattern(ioc_stripped):
                return 'Suspicious domain pattern (potential homograph attack or malformed domain)'
            
            return 'Potentially dangerous input detected'
        
        return 'Invalid IOC format'
    
    def deduplicate_iocs(self, iocs: List[Dict]) -> List[Dict]:
        """Remove duplicate IOCs based on normalized value and type."""
        seen = set()
        unique_iocs = []
        
        for ioc in iocs:
            key = f"{ioc['type']}:{ioc['value']}"
            if key not in seen:
                seen.add(key)
                unique_iocs.append(ioc)
                
        return unique_iocs
