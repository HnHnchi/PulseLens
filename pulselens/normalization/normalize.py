from typing import List, Dict, Optional
from datetime import datetime
import re
import ipaddress
from urllib.parse import urlparse

class IOCNormalizer:
    """Normalizes IOCs into a consistent format."""
    
    def __init__(self):
        self.current_time = datetime.utcnow()
    
    def normalize_iocs(self, validated_iocs: List[Dict]) -> List[Dict]:
        """
        Convert validated IOCs into normalized format.
        
        Args:
            validated_iocs: List of validated IOC dictionaries
            
        Returns:
            List of normalized IOC dictionaries
        """
        normalized_iocs = []
        
        for ioc in validated_iocs:
            normalized_ioc = self._normalize_single_ioc(ioc)
            if normalized_ioc:
                normalized_iocs.append(normalized_ioc)
        
        return normalized_iocs
    
    def _normalize_single_ioc(self, ioc: Dict) -> Optional[Dict]:
        """
        Normalize a single IOC.
        
        Args:
            ioc: Validated IOC dictionary
            
        Returns:
            Normalized IOC dictionary or None if invalid
        """
        try:
            normalized = {
                'ioc_value': ioc['value'],
                'ioc_type': ioc['type'],
                'original_value': ioc['original'],
                'feed_source': 'manual',  # Default source
                'first_seen': self.current_time.isoformat(),
                'last_seen': self.current_time.isoformat(),
                'confidence': 'medium',  # Default confidence
                'tags': [],
                'metadata': {}
            }
            
            # Apply type-specific normalization
            if normalized['ioc_type'] == 'ip':
                self._normalize_ip(normalized)
            elif normalized['ioc_type'] == 'url':
                self._normalize_url(normalized)
            elif normalized['ioc_type'] == 'domain':
                self._normalize_domain(normalized)
            elif normalized['ioc_type'] == 'hash':
                self._normalize_hash(normalized)
            elif normalized['ioc_type'] == 'email':
                self._normalize_email(normalized)
            
            return normalized
            
        except Exception as e:
            print(f"Error normalizing IOC {ioc.get('original', 'unknown')}: {e}")
            return None
    
    def _normalize_ip(self, ioc: Dict) -> None:
        """Normalize IP address IOC."""
        try:
            ip_obj = ipaddress.ip_address(ioc['ioc_value'])
            
            # Add IP-specific metadata
            ioc['metadata'].update({
                'is_ipv6': ip_obj.version == 6,
                'is_private': ip_obj.is_private,
                'is_loopback': ip_obj.is_loopback,
                'is_multicast': ip_obj.is_multicast,
                'is_reserved': ip_obj.is_reserved
            })
            
            # Add classification based on IP type
            if ip_obj.is_private:
                ioc['tags'].append('private_ip')
            if ip_obj.is_loopback:
                ioc['tags'].append('loopback')
            if ip_obj.is_multicast:
                ioc['tags'].append('multicast')
                
        except Exception:
            pass
    
    def _normalize_url(self, ioc: Dict) -> None:
        """Normalize URL IOC."""
        try:
            parsed = urlparse(ioc['ioc_value'])
            
            # Sanitize URL by removing suspicious patterns
            sanitized_value = self._sanitize_url(ioc['ioc_value'])
            ioc['ioc_value'] = sanitized_value
            
            # Add URL-specific metadata
            ioc['metadata'].update({
                'scheme': parsed.scheme.lower(),
                'netloc': parsed.netloc.lower(),
                'path': parsed.path,
                'query': parsed.query,
                'fragment': parsed.fragment,
                'port': parsed.port,
                'has_credentials': bool(parsed.username or parsed.password)
            })
            
            # Add tags based on URL characteristics
            if parsed.scheme not in ['http', 'https']:
                ioc['tags'].append('unusual_scheme')
            if parsed.port and parsed.port not in [80, 443]:
                ioc['tags'].append('unusual_port')
            if parsed.username or parsed.password:
                ioc['tags'].append('has_credentials')
                
        except Exception:
            pass
    
    def _normalize_domain(self, ioc: Dict) -> None:
        """Normalize domain IOC."""
        domain = ioc['ioc_value'].lower()
        
        # Remove common subdomain prefixes for normalization
        domain = self._normalize_domain_name(domain)
        ioc['ioc_value'] = domain
        
        # Add domain-specific metadata
        ioc['metadata'].update({
            'length': len(domain),
            'has_hyphens': '-' in domain,
            'has_numbers': any(char.isdigit() for char in domain),
            'subdomain_count': domain.count('.'),
            'tld': domain.split('.')[-1] if '.' in domain else None
        })
        
        # Add tags based on domain characteristics
        if len(domain) > 50:
            ioc['tags'].append('long_domain')
        if domain.count('.') > 3:
            ioc['tags'].append('deep_subdomain')
        if '-' in domain:
            ioc['tags'].append('has_hyphens')
    
    def _normalize_hash(self, ioc: Dict) -> None:
        """Normalize hash IOC."""
        hash_value = ioc['ioc_value'].lower()
        ioc['ioc_value'] = hash_value
        
        # Determine hash algorithm
        hash_length = len(hash_value)
        if hash_length == 32:
            hash_type = 'md5'
        elif hash_length == 40:
            hash_type = 'sha1'
        elif hash_length == 64:
            hash_type = 'sha256'
        elif hash_length == 128:
            hash_type = 'sha512'
        else:
            hash_type = 'unknown'
        
        # Add hash-specific metadata
        ioc['metadata'].update({
            'hash_type': hash_type,
            'hash_length': hash_length
        })
        
        ioc['tags'].append(hash_type)
    
    def _normalize_email(self, ioc: Dict) -> None:
        """Normalize email IOC."""
        email = ioc['ioc_value'].lower()
        ioc['ioc_value'] = email
        
        # Parse email components
        if '@' in email:
            local_part, domain = email.split('@', 1)
            
            # Add email-specific metadata
            ioc['metadata'].update({
                'local_part': local_part,
                'domain': domain,
                'is_free_provider': self._is_free_email_provider(domain)
            })
            
            # Add tags based on email characteristics
            if self._is_free_email_provider(domain):
                ioc['tags'].append('free_email_provider')
            if '+' in local_part:
                ioc['tags'].append('has_plus_alias')
    
    def _sanitize_url(self, url: str) -> str:
        """Sanitize URL by removing defacement patterns."""
        # Common defacement patterns
        patterns = [
            r'\[dot\]',  # [dot]
            r'\[.\]',    # [.]
            r'\(dot\)',  # (dot)
            r'\{\.\}',   # {.}
            r'\[\.com\]', # [.com]
            r'\[\.net\]', # [.net]
            r'\[\.org\]', # [.org]
        ]
        
        sanitized = url
        for pattern in patterns:
            sanitized = re.sub(pattern, '.', sanitized, flags=re.IGNORECASE)
        
        return sanitized
    
    def _normalize_domain_name(self, domain: str) -> str:
        """Normalize domain name by removing common prefixes."""
        # Remove common prefixes that don't affect the core domain
        prefixes_to_remove = ['www.', 'm.', 'mobile.', 'mail.', 'webmail.']
        
        normalized = domain.lower()
        for prefix in prefixes_to_remove:
            if normalized.startswith(prefix):
                normalized = normalized[len(prefix):]
                break
        
        return normalized
    
    def _is_free_email_provider(self, domain: str) -> bool:
        """Check if domain is a free email provider."""
        free_providers = {
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
            'aol.com', 'icloud.com', 'mail.com', 'gmx.com',
            'yandex.com', 'protonmail.com', 'tutanota.com'
        }
        
        return domain.lower() in free_providers
    
    def deduplicate_normalized_iocs(self, iocs: List[Dict]) -> List[Dict]:
        """
        Remove duplicate normalized IOCs.
        
        Args:
            iocs: List of normalized IOC dictionaries
            
        Returns:
            List of unique normalized IOCs
        """
        seen = set()
        unique_iocs = []
        
        for ioc in iocs:
            # Create a unique key based on type and value
            key = f"{ioc['ioc_type']}:{ioc['ioc_value']}"
            
            if key not in seen:
                seen.add(key)
                unique_iocs.append(ioc)
        
        return unique_iocs
    
    def enrich_with_context(self, iocs: List[Dict]) -> List[Dict]:
        """
        Add contextual information to IOCs.
        
        Args:
            iocs: List of normalized IOC dictionaries
            
        Returns:
            List of enriched IOC dictionaries
        """
        for ioc in iocs:
            # Add processing timestamp
            ioc['metadata']['processed_at'] = self.current_time.isoformat()
            
            # Add context tags based on IOC characteristics
            self._add_context_tags(ioc)
        
        return iocs
    
    def _add_context_tags(self, ioc: Dict) -> None:
        """Add context tags based on IOC characteristics."""
        ioc_type = ioc['ioc_type']
        
        # Add general context tags
        if ioc_type == 'ip':
            if ioc['metadata'].get('is_private'):
                ioc['tags'].append('internal')
            else:
                ioc['tags'].append('external')
        
        elif ioc_type == 'url':
            if 'https' in ioc.get('metadata', {}).get('scheme', ''):
                ioc['tags'].append('encrypted')
            else:
                ioc['tags'].append('unencrypted')
        
        elif ioc_type == 'domain':
            tld = ioc.get('metadata', {}).get('tld')
            if tld in ['gov', 'mil', 'edu']:
                ioc['tags'].append('official_tld')
