import requests
import time
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import logging

class OTXClient:
    """OTX (AlienVault Open Threat Exchange) API client."""
    
    def __init__(self, api_key: str, base_url: str = "https://otx.alienvault.com/api/v1", rate_limit: int = 60):
        self.api_key = api_key
        self.base_url = base_url
        self.rate_limit = rate_limit  # requests per minute
        self.last_request_time = 0
        self.session = requests.Session()
        self.session.headers.update({
            'X-OTX-API-KEY': api_key,
            'Content-Type': 'application/json'
        })
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
    
    def _rate_limit_check(self) -> None:
        """Check and enforce rate limiting."""
        current_time = time.time()
        time_since_last_request = current_time - self.last_request_time
        min_interval = 60.0 / self.rate_limit
        
        if time_since_last_request < min_interval:
            sleep_time = min_interval - time_since_last_request
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    def _make_request(self, endpoint: str, params: Optional[Dict] = None) -> Optional[Dict]:
        """
        Make a request to the OTX API.
        
        Args:
            endpoint: API endpoint
            params: Query parameters
            
        Returns:
            JSON response data or None if error
        """
        self._rate_limit_check()
        
        try:
            url = f"{self.base_url}{endpoint}"
            response = self.session.get(url, params=params, timeout=30)
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"OTX API request failed: {e}")
            return None
        except ValueError as e:
            self.logger.error(f"Failed to parse OTX API response: {e}")
            return None
    
    def get_indicator_details(self, indicator: str, indicator_type: str) -> Optional[Dict]:
        """
        Get detailed information about an indicator.
        
        Args:
            indicator: The indicator value
            indicator_type: Type of indicator (IPv4, domain, URL, hash, etc.)
            
        Returns:
            Indicator details or None if not found
        """
        # Map indicator types to OTX types
        type_mapping = {
            'ip': 'IPv4',
            'ipv6': 'IPv6', 
            'domain': 'domain',
            'url': 'URL',
            'hash': 'file',
            'email': 'email'
        }
        
        otx_type = type_mapping.get(indicator_type.lower(), indicator_type)
        
        if otx_type == 'file':
            endpoint = f"/indicators/file/{indicator}"
        else:
            endpoint = f"/indicators/{otx_type}/{indicator}"
        
        return self._make_request(endpoint)
    
    def get_indicator_pulses(self, indicator: str, indicator_type: str) -> List[Dict]:
        """
        Get pulses associated with an indicator.
        
        Args:
            indicator: The indicator value
            indicator_type: Type of indicator
            
        Returns:
            List of pulse information
        """
        # Map indicator types to OTX types
        type_mapping = {
            'ip': 'IPv4',
            'ipv6': 'IPv6',
            'domain': 'domain', 
            'url': 'URL',
            'hash': 'file',
            'email': 'email'
        }
        
        otx_type = type_mapping.get(indicator_type.lower(), indicator_type)
        
        if otx_type == 'file':
            endpoint = f"/indicators/file/{indicator}/pulses"
        else:
            endpoint = f"/indicators/{otx_type}/{indicator}/pulses"
        
        result = self._make_request(endpoint)
        if result and isinstance(result, dict):
            return result.get('results', []) or []

        # Fallback: some indicator types return 404 for the /pulses endpoint while
        # still embedding pulses under details.pulse_info.pulses.
        details = self.get_indicator_details(indicator, indicator_type)
        if isinstance(details, dict):
            pulse_info = details.get('pulse_info', {})
            if isinstance(pulse_info, dict):
                pulses = pulse_info.get('pulses', [])
                return pulses if isinstance(pulses, list) else []

        return []
    
    def get_indicator_reputation(self, indicator: str, indicator_type: str) -> Dict:
        """
        Get reputation information for an indicator.
        
        Args:
            indicator: The indicator value
            indicator_type: Type of indicator
            
        Returns:
            Reputation information
        """
        details = self.get_indicator_details(indicator, indicator_type)
        
        if not details:
            return {
                'reputation': 'unknown',
                'threat_score': 0,
                'pulse_count': 0,
                'first_seen': None,
                'last_seen': None,
                'malicious_samples': 0
            }

        # OTX returns different shapes per indicator type. For IPs, "reputation" can be an int.
        rep_block = details.get('reputation')
        rep_dict = rep_block if isinstance(rep_block, dict) else {}
        rep_score = int(rep_block) if isinstance(rep_block, (int, float, str)) and str(rep_block).isdigit() else 0

        validation = details.get('validation')
        if isinstance(validation, list):
            for row in validation:
                if not isinstance(row, dict):
                    continue
                src = str(row.get('source') or '').lower()
                name = str(row.get('name') or '').lower()
                msg = str(row.get('message') or '').lower()
                if src in {'false_positive', 'whitelist'} or 'false positive' in name or 'whitelist' in name or 'whitelist' in msg:
                    return {
                        'reputation': 'clean',
                        'threat_score': 0,
                        'pulse_count': details.get('pulse_info', {}).get('count', 0) if isinstance(details.get('pulse_info', {}), dict) else 0,
                        'first_seen': details.get('first_seen'),
                        'last_seen': details.get('last_seen'),
                        'malicious_samples': 0
                    }
        
        indicator_type_l = str(indicator_type or '').lower()

        # For infrastructure IOCs, threat_score is often noisy; use pulses/samples instead.
        if indicator_type_l in {'ip', 'ipv4', 'ipv6', 'domain', 'url', 'email'}:
            pulse_info = details.get('pulse_info', {}) if isinstance(details.get('pulse_info', {}), dict) else {}
            pulse_count = pulse_info.get('count', 0) or 0
            malware_samples = details.get('malware_samples', {}) if isinstance(details.get('malware_samples', {}), dict) else {}
            malware_count = malware_samples.get('count', 0) or 0

            pulses = pulse_info.get('pulses', []) if isinstance(pulse_info, dict) else []
            pulse_tags = set()
            high_signal_pulse_count = 0
            if isinstance(pulses, list):
                for p in pulses[:25]:
                    if not isinstance(p, dict):
                        continue
                    tags = p.get('tags', [])
                    if isinstance(tags, list):
                        pulse_has_high_signal = False
                        for t in tags:
                            if isinstance(t, str) and t:
                                tt = t.strip().lower()
                                pulse_tags.add(tt)
                                if tt in {
                                    'c2', 'command and control', 'botnet',
                                    'phishing', 'credential', 'credential theft'
                                }:
                                    pulse_has_high_signal = True
                        if pulse_has_high_signal:
                            high_signal_pulse_count += 1

            if malware_count > 0:
                rep = 'malicious'
            else:
                if indicator_type_l == 'domain':
                    # Domains can appear in many unrelated/broad pulses; require stronger evidence.
                    # - Dedicated infra: low-volume pulse set + at least one high-signal pulse.
                    # - Repeated infra: multiple high-signal pulses.
                    if high_signal_pulse_count >= 3:
                        rep = 'suspicious'
                    elif high_signal_pulse_count >= 1 and pulse_count <= 3:
                        rep = 'suspicious'
                    else:
                        rep = 'clean'
                else:
                    # Other infra types: keep a lighter threshold.
                    if pulse_count >= 2 and high_signal_pulse_count >= 1:
                        rep = 'suspicious'
                    else:
                        rep = 'clean'

            return {
                'reputation': rep,
                'threat_score': 0,
                'pulse_count': pulse_count,
                'first_seen': details.get('first_seen'),
                'last_seen': details.get('last_seen'),
                'malicious_samples': malware_count,
            }

        # Extract reputation information
        reputation_info = {
            'reputation': self._determine_reputation(details),
            'threat_score': rep_dict.get('threat_score', rep_score),
            'pulse_count': details.get('pulse_info', {}).get('count', 0),
            'first_seen': details.get('first_seen'),
            'last_seen': details.get('last_seen'),
            'malicious_samples': details.get('malware_samples', {}).get('count', 0)
        }
        
        return reputation_info
    
    def _determine_reputation(self, details: Dict) -> str:
        """Determine reputation based on OTX details."""
        rep_block = details.get('reputation')
        if isinstance(rep_block, dict):
            threat_score = rep_block.get('threat_score', 0)
        else:
            try:
                threat_score = int(rep_block or 0)
            except Exception:
                threat_score = 0
        pulse_count = details.get('pulse_info', {}).get('count', 0)
        malware_count = details.get('malware_samples', {}).get('count', 0)
        
        if threat_score >= 7 or malware_count > 0:
            return 'malicious'
        elif threat_score >= 4 or pulse_count >= 2:
            return 'suspicious'
        elif threat_score >= 1:
            return 'neutral'
        else:
            return 'clean'
    
    def get_pulse_details(self, pulse_id: str) -> Optional[Dict]:
        """
        Get detailed information about a pulse.
        
        Args:
            pulse_id: The pulse ID
            
        Returns:
            Pulse details or None if not found
        """
        return self._make_request(f"/pulses/{pulse_id}")
    
    def search_pulses(self, query: str, limit: int = 10) -> List[Dict]:
        """
        Search for pulses.
        
        Args:
            query: Search query
            limit: Maximum number of results
            
        Returns:
            List of pulse information
        """
        params = {'q': query, 'limit': limit}
        result = self._make_request("/search/pulses", params)
        return result.get('results', []) if result else []
    
    def get_subscriptions(self) -> List[Dict]:
        """Get user's subscribed pulses."""
        result = self._make_request("/pulses/subscribed")
        return result.get('results', []) if result else []
    
    def get_user_pulses(self) -> List[Dict]:
        """Get pulses created by the user."""
        result = self._make_request("/pulses/user")
        return result.get('results', []) if result else []
    
    def create_pulse(self, pulse_data: Dict) -> Optional[Dict]:
        """
        Create a new pulse.
        
        Args:
            pulse_data: Pulse data dictionary
            
        Returns:
            Created pulse information or None if failed
        """
        self._rate_limit_check()
        
        try:
            response = self.session.post(
                f"{self.base_url}/pulses",
                json=pulse_data,
                timeout=30
            )
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to create pulse: {e}")
            return None
    
    def batch_enrich_indicators(self, indicators: List[Dict]) -> List[Dict]:
        """
        Enrich multiple indicators with OTX data.
        
        Args:
            indicators: List of indicator dictionaries with 'ioc_value' and 'ioc_type'
            
        Returns:
            List of enriched indicators
        """
        enriched_indicators = []
        
        for indicator in indicators:
            try:
                enriched = self.enrich_indicator(indicator)
                enriched_indicators.append(enriched)
            except Exception as e:
                self.logger.error(f"Failed to enrich indicator {indicator.get('ioc_value', 'unknown')}: {e}")
                # Add original indicator with error info
                indicator['otx_error'] = str(e)
                enriched_indicators.append(indicator)
        
        return enriched_indicators
    
    def enrich_indicator(self, indicator: Dict) -> Dict:
        """
        Enrich a single indicator with OTX data.
        
        Args:
            indicator: Indicator dictionary with 'ioc_value' and 'ioc_type'
            
        Returns:
            Enriched indicator dictionary
        """
        ioc_value = indicator['ioc_value']
        ioc_type = indicator['ioc_type']
        
        # Get reputation information
        reputation = self.get_indicator_reputation(ioc_value, ioc_type)
        
        # Get pulse information
        pulses = self.get_indicator_pulses(ioc_value, ioc_type)
        
        # Get detailed information
        details = self.get_indicator_details(ioc_value, ioc_type)
        
        # Create enriched indicator
        enriched = indicator.copy()
        enriched['otx_data'] = {
            'reputation': reputation,
            'pulses': pulses[:10],  # Limit to first 10 pulses
            'details': details,
            'enriched_at': datetime.utcnow().isoformat(),
            'pulse_count': len(pulses),
            'references': self._extract_references(details)
        }
        
        # Add OTX-specific tags
        self._add_otx_tags(enriched, reputation, pulses)
        
        return enriched
    
    def _extract_references(self, details: Dict) -> List[str]:
        """Extract references from OTX details."""
        references = []
        
        # Extract from pulse info
        pulse_info = details.get('pulse_info', {})
        for pulse in pulse_info.get('pulses', []):
            for reference in pulse.get('references', []):
                if isinstance(reference, str):
                    references.append(reference)
        
        # Extract from other sources
        if 'references' in details:
            for ref in details['references']:
                if isinstance(ref, str):
                    references.append(ref)
        
        return list(set(references))  # Remove duplicates
    
    def _add_otx_tags(self, indicator: Dict, reputation: Dict, pulses: List[Dict]) -> None:
        """Add OTX-specific tags to indicator."""
        tags = indicator.get('tags', [])
        
        # Add reputation tag
        reputation_value = reputation.get('reputation', 'unknown')
        tags.append(f"otx_{reputation_value}")
        
        # Add pulse count tag
        pulse_count = len(pulses)
        if pulse_count >= 10:
            tags.append('otx_high_pulse_count')
        elif pulse_count >= 5:
            tags.append('otx_medium_pulse_count')
        elif pulse_count >= 1:
            tags.append('otx_low_pulse_count')
        
        # Add threat score tag
        threat_score = reputation.get('threat_score', 0)
        if threat_score >= 7:
            tags.append('otx_high_threat')
        elif threat_score >= 4:
            tags.append('otx_medium_threat')
        elif threat_score >= 1:
            tags.append('otx_low_threat')
        
        # Add malware tag if present
        if reputation.get('malicious_samples', 0) > 0:
            tags.append('otx_malware_detected')
        
        indicator['tags'] = list(set(tags))  # Remove duplicates
    
    def test_connection(self) -> bool:
        """Test connection to OTX API."""
        try:
            result = self._make_request("/users/me")
            return result is not None
        except Exception:
            return False
