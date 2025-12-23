from __future__ import annotations

import time
import logging
import hashlib
from typing import Dict, List, Optional, Any
from datetime import datetime

import requests


class _RateLimiter:
    """Simple rate limiter for API requests."""
    
    def __init__(self, requests_per_minute: int):
        self.requests_per_minute = requests_per_minute
        self._window_start = 0.0
        self._count = 0
    
    def wait_if_needed(self) -> None:
        if self.requests_per_minute <= 0:
            return
        
        now = time.monotonic()
        if self._window_start == 0.0 or now - self._window_start >= 60.0:
            self._window_start = now
            self._count = 0
        
        if self._count >= self.requests_per_minute:
            sleep_s = max(0.0, 60.0 - (now - self._window_start))
            time.sleep(sleep_s)
            self._window_start = time.monotonic()
            self._count = 0
        
        self._count += 1


class VirusTotalClient:
    """VirusTotal API client for file reputation analysis."""
    
    def __init__(self, api_key: str, base_url: str = "https://www.virustotal.com/vtapi/v2", rate_limit: int = 4):
        self.api_key = api_key
        self.base_url = base_url
        self.logger = logging.getLogger(__name__)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'PulseLens/1.0 (+https://localhost)',
            'Accept': 'application/json'
        })
        self._rl = _RateLimiter(rate_limit)
        self.logger.info(f"VirusTotal client initialized with rate limit: {rate_limit} requests/minute")
    
    def get_file_report(self, file_hash: str) -> Dict[str, Any]:
        """
        Get a file report from VirusTotal.
        
        Args:
            file_hash: MD5, SHA1, or SHA256 hash of the file
            
        Returns:
            File report data or empty dict if not found/error
        """
        self._rl.wait_if_needed()
        
        params = {
            'apikey': self.api_key,
            'resource': file_hash
        }
        
        try:
            response = self.session.get(f"{self.base_url}/file/report", params=params, timeout=30)
            response.raise_for_status()
            
            # Check if response is actually JSON
            content_type = response.headers.get('content-type', '')
            if 'application/json' not in content_type:
                self.logger.warning(f"VirusTotal returned non-JSON response: {response.text[:200]}")
                return {}
            
            data = response.json()
            
            # Handle API response codes
            if data.get('response_code') == 0:
                self.logger.info(f"VirusTotal: File {file_hash} not found")
                return {}
            elif data.get('response_code') == 1:
                self.logger.info(f"VirusTotal: Got report for {file_hash}")
                return data
            else:
                self.logger.warning(f"VirusTotal: Unexpected response code {data.get('response_code')} for {file_hash}")
                return {}
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"VirusTotal API request failed for {file_hash}: {e}")
            return {}
        except ValueError as e:
            self.logger.error(f"Failed to parse VirusTotal response for {file_hash}: {e}")
            return {}
    
    def get_ip_report(self, ip_address: str) -> Dict[str, Any]:
        """
        Get an IP address report from VirusTotal.
        
        Args:
            ip_address: IP address to query
            
        Returns:
            Dictionary with IP reputation data
        """
        if not ip_address or not self.api_key:
            return {}
            
        self._rl.wait_if_needed()
        
        params = {
            'apikey': self.api_key,
            'ip': ip_address
        }
        
        try:
            response = self.session.get(f"{self.base_url}/ip-address/report", params=params)
            response.raise_for_status()
            
            content_type = response.headers.get('content-type', '')
            if 'application/json' not in content_type:
                self.logger.error(f"VirusTotal returned non-JSON response for IP {ip_address}")
                return {}
                
            data = response.json()
            
            if data.get('response_code') == 0:
                self.logger.info(f"VirusTotal: IP {ip_address} not found")
                return {}
                
            return data
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"VirusTotal IP request failed for {ip_address}: {e}")
            return {}
        except ValueError as e:
            self.logger.error(f"Failed to parse VirusTotal IP response for {ip_address}: {e}")
            return {}
    
    def get_domain_report(self, domain: str) -> Dict[str, Any]:
        """
        Get a domain report from VirusTotal.
        
        Args:
            domain: Domain to query
            
        Returns:
            Dictionary with domain reputation data
        """
        if not domain or not self.api_key:
            return {}
            
        self._rl.wait_if_needed()
        
        params = {
            'apikey': self.api_key,
            'domain': domain
        }
        
        try:
            response = self.session.get(f"{self.base_url}/domain/report", params=params)
            response.raise_for_status()
            
            content_type = response.headers.get('content-type', '')
            if 'application/json' not in content_type:
                self.logger.error(f"VirusTotal returned non-JSON response for domain {domain}")
                return {}
                
            data = response.json()
            
            if data.get('response_code') == 0:
                self.logger.info(f"VirusTotal: Domain {domain} not found")
                return {}
                
            return data
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"VirusTotal domain request failed for {domain}: {e}")
            return {}
        except ValueError as e:
            self.logger.error(f"Failed to parse VirusTotal domain response for {domain}: {e}")
            return {}

    def get_file_scan_id(self, file_hash: str) -> Optional[str]:
        """
        Get scan ID for a file (for re-scanning if needed).
        
        Args:
            file_hash: Hash of the file
            
        Returns:
            Scan ID or None if not found
        """
        report = self.get_file_report(file_hash)
        return report.get('scan_id') if report else None
    
    def rescan_file(self, file_hash: str) -> Dict[str, Any]:
        """
        Request a rescan of a file.
        
        Args:
            file_hash: Hash of the file to rescan
            
        Returns:
            Rescan response data
        """
        self._rl.wait_if_needed()
        
        params = {
            'apikey': self.api_key,
            'resource': file_hash
        }
        
        try:
            response = self.session.post(f"{self.base_url}/file/rescan", data=params, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            if data.get('response_code') == 1:
                self.logger.info(f"VirusTotal: Rescan requested for {file_hash}")
                return data
            else:
                self.logger.warning(f"VirusTotal: Rescan failed for {file_hash}: {data.get('verbose_msg', 'Unknown error')}")
                return {}
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"VirusTotal rescan request failed for {file_hash}: {e}")
            return {}


def build_cache_key(source: str, ioc_type: str, ioc_value: str) -> str:
    """Build a cache key for VirusTotal results."""
    h = hashlib.sha256()
    h.update(f"{source}|{ioc_type}|{ioc_value}".encode("utf-8"))
    return h.hexdigest()


def to_threat_intel(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize VirusTotal response into a compact structure."""
    if not payload:
        return {
            'queried_at': datetime.utcnow().isoformat(),
            'query_status': 'no_result',
            'is_malicious': False,
        }
    
    response_code = payload.get('response_code', 0)
    
    intel: Dict[str, Any] = {
        'queried_at': datetime.utcnow().isoformat(),
        'query_status': 'ok' if response_code == 1 else 'no_result',
        'is_malicious': False,
    }
    
    if response_code == 1:
        positives = payload.get('positives', 0)
        total = payload.get('total', 0)
        
        intel.update({
            'positives': positives,
            'total': total,
            'scan_date': payload.get('scan_date'),
            'permalink': payload.get('permalink'),
            'resource': payload.get('resource'),
            'scan_id': payload.get('scan_id'),
            'sha256': payload.get('sha256'),
            'sha1': payload.get('sha1'),
            'md5': payload.get('md5'),
        })
        
        # Determine if malicious based on detection ratio
        if positives > 0:
            intel['is_malicious'] = True
            intel['detection_ratio'] = f"{positives}/{total}"
            intel['severity'] = 'high' if positives >= 10 else 'medium' if positives >= 3 else 'low'
        
        # Add scan results summary
        scans = payload.get('scans', {})
        if scans:
            detected_engines = {engine: result for engine, result in scans.items() if result.get('detected', False)}
            intel['detected_by'] = list(detected_engines.keys())
            intel['detection_count'] = len(detected_engines)
    
    return intel


def to_threat_intel_ip_domain(payload: Dict[str, Any], ip_address: str = '') -> Dict[str, Any]:
    """Normalize VirusTotal IP/domain response into a compact structure."""
    if not payload:
        return {
            'queried_at': datetime.utcnow().isoformat(),
            'query_status': 'no_result',
            'is_malicious': False,
        }
    
    response_code = payload.get('response_code', 0)
    
    intel: Dict[str, Any] = {
        'queried_at': datetime.utcnow().isoformat(),
        'query_status': 'ok' if response_code == 1 else 'no_result',
        'is_malicious': False,
    }
    
    if response_code == 1:
        # For IP/domain, VirusTotal provides different fields
        detected_urls = payload.get('detected_urls', []) or []
        resolutions = payload.get('resolutions', []) or []
        detected_downloaded_samples = payload.get('detected_downloaded_samples', []) or []
        detected_communicating_samples = payload.get('detected_communicating_samples', []) or []
        detected_referrer_samples = payload.get('detected_referrer_samples', []) or []

        url_entries = [u for u in detected_urls if isinstance(u, dict)]
        malicious_url_entries = [u for u in url_entries if (u.get('positives', 0) or 0) > 0]
        malicious_urls = len(malicious_url_entries)

        # Use URL scan stats as context-only. Take the max positives/total among detected malicious URLs.
        max_positives = 0
        max_total = 0
        for u in malicious_url_entries:
            try:
                p = int(u.get('positives', 0) or 0)
                t = int(u.get('total', 0) or 0)
            except Exception:
                continue
            if p > max_positives:
                max_positives = p
                max_total = t

        downloaded_samples = [s for s in detected_downloaded_samples if isinstance(s, dict)]
        communicating_samples = [s for s in detected_communicating_samples if isinstance(s, dict)]
        referrer_samples = [s for s in detected_referrer_samples if isinstance(s, dict)]

        malicious_downloaded_samples = [s for s in downloaded_samples if (s.get('positives', 0) or 0) > 0]
        malicious_communicating_samples = [s for s in communicating_samples if (s.get('positives', 0) or 0) > 0]
        malicious_referrer_samples = [s for s in referrer_samples if (s.get('positives', 0) or 0) > 0]

        intel.update({
            'detected_urls_count': len(detected_urls),
            'malicious_urls_count': malicious_urls,
            'resolutions_count': len(resolutions),
            'downloaded_samples_count': len(detected_downloaded_samples),
            'communicating_samples_count': len(detected_communicating_samples),
            'referrer_samples_count': len(detected_referrer_samples),
            'malicious_samples_count': (len(malicious_downloaded_samples) + len(malicious_communicating_samples) + len(malicious_referrer_samples)),
            'downloaded_malicious_samples_count': len(malicious_downloaded_samples),
            'communicating_malicious_samples_count': len(malicious_communicating_samples),
            'referrer_malicious_samples_count': len(malicious_referrer_samples),
            'positives': max_positives,
            'total': max_total,
            'country': payload.get('country'),
            'as_owner': payload.get('as_owner'),
            'asn': payload.get('asn'),
        })

        # VT domain/IP reports are contextual (URLs and sample relationships), not a direct verdict on the IOC.
        # Do not set is_malicious=True based on these associations.
        detected_urls_count = len(detected_urls)
        malicious_url_ratio = (malicious_urls / max(detected_urls_count, 1)) if detected_urls_count else 0.0

        if malicious_downloaded_samples or malicious_communicating_samples or malicious_referrer_samples:
            intel['associated_malware_samples'] = True
        if malicious_urls > 0:
            intel['hosts_malicious_urls'] = True

        intel['ioc_context'] = {
            'detected_urls_count': detected_urls_count,
            'malicious_urls_ratio': malicious_url_ratio,
        }
        
        # Add URL details if present
        if detected_urls:
            intel['url_details'] = detected_urls[:5]  # Limit to first 5
        
        # Add resolution details if present
        if resolutions:
            intel['resolution_details'] = resolutions[:5]  # Limit to first 5
    
    return intel
