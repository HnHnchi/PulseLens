from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import logging

from ..enrichment.otx import OTXClient
from ..enrichment.urlhaus import URLhausClient as _URLhausClient
from ..enrichment.urlhaus import build_cache_key as _urlhaus_cache_key
from ..enrichment.urlhaus import to_threat_intel as _urlhaus_to_intel
from ..enrichment.threatfox import ThreatFoxClient as _ThreatFoxClient
from ..enrichment.threatfox import build_cache_key as _threatfox_cache_key
from ..enrichment.threatfox import to_threat_intel as _threatfox_to_intel
from ..enrichment.virustotal import VirusTotalClient as _VirusTotalClient
from ..enrichment.virustotal import build_cache_key as _virustotal_cache_key
from ..enrichment.virustotal import to_threat_intel as _virustotal_to_intel
from ..enrichment.virustotal import to_threat_intel_ip_domain as _virustotal_to_intel_ip_domain

class IOCEnricher:
    """Main enrichment engine for IOCs."""
    
    def __init__(self, config: Dict, db: Optional[Any] = None):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.db = db
        
        # Initialize OTX client if API key is provided
        self.otx_client = None
        if config.get('OTX_API_KEY'):
            self.otx_client = OTXClient(
                api_key=config['OTX_API_KEY'],
                base_url=config.get('OTX_BASE_URL', 'https://otx.alienvault.com/api/v1'),
                rate_limit=config.get('OTX_RATE_LIMIT', 60)
            )
        else:
            self.logger.warning("No OTX API key provided - enrichment will be limited")

        self.urlhaus_client: Optional[_URLhausClient] = None
        if config.get('URLHAUS_ENABLED', True):
            try:
                self.urlhaus_client = _URLhausClient(
                    base_url=config.get('URLHAUS_BASE_URL', 'https://urlhaus-api.abuse.ch/v1'),
                    rate_limit=config.get('URLHAUS_RATE_LIMIT', 60),
                    auth_key=config.get('URLHAUS_API_KEY')
                )
            except Exception as e:
                self.logger.error(f"Failed to initialize URLhaus client: {e}")
                self.urlhaus_client = None

        self.threatfox_client: Optional[_ThreatFoxClient] = None
        if config.get('THREATFOX_ENABLED', True):
            try:
                self.threatfox_client = _ThreatFoxClient(
                    base_url=config.get('THREATFOX_BASE_URL', 'https://threatfox-api.abuse.ch/api/v1'),
                    rate_limit=config.get('THREATFOX_RATE_LIMIT', 60),
                    auth_key=config.get('THREATFOX_API_KEY')
                )
            except Exception as e:
                self.logger.error(f"Failed to initialize ThreatFox client: {e}")
                self.threatfox_client = None

        # Initialize VirusTotal client if API key is provided and enabled
        self.virustotal_client: Optional[_VirusTotalClient] = None
        if config.get('VIRUSTOTAL_ENABLED', True) and config.get('VIRUSTOTAL_API_KEY'):
            try:
                self.virustotal_client = _VirusTotalClient(
                    api_key=config['VIRUSTOTAL_API_KEY'],
                    base_url=config.get('VIRUSTOTAL_BASE_URL', 'https://www.virustotal.com/vtapi/v2'),
                    rate_limit=config.get('VIRUSTOTAL_RATE_LIMIT', 4)
                )
                self.logger.info("VirusTotal client initialized successfully")
            except Exception as e:
                self.logger.error(f"Failed to initialize VirusTotal client: {e}")
                self.virustotal_client = None
        else:
            self.logger.warning("VirusTotal disabled or no API key provided - hash enrichment will be limited")
    
    def enrich_iocs(self, iocs: List[Dict], use_cache: bool = True) -> List[Dict]:
        """
        Enrich multiple IOCs with threat intelligence data.
        
        Args:
            iocs: List of normalized IOC dictionaries
            use_cache: Whether to use cached results
            
        Returns:
            List of enriched IOC dictionaries
        """
        enriched_iocs = []
        
        for ioc in iocs:
            try:
                enriched_ioc = self.enrich_single_ioc(ioc, use_cache)
                enriched_iocs.append(enriched_ioc)
            except Exception as e:
                self.logger.error(f"Failed to enrich IOC {ioc.get('ioc_value', 'unknown')}: {e}")
                # Add original IOC with error info
                ioc['enrichment_error'] = str(e)
                enriched_iocs.append(ioc)
        
        return enriched_iocs
    
    def enrich_single_ioc(self, ioc: Dict, use_cache: bool = True) -> Dict:
        """
        Enrich a single IOC with threat intelligence data.
        
        Args:
            ioc: Normalized IOC dictionary
            use_cache: Whether to use cached results
            
        Returns:
            Enriched IOC dictionary
        """
        enriched = ioc.copy()
        
        # Initialize enrichment data
        enriched['enrichment'] = {
            'enriched_at': datetime.utcnow().isoformat(),
            'sources': [],
            'reputation': {
                'overall': 'unknown',
                'score': 0,
                'confidence': 'low'
            },
            'threat_intel': {},
            'metadata': {}
        }

        # Feed/DB hit lookup (if this IOC exists from prior feed ingestion)
        if self.db:
            try:
                existing = self.db.get_ioc(ioc.get('ioc_value', ''), ioc.get('ioc_type', ''))
                if existing:
                    feed_source = existing.get('feed_source')
                    existing_tags = existing.get('tags', [])
                    if (feed_source and feed_source != 'manual') or ('feed' in existing_tags):
                        enriched['enrichment']['threat_intel']['feeds'] = {
                            'hit': True,
                            'feed_source': feed_source or 'unknown',
                            'confidence': existing.get('confidence', 'medium'),
                            'tags': list(existing_tags) if isinstance(existing_tags, list) else [],
                            'metadata': existing.get('metadata', {}) if isinstance(existing.get('metadata', {}), dict) else {},
                            'last_seen': existing.get('last_seen'),
                        }
                        if feed_source and feed_source not in enriched['enrichment']['sources']:
                            enriched['enrichment']['sources'].append(feed_source)
            except Exception:
                pass
        
        # Enrich with OTX if available
        if self.otx_client:
            try:
                otx_enriched = self.otx_client.enrich_indicator(ioc)
                self._merge_otx_data(enriched, otx_enriched)
                if 'otx' not in enriched['enrichment']['sources']:
                    enriched['enrichment']['sources'].append('otx')
            except Exception as e:
                self.logger.error(f"OTX enrichment failed for {ioc.get('ioc_value')}: {e}")
                enriched['enrichment']['otx_error'] = str(e)

        if self.urlhaus_client:
            try:
                urlhaus_intel = self._enrich_urlhaus(ioc, use_cache=use_cache)
                if urlhaus_intel is not None:
                    enriched['enrichment']['threat_intel']['urlhaus'] = urlhaus_intel
                    if 'urlhaus' not in enriched['enrichment']['sources']:
                        enriched['enrichment']['sources'].append('urlhaus')
                    if urlhaus_intel.get('is_malicious'):
                        enriched.setdefault('tags', []).append('urlhaus_flagged')
                        enriched.setdefault('tags', []).append('malicious')
            except Exception as e:
                self.logger.error(f"URLhaus enrichment failed for {ioc.get('ioc_value')}: {e}")
                enriched['enrichment']['urlhaus_error'] = str(e)

        if self.threatfox_client:
            try:
                threatfox_intel = self._enrich_threatfox(ioc, use_cache=use_cache)
                if threatfox_intel is not None:
                    enriched['enrichment']['threat_intel']['threatfox'] = threatfox_intel
                    if 'threatfox' not in enriched['enrichment']['sources']:
                        enriched['enrichment']['sources'].append('threatfox')
                    if threatfox_intel.get('is_malicious'):
                        enriched.setdefault('tags', []).append('threatfox_flagged')
                        enriched.setdefault('tags', []).append('malicious')
            except Exception as e:
                self.logger.error(f"ThreatFox enrichment failed for {ioc.get('ioc_value')}: {e}")
                enriched['enrichment']['threatfox_error'] = str(e)
        
        # Enrich with VirusTotal if available
        if self.virustotal_client:
            try:
                virustotal_intel = self._enrich_virustotal(ioc, use_cache=use_cache)
                if virustotal_intel is not None:
                    enriched['enrichment']['threat_intel']['virustotal'] = virustotal_intel
                    if 'virustotal' not in enriched['enrichment']['sources']:
                        enriched['enrichment']['sources'].append('virustotal')
                    if virustotal_intel.get('is_malicious'):
                        enriched.setdefault('tags', []).append('virustotal_flagged')
                        enriched.setdefault('tags', []).append('malicious')
            except Exception as e:
                self.logger.error(f"VirusTotal enrichment failed for {ioc.get('ioc_value')}: {e}")
                enriched['enrichment']['virustotal_error'] = str(e)
        
        # Add general enrichment based on IOC type
        self._add_general_enrichment(enriched)
        
        # Calculate overall reputation
        self._calculate_overall_reputation(enriched)
        
        return enriched
    
    def _merge_otx_data(self, enriched: Dict, otx_enriched: Dict) -> None:
        """Merge OTX enrichment data into the main enrichment structure."""
        if 'otx_data' not in otx_enriched:
            return
        
        otx_data = otx_enriched['otx_data']
        
        details = otx_data.get('details', {})
        details_validation = []
        if isinstance(details, dict):
            dv = details.get('validation', [])
            details_validation = dv if isinstance(dv, list) else []

        # Update threat intelligence data
        enriched['enrichment']['threat_intel']['otx'] = {
            'reputation': otx_data.get('reputation', {}),
            'pulse_count': otx_data.get('pulse_count', 0),
            'pulses': otx_data.get('pulses', []),
            'references': otx_data.get('references', []),
            'details_validation': details_validation,
            'malicious_samples': otx_data.get('reputation', {}).get('malicious_samples', 0),
            'threat_score': otx_data.get('reputation', {}).get('threat_score', 0),
            'first_seen': otx_data.get('reputation', {}).get('first_seen'),
            'last_seen': otx_data.get('reputation', {}).get('last_seen')
        }
        
        # Merge OTX tags
        if 'tags' in otx_enriched:
            enriched['tags'] = list(set(enriched.get('tags', []) + otx_enriched['tags']))
        
        # Add OTX metadata
        enriched['enrichment']['metadata']['otx_enriched'] = True
        enriched['enrichment']['metadata']['otx_enriched_at'] = otx_data.get('enriched_at')
    
    def _add_general_enrichment(self, ioc: Dict) -> None:
        """Add general enrichment based on IOC characteristics."""
        ioc_type = ioc['ioc_type']
        ioc_value = ioc['ioc_value']
        
        # Add type-specific enrichment
        if ioc_type == 'ip':
            self._enrich_ip(ioc)
        elif ioc_type == 'domain':
            self._enrich_domain(ioc)
        elif ioc_type == 'url':
            self._enrich_url(ioc)
        elif ioc_type == 'hash':
            self._enrich_hash(ioc)
        elif ioc_type == 'email':
            self._enrich_email(ioc)
        
        # Add temporal context
        self._add_temporal_context(ioc)
        
        # Add risk factors
        self._add_risk_factors(ioc)
    
    def _enrich_ip(self, ioc: Dict) -> None:
        """Enrich IP address IOC."""
        metadata = ioc.get('metadata', {})
        
        # Add geolocation context (placeholder - would need external service)
        enriched_geo = {
            'country': 'unknown',
            'asn': 'unknown',
            'is_tor_exit': False,
            'is_proxy': False
        }
        
        ioc['enrichment']['threat_intel']['geo'] = enriched_geo
        
        # Add network context
        if metadata.get('is_private'):
            ioc.setdefault('tags', []).append('internal_network')
        else:
            ioc.setdefault('tags', []).append('external_network')
    
    def _enrich_domain(self, ioc: Dict) -> None:
        """Enrich domain IOC."""
        metadata = ioc.get('metadata', {})
        
        # Add domain-specific context
        domain_age_days = self._estimate_domain_age(ioc['ioc_value'])
        ioc['enrichment']['threat_intel']['domain'] = {
            'estimated_age_days': domain_age_days,
            'is_suspicious_tld': self._is_suspicious_tld(metadata.get('tld')),
            'dga_probability': self._calculate_dga_probability(ioc['ioc_value'])
        }
        
        # Add tags based on domain characteristics
        if domain_age_days and domain_age_days < 30:
            ioc.setdefault('tags', []).append('newly_registered')
        if self._is_suspicious_tld(metadata.get('tld')):
            ioc.setdefault('tags', []).append('suspicious_tld')
    
    def _enrich_url(self, ioc: Dict) -> None:
        """Enrich URL IOC."""
        metadata = ioc.get('metadata', {})
        
        # Add URL-specific context
        ioc['enrichment']['threat_intel']['url'] = {
            'url_length': len(ioc['ioc_value']),
            'suspicious_patterns': self._detect_url_patterns(ioc['ioc_value']),
            'file_extension': self._extract_file_extension(metadata.get('path', '')),
            'is_shortened': self._is_url_shortened(ioc['ioc_value'])
        }
        
        # Add tags based on URL characteristics
        if len(ioc['ioc_value']) > 200:
            ioc.setdefault('tags', []).append('long_url')
        if self._is_url_shortened(ioc['ioc_value']):
            ioc.setdefault('tags', []).append('url_shortener')
    
    def _enrich_hash(self, ioc: Dict) -> None:
        """Enrich hash IOC."""
        metadata = ioc.get('metadata', {})
        
        # Add hash-specific context
        ioc['enrichment']['threat_intel']['hash'] = {
            'hash_type': metadata.get('hash_type'),
            'is_known_malware': self._check_known_malware_hash(ioc['ioc_value']),
            'file_type': self._guess_file_type_from_hash(ioc['ioc_value'])
        }
        
        # Add tags based on hash characteristics
        if self._check_known_malware_hash(ioc['ioc_value']):
            ioc.setdefault('tags', []).append('known_malware')
    
    def _enrich_email(self, ioc: Dict) -> None:
        """Enrich email IOC."""
        metadata = ioc.get('metadata', {})
        
        # Add email-specific context
        ioc['enrichment']['threat_intel']['email'] = {
            'is_free_provider': metadata.get('is_free_provider', False),
            'domain_reputation': self._assess_email_domain_reputation(metadata.get('domain')),
            'has_suspicious_pattern': self._detect_email_patterns(ioc['ioc_value'])
        }
        
        # Add tags based on email characteristics
        if metadata.get('is_free_provider'):
            ioc.setdefault('tags', []).append('free_email_provider')
    
    def _add_temporal_context(self, ioc: Dict) -> None:
        """Add temporal context to IOC."""
        current_time = datetime.utcnow()
        
        # Add temporal metadata
        ioc['enrichment']['metadata']['temporal_context'] = {
            'processed_at': current_time.isoformat(),
            'days_since_first_seen': self._calculate_days_since(ioc.get('first_seen')),
            'is_recent': self._is_recent_ioc(ioc.get('first_seen'))
        }
        
        # Add temporal tags
        if self._is_recent_ioc(ioc.get('first_seen')):
            ioc.setdefault('tags', []).append('recent_threat')
    
    def _add_risk_factors(self, ioc: Dict) -> None:
        """Add risk factor analysis to IOC."""
        risk_factors = []
        risk_score = 0
        
        # Analyze existing tags for risk factors
        tags = ioc.get('tags', [])
        
        if 'malicious' in tags:
            risk_factors.append('malicious_reputation')
            risk_score += 30
        if 'suspicious' in tags:
            risk_factors.append('suspicious_reputation')
            risk_score += 20
        if 'known_malware' in tags:
            risk_factors.append('known_malware_hash')
            risk_score += 25
        if 'newly_registered' in tags:
            risk_factors.append('new_domain')
            risk_score += 15
        if 'url_shortener' in tags:
            risk_factors.append('url_shortening_service')
            risk_score += 10
        
        # Add risk assessment
        ioc['enrichment']['risk_assessment'] = {
            'risk_factors': risk_factors,
            'risk_score': min(risk_score, 100),  # Cap at 100
            'risk_level': self._determine_risk_level(risk_score)
        }
    
    def _score_ip_domain_ioc(self, ioc: Dict, enrichment: Dict) -> float:
        """Score IP/domain IOCs with infrastructure-aware scoring (different from hashes)."""
        score = 5  # baseline
        
        # Get OTX verdict from threat intel
        otx_data = enrichment.get('threat_intel', {}).get('otx', {})
        otx_verdict = otx_data.get('reputation', {}).get('reputation', 'unknown')
        otx_pulses = otx_data.get('pulse_count', 0)

        # Domain scoring should consider pulse tags (C2/phishing/botnet) but avoid broad/noisy pulses.
        high_signal_tags = {
            'c2', 'command and control', 'botnet',
            'phishing', 'credential', 'credential theft'
        }

        otx_pulse_tags = set()
        high_signal_pulse_count = 0
        otx_pulses_list = otx_data.get('pulses', [])
        if isinstance(otx_pulses_list, list):
            for p in otx_pulses_list[:25]:
                if not isinstance(p, dict):
                    continue
                tags = p.get('tags', [])
                if isinstance(tags, list):
                    pulse_has_high_signal = False
                    for t in tags:
                        if isinstance(t, str) and t:
                            tt = t.strip().lower()
                            otx_pulse_tags.add(tt)
                            if tt in high_signal_tags:
                                pulse_has_high_signal = True
                    if pulse_has_high_signal:
                        high_signal_pulse_count += 1

        # Strong clean signal from OTX validations (whitelist/false_positive).
        otx_validations = otx_data.get('details_validation', [])
        is_otx_whitelisted = False
        if isinstance(otx_validations, list):
            for row in otx_validations:
                if not isinstance(row, dict):
                    continue
                src = str(row.get('source') or '').lower()
                name = str(row.get('name') or '').lower()
                msg = str(row.get('message') or '').lower()
                if src in {'whitelist', 'false_positive'} or 'whitelist' in name or 'false positive' in name or 'whitelist' in msg:
                    is_otx_whitelisted = True
                    break
        
        # Get VirusTotal verdict from threat intel
        vt_data = enrichment.get('threat_intel', {}).get('virustotal', {})
        vt_is_malicious = vt_data.get('is_malicious', False)
        vt_positives = vt_data.get('positives', 0)
        vt_total = vt_data.get('total', 0)
        vt_malicious_urls = vt_data.get('malicious_urls_count', 0)
        vt_detected_urls = vt_data.get('detected_urls_count', 0)
        vt_detected_ratio = vt_detected_urls and (vt_malicious_urls / max(vt_detected_urls, 1)) or 0.0
        vt_engine_ratio = vt_total and (vt_positives / max(vt_total, 1)) or 0.0
        
        # Get URLhaus verdict
        urlhaus_data = enrichment.get('threat_intel', {}).get('urlhaus', {})
        urlhaus_malicious = urlhaus_data.get('is_malicious', False)
        
        # Get ThreatFox verdict
        threatfox_data = enrichment.get('threat_intel', {}).get('threatfox', {})
        threatfox_malicious = threatfox_data.get('is_malicious', False)
        threatfox_matches = threatfox_data.get('match_count', 0)
        
        # Priority 1: OTX malicious verdict (strongest signal for infrastructure)
        if otx_verdict == 'malicious':
            score = max(score, 45)
        elif otx_verdict == 'suspicious':
            score = max(score, 30)

        # Domain-specific OTX scoring (pulse counts + tags)
        if ioc.get('ioc_type') == 'domain':
            # Pulse count alone can be misleading (benign/dual-use domains often appear in many pulses).
            # Only allow pulse count to drive MEDIUM/HIGH when paired with strong domain-level tags.
            has_high_signal = False
            if otx_pulses and high_signal_pulse_count:
                ratio = high_signal_pulse_count / max(int(otx_pulses) or 0, 1)
                # Dedicated infra: small pulse set with any high-signal pulse
                if int(otx_pulses) <= 3 and high_signal_pulse_count >= 1:
                    has_high_signal = True
                # Repeated infra: multiple high-signal pulses
                elif high_signal_pulse_count >= 3:
                    has_high_signal = True
                # Strong concentration
                elif ratio >= 0.5 and high_signal_pulse_count >= 2:
                    has_high_signal = True

            if has_high_signal:
                if otx_pulses >= 10:
                    score += 40
                elif otx_pulses >= 3:
                    score += 25
                elif otx_pulses >= 1:
                    score += 10
                score += 30
            else:
                # Weak/noisy signal: keep it small.
                if otx_pulses >= 10:
                    score += 5
                elif otx_pulses >= 3:
                    score += 3
                elif otx_pulses >= 1:
                    score += 1
        
        # Priority 2: VirusTotal analysis with context awareness
        if vt_is_malicious and vt_positives > 0:
            detection_ratio = vt_positives / max(vt_total, 1)
            malicious_url_ratio = vt_malicious_urls / max(vt_detected_urls, 1)
            
            # For infrastructure, consider the scale and context
            # High-volume legitimate domains (like google.com) will have some malicious URLs
            # but the ratio should be very low
            if vt_detected_urls >= 1000:  # High-volume domain
                # Require very high malicious URL ratio for high-volume domains
                if malicious_url_ratio >= 0.1:  # 10%+ malicious URLs
                    score = max(score, 50)
                elif malicious_url_ratio >= 0.05:  # 5%+ malicious URLs
                    score = max(score, 35)
                elif malicious_url_ratio >= 0.01:  # 1%+ malicious URLs
                    score = max(score, 20)
            elif vt_detected_urls >= 100:  # Medium-volume domain
                # Moderate thresholds for medium-volume domains
                if malicious_url_ratio >= 0.2:  # 20%+ malicious URLs
                    score = max(score, 45)
                elif malicious_url_ratio >= 0.1:  # 10%+ malicious URLs
                    score = max(score, 30)
                elif malicious_url_ratio >= 0.05:  # 5%+ malicious URLs
                    score = max(score, 18)
            else:  # Low-volume domain (likely malicious)
                # Lower thresholds for low-volume domains
                if malicious_url_ratio >= 0.3:  # 30%+ malicious URLs
                    score = max(score, 55)
                elif malicious_url_ratio >= 0.15:  # 15%+ malicious URLs
                    score = max(score, 40)
                elif malicious_url_ratio >= 0.05:  # 5%+ malicious URLs
                    score = max(score, 25)
                elif vt_malicious_urls >= 1:  # Any malicious URLs
                    score = max(score, 15)
        else:
            # Even when VirusTotal does not label the IP/domain malicious, a high malicious URL ratio
            # or detection count is a strong indicator for infrastructure abuse.
            vt_context_score = 0
            if vt_detected_urls >= 25 and vt_detected_ratio >= 0.5:
                vt_context_score = 45
            elif vt_detected_urls >= 10 and vt_detected_ratio >= 0.35:
                vt_context_score = max(vt_context_score, 35)
            elif vt_detected_urls >= 5 and vt_detected_ratio >= 0.25:
                vt_context_score = max(vt_context_score, 25)
            elif vt_malicious_urls >= 3 and vt_engine_ratio >= 0.2:
                vt_context_score = max(vt_context_score, 20)
            elif vt_malicious_urls >= 1 and vt_engine_ratio >= 0.1:
                vt_context_score = max(vt_context_score, 18)

            if vt_context_score > 0:
                score = max(score, vt_context_score)

            score += min(25, vt_malicious_urls * 2)
        
        # Priority 3: Other threat intel sources
        if urlhaus_malicious:
            score = max(score, 25)
        
        if threatfox_malicious:
            score = max(score, 20)
            # Bonus for multiple ThreatFox matches
            if threatfox_matches >= 10:
                score += 8
            elif threatfox_matches >= 5:
                score += 5
            elif threatfox_matches >= 2:
                score += 2
        
        # Pulse count bonus (OTX) - Enhanced for IPs with multi-source intelligence
        if ioc.get('ioc_type') != 'domain':
            # Base pulse count scoring
            if otx_pulses >= 10:
                score += 15
            elif otx_pulses >= 5:
                score += 8
            elif otx_pulses >= 1:
                score += 3
            
            # Bonus for IPs with multi-source threat intelligence
            multi_source_count = 0
            if otx_pulses >= 1:
                multi_source_count += 1
            if threatfox_malicious:
                multi_source_count += 1
            if vt_is_malicious or vt_malicious_urls >= 1:
                multi_source_count += 1
            if urlhaus_malicious:
                multi_source_count += 1
            
            # Additional scoring for multi-source confirmation
            if multi_source_count >= 3:
                score += 25  # Strong multi-source confirmation
            elif multi_source_count >= 2:
                score += 15  # Moderate multi-source confirmation

        # If OTX explicitly whitelists the domain or marks it false positive, keep it low.
        if ioc.get('ioc_type') == 'domain' and is_otx_whitelisted:
            score = min(score, 8)
        
        # Recent IOC bonus
        # Manual lookups set first_seen to "now" which makes everything look recent.
        # Only apply recency bonus for feed-derived IOCs.
        feed_source = str(ioc.get('feed_source') or '').lower()
        feed_hit = enrichment.get('threat_intel', {}).get('feeds', {})
        is_feed_hit = isinstance(feed_hit, dict) and bool(feed_hit.get('hit'))
        if (feed_source and feed_source != 'manual') or is_feed_hit:
            if self._is_recent_ioc(ioc.get('first_seen')):
                score += 5
        
        # Return calculated score
        return score
    
    def _score_hash_ioc(self, ioc: Dict, enrichment: Dict) -> float:
        """Score hash IOCs with OTX and VirusTotal verdict priority."""
        score = 10  # baseline
        
        # Get OTX verdict from threat intel
        otx_data = enrichment.get('threat_intel', {}).get('otx', {})
        otx_verdict = otx_data.get('reputation', {}).get('reputation', 'unknown')
        otx_pulses = otx_data.get('pulse_count', 0)
        
        # Get VirusTotal verdict from threat intel
        vt_data = enrichment.get('threat_intel', {}).get('virustotal', {})
        vt_is_malicious = vt_data.get('is_malicious', False)
        vt_positives = vt_data.get('positives', 0)
        vt_total = vt_data.get('total', 0)
        
        # Priority 1: VirusTotal malicious verdict (strongest signal)
        if vt_is_malicious and vt_positives > 0:
            # Scale score based on detection ratio
            detection_ratio = vt_positives / max(vt_total, 1)
            if detection_ratio >= 0.3:  # 30%+ detection
                score = max(score, 65)
            elif detection_ratio >= 0.1:  # 10%+ detection
                score = max(score, 50)
            else:  # Any detection
                score = max(score, 40)
            
            # Bonus for high detection counts
            if vt_positives >= 20:
                score += 15
            elif vt_positives >= 10:
                score += 10
            elif vt_positives >= 5:
                score += 5
        
        # Priority 2: OTX malicious verdict
        if otx_verdict == 'malicious':
            score = max(score, 45)
        elif otx_verdict == 'suspicious':
            score = max(score, 30)
        
        # Pulse count bonus (OTX)
        if otx_pulses >= 5:
            score += 15
        elif otx_pulses >= 1:
            score += 8
        
        # Recent IOC bonus
        feed_source = str(ioc.get('feed_source') or '').lower()
        feed_hit = enrichment.get('threat_intel', {}).get('feeds', {})
        if feed_source and 'feed' in feed_source and feed_hit:
            score += 8
        
        # Malware tags bonus
        if any('malware' in t.lower() for t in ioc.get('tags', [])):
            score += 12
        
        # Return calculated score
        return score
    
    def _calculate_overall_reputation(self, ioc: Dict) -> None:
        """Calculate overall reputation from all sources."""
        enrichment = ioc.get('enrichment', {})
        threat_intel = enrichment.get('threat_intel', {})
        
        # Start with neutral reputation
        overall_reputation = 'unknown'
        overall_score = 0
        confidence = 'low'

        evidence: Dict[str, Any] = {
            'sources': list(enrichment.get('sources', [])),
            'otx': {
                'reputation': None,
                'threat_score': 0,
                'pulse_count': 0,
                'malicious_samples': 0,
            },
            'virustotal': {
                'is_malicious': False,
                'positives': 0,
                'total': 0,
                'detection_count': 0,
            },
            'feeds': {
                'hit': False,
                'sources': [],
            },
            'urlhaus': {
                'is_malicious': False,
            },
            'threatfox': {
                'is_malicious': False,
                'match_count': 0,
            },
            'risk_assessment': {
                'risk_score': 0,
                'risk_factors': [],
            },
            'evidence_score': 0,
            'source_agreement': 0,
        }

        evidence_score = 0
        malicious_votes = 0
        suspicious_votes = 0
        clean_votes = 0
        
        # Consider OTX data if available
        otx_data = threat_intel.get('otx', {})
        otx_reputation = 'unknown'  # Default value
        if otx_data:
            otx_reputation = otx_data.get('reputation', {}).get('reputation', 'unknown')
            rep_block = otx_data.get('reputation', {}) if isinstance(otx_data.get('reputation', {}), dict) else {}

            # NOTE: OTX /pulses endpoint can 404 for some hashes even though
            # the indicator details include pulse_info.count. In that case,
            # pulse_count is present inside the reputation payload.
            otx_threat_score = int(otx_data.get('threat_score', 0) if isinstance(otx_data.get('threat_score'), (int, str)) else rep_block.get('threat_score', 0))
            otx_pulse_count = int(otx_data.get('pulse_count', 0) if isinstance(otx_data.get('pulse_count'), (int, str)) else rep_block.get('pulse_count', 0))
            otx_malicious_samples = int(otx_data.get('malicious_samples', 0) if isinstance(otx_data.get('malicious_samples', 0), (int, str)) else rep_block.get('malicious_samples', 0))

            evidence['otx'].update({
                'reputation': otx_reputation,
                'threat_score': otx_threat_score,
                'pulse_count': otx_pulse_count,
                'malicious_samples': otx_malicious_samples,
            })

            # Weighted OTX contribution (do not treat presence as automatically malicious)
            if otx_reputation == 'malicious':
                malicious_votes += 1
                evidence_score += 55
                evidence_score += min(25, otx_threat_score * 3)
                evidence_score += min(20, otx_pulse_count * 2)
                evidence_score += 20 if otx_malicious_samples > 0 else 0
            elif otx_reputation == 'suspicious':
                suspicious_votes += 1
                evidence_score += 30
                evidence_score += min(20, otx_threat_score * 2)
                evidence_score += min(15, otx_pulse_count * 2)
            elif otx_reputation == 'clean':
                clean_votes += 1
                evidence_score -= 15
            else:
                evidence_score += 0
        
        # Consider other risk factors
        risk_assessment = enrichment.get('risk_assessment', {})
        risk_score = risk_assessment.get('risk_score', 0)

        evidence['risk_assessment']['risk_score'] = int(risk_score or 0)
        evidence['risk_assessment']['risk_factors'] = list(risk_assessment.get('risk_factors', []) or [])

        # risk_score is a weak/derived signal; cap its contribution
        evidence_score += min(20, max(0, int(risk_score or 0)) // 5)

        # Consider VirusTotal data for all IOC types
        vt_data = threat_intel.get('virustotal', {})
        if vt_data and vt_data.get('is_malicious'):
            vt_positives = vt_data.get('positives', 0)
            vt_total = vt_data.get('total', 0)
            vt_detection_count = vt_data.get('detection_count', 0)
            
            # Add VirusTotal to evidence tracking
            evidence['virustotal'] = {
                'is_malicious': True,
                'positives': vt_positives,
                'total': vt_total,
                'detection_count': vt_detection_count
            }
            
            malicious_votes += 1
            # Scale score based on detection ratio and count
            detection_ratio = vt_positives / max(vt_total, 1)
            if detection_ratio >= 0.3 or vt_detection_count >= 10:  # High confidence
                evidence_score += 65
            elif detection_ratio >= 0.1 or vt_detection_count >= 5:  # Medium confidence
                evidence_score += 50
            else:  # Any detection
                evidence_score += 40
            
            # Bonus for high detection counts
            if vt_detection_count >= 20:
                evidence_score += 15
            elif vt_detection_count >= 10:
                evidence_score += 10
            elif vt_detection_count >= 5:
                evidence_score += 5
        elif vt_data:
            # Track clean/unknown VirusTotal results
            evidence['virustotal'] = {
                'is_malicious': False,
                'positives': vt_data.get('positives', 0),
                'total': vt_data.get('total', 0)
            }
            if vt_data.get('positives', 0) == 0 and vt_data.get('total', 0) > 0:
                clean_votes += 1
                evidence_score -= 10

        urlhaus_data = threat_intel.get('urlhaus', {})
        if urlhaus_data and urlhaus_data.get('is_malicious'):
            evidence['urlhaus']['is_malicious'] = True
            malicious_votes += 1
            evidence_score += 60

        threatfox_data = threat_intel.get('threatfox', {})
        if threatfox_data and threatfox_data.get('is_malicious'):
            matches = threatfox_data.get('matches', [])
            match_count = len(matches) if isinstance(matches, list) else 0
            evidence['threatfox']['is_malicious'] = True
            evidence['threatfox']['match_count'] = match_count
            suspicious_votes += 1
            evidence_score += 45
            evidence_score += min(10, match_count)

        feed_hit = threat_intel.get('feeds', {})
        if isinstance(feed_hit, dict) and feed_hit.get('hit'):
            feed_source = str(feed_hit.get('feed_source') or '').lower()
            evidence['feeds']['hit'] = True
            evidence['feeds']['sources'] = [feed_source] if feed_source else ['feed']

            # Feed hits are strong, but we still separate sources
            if 'urlhaus' in feed_source:
                malicious_votes += 1
                evidence_score += 60
            elif 'threatfox' in feed_source:
                suspicious_votes += 1
                evidence_score += 45
            else:
                suspicious_votes += 1
                evidence_score += 35

        evidence['evidence_score'] = max(0, min(100, int(round(evidence_score))))
        evidence['source_agreement'] = max(malicious_votes, suspicious_votes, clean_votes)

        # Decide normalized verdict with hash-specific logic
        ioc_type = ioc.get('ioc_type', '')
        
        # Special handling for hashes
        if ioc_type == 'hash':
            # Use the new hash scoring method that prioritizes OTX verdict
            hash_score = self._score_hash_ioc(ioc, enrichment)
            
            # Get OTX verdict for reputation decision
            otx_data = threat_intel.get('otx', {})
            otx_reputation = otx_data.get('reputation', {}).get('reputation', 'unknown')
            
            # Rule 1: Don't override malicious hashes with LOW score if they have OTX verdict
            if otx_reputation == 'malicious':
                overall_reputation = 'malicious'
                confidence = 'high'
                overall_score = hash_score
            # Rule 2: Only truly unknown hashes (no enrichment) get LOW/INFO
            elif len(evidence['sources']) == 0 and hash_score <= 15:
                overall_reputation = 'unknown'
                confidence = 'low'
                overall_score = hash_score
            # Rule 3: Pulses and recency add extra weight but are not required to get HIGH
            elif hash_score >= 45:
                overall_reputation = 'malicious'
                confidence = 'high' if otx_reputation == 'malicious' else 'medium'
                overall_score = hash_score
            elif hash_score >= 30:
                overall_reputation = 'suspicious'
                confidence = 'medium'
                overall_score = hash_score
            else:
                overall_reputation = 'unknown'
                confidence = 'low'
                overall_score = hash_score
        else:
            # Use comprehensive IP/domain scoring similar to hashes
            if ioc_type in ['ip', 'domain']:
                # Use the new IP/domain scoring method
                ip_domain_score = self._score_ip_domain_ioc(ioc, enrichment)
                
                # Get OTX verdict for reputation decision
                otx_data = threat_intel.get('otx', {})
                otx_reputation = otx_data.get('reputation', {}).get('reputation', 'unknown')
                
                # Rule 1: Don't override malicious IPs/domains with LOW score if they have OTX verdict
                if otx_reputation == 'malicious':
                    overall_reputation = 'malicious'
                    confidence = 'high'
                    overall_score = ip_domain_score
                # Rule 2: Only truly unknown IPs/domains (no enrichment) get LOW/INFO
                elif len(evidence['sources']) == 0 and ip_domain_score <= 15:
                    overall_reputation = 'unknown'
                    confidence = 'low'
                    overall_score = ip_domain_score
                # Rule 3: Pulses and recency add extra weight but are not required to get HIGH
                elif ip_domain_score >= 45:
                    overall_reputation = 'malicious'
                    confidence = 'high' if otx_reputation == 'malicious' else 'medium'
                    overall_score = ip_domain_score
                elif ip_domain_score >= 30:
                    overall_reputation = 'suspicious'
                    confidence = 'medium'
                    overall_score = ip_domain_score
                else:
                    overall_reputation = 'unknown'
                    confidence = 'low'
                    overall_score = ip_domain_score
            else:
                # Original logic for other IOC types
                if malicious_votes >= 2:
                    overall_reputation = 'malicious'
                    confidence = 'high'
                elif malicious_votes == 1 and suspicious_votes >= 1:
                    overall_reputation = 'malicious'
                    confidence = 'high'
                elif malicious_votes == 1:
                    overall_reputation = 'malicious'
                    confidence = 'medium'
                elif suspicious_votes >= 2:
                    overall_reputation = 'suspicious'
                    confidence = 'high'
                elif suspicious_votes == 1:
                    overall_reputation = 'suspicious'
                    confidence = 'medium'
                elif clean_votes >= 1 and evidence['evidence_score'] <= 10:
                    overall_reputation = 'clean'
                    confidence = 'medium' if clean_votes >= 1 else 'low'
                else:
                    overall_reputation = 'unknown'
                    confidence = 'low'
                
                overall_score = evidence['evidence_score']

        # Update enrichment with overall reputation + evidence
        ioc['enrichment']['reputation'] = {
            'overall': overall_reputation,
            'score': overall_score,
            'confidence': confidence
        }
        ioc['enrichment']['evidence'] = evidence

    def _cache_get(self, cache_key: str) -> Optional[Dict[str, Any]]:
        if not self.db:
            return None
        try:
            return self.db.get_cached_result(cache_key)
        except Exception:
            return None

    def _cache_set(self, cache_key: str, data: Dict[str, Any]) -> None:
        if not self.db:
            return
        try:
            self.db.cache_api_result(cache_key, 'virustotal', data)
        except Exception:
            return

    def _enrich_virustotal_ip(self, ioc: Dict, use_cache: bool = True) -> Optional[Dict[str, Any]]:
        """Enrich IP IOC with VirusTotal data."""
        ip_address = ioc.get('ioc_value', '')
        
        if not ip_address or not self.virustotal_client:
            return None

        cache_key = f"virustotal_ip_v4_{ip_address}"
        
        if use_cache:
            cached = self._cache_get(cache_key)
            if cached is not None:
                return cached

        try:
            payload = self.virustotal_client.get_ip_report(ip_address)
            if payload:
                vt_data = _virustotal_to_intel_ip_domain(payload, ip_address)
                if use_cache:
                    self._cache_set(cache_key, vt_data)
                return vt_data
        except Exception as e:
            self.logger.error(f"VirusTotal IP lookup failed for {ip_address}: {e}")
            
        return None
    
    def _enrich_virustotal_domain(self, ioc: Dict, use_cache: bool = True) -> Optional[Dict[str, Any]]:
        """Enrich domain IOC with VirusTotal data."""
        domain = ioc.get('ioc_value', '')
        
        if not domain or not self.virustotal_client:
            return None

        cache_key = f"virustotal_domain_v4_{domain}"
        
        if use_cache:
            cached = self._cache_get(cache_key)
            if cached is not None:
                return cached

        try:
            payload = self.virustotal_client.get_domain_report(domain)
            if payload:
                vt_data = _virustotal_to_intel_ip_domain(payload, domain)
                if use_cache:
                    self._cache_set(cache_key, vt_data)
                return vt_data
        except Exception as e:
            self.logger.error(f"VirusTotal domain lookup failed for {domain}: {e}")
            
        return None

    def _enrich_urlhaus(self, ioc: Dict, use_cache: bool = True) -> Optional[Dict[str, Any]]:
        ioc_value = ioc.get('ioc_value', '')
        ioc_type = ioc.get('ioc_type', '')

        if not ioc_value or ioc_type not in ['url', 'domain', 'ip']:
            return None

        cache_key = _urlhaus_cache_key('urlhaus', ioc_type, ioc_value)
        if use_cache:
            cached = self._cache_get(cache_key)
            if cached is not None:
                return cached

        if ioc_type == 'url':
            payload = self.urlhaus_client.lookup_url(ioc_value)
        else:
            payload = self.urlhaus_client.lookup_host(ioc_value)

        intel = _urlhaus_to_intel(payload)
        self._cache_set(cache_key, intel)
        return intel

    def _enrich_threatfox(self, ioc: Dict, use_cache: bool = True) -> Optional[Dict[str, Any]]:
        ioc_value = ioc.get('ioc_value', '')
        ioc_type = ioc.get('ioc_type', '')

        if not ioc_value or not ioc_type:
            return None

        cache_key = _threatfox_cache_key('threatfox_v2', ioc_type, ioc_value)
        if use_cache:
            cached = self._cache_get(cache_key)
            if cached is not None:
                return cached

        payload = self.threatfox_client.lookup_ioc(ioc_value)
        intel = _threatfox_to_intel(payload, ioc_value)
        self._cache_set(cache_key, intel)
        return intel
    
    # Helper methods for enrichment
    def _estimate_domain_age(self, domain: str) -> Optional[int]:
        """Estimate domain age in days (placeholder - would need WHOIS data)."""
        # This is a placeholder - in a real implementation, you would query WHOIS
        return None
    
    def _is_suspicious_tld(self, tld: str) -> bool:
        """Check if TLD is commonly associated with malicious activity."""
        suspicious_tlds = {'tk', 'ml', 'ga', 'cf', 'top', 'click', 'download'}
        return tld.lower() in suspicious_tlds if tld else False
    
    def _calculate_dga_probability(self, domain: str) -> float:
        """Calculate probability of domain being generated by DGA."""
        # Simple heuristic-based DGA detection
        score = 0.0
        
        # Check for high entropy
        if len(domain) > 12:
            score += 0.3
        
        # Check for random-looking character sequences
        vowels = sum(1 for c in domain.lower() if c in 'aeiou')
        consonants = len(domain) - vowels
        if consonants > vowels * 2:
            score += 0.4
        
        # Check for numeric sequences
        if any(char.isdigit() for char in domain):
            score += 0.3
        
        return min(score, 1.0)
    
    def _detect_url_patterns(self, url: str) -> List[str]:
        """Detect suspicious patterns in URL."""
        patterns = []
        
        # Check for IP address in URL
        if any(char.isdigit() for char in url) and '.' in url:
            patterns.append('ip_in_url')
        
        # Check for suspicious parameters
        suspicious_params = ['exec', 'cmd', 'eval', 'system', 'shell']
        for param in suspicious_params:
            if param in url.lower():
                patterns.append(f'suspicious_param_{param}')
        
        return patterns
    
    def _extract_file_extension(self, path: str) -> Optional[str]:
        """Extract file extension from URL path."""
        if '.' in path:
            return path.split('.')[-1].lower()
        return None
    
    def _is_url_shortened(self, url: str) -> bool:
        """Check if URL is from a known URL shortening service."""
        shorteners = {
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
            'is.gd', 'buff.ly', 'adf.ly', 'bit.do', 'mcaf.ee'
        }
        
        for shortener in shorteners:
            if shortener in url.lower():
                return True
        return False
    
    def _check_known_malware_hash(self, hash_value: str) -> bool:
        """Check if hash is known malware (placeholder)."""
        # This would query a malware database in a real implementation
        return False
    
    def _guess_file_type_from_hash(self, hash_value: str) -> Optional[str]:
        """Guess file type from hash (placeholder)."""
        # This would query a hash database in a real implementation
        return None
    
    def _assess_email_domain_reputation(self, domain: str) -> str:
        """Assess email domain reputation."""
        if not domain:
            return 'unknown'
        
        # Check if it's a known free provider
        free_providers = {
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com'
        }
        
        if domain.lower() in free_providers:
            return 'legitimate'
        elif self._is_suspicious_tld(domain.split('.')[-1]):
            return 'suspicious'
        else:
            return 'unknown'
    
    def _detect_email_patterns(self, email: str) -> List[str]:
        """Detect suspicious patterns in email."""
        patterns = []
        
        # Check for random-looking local part
        local_part = email.split('@')[0] if '@' in email else email
        if len(local_part) > 20 and any(char.isdigit() for char in local_part):
            patterns.append('random_local_part')
        
        return patterns
    
    def _calculate_days_since(self, date_string: str) -> Optional[int]:
        """Calculate days since a given date."""
        if not date_string:
            return None
        
        try:
            date_obj = datetime.fromisoformat(date_string.replace('Z', '+00:00'))
            days = (datetime.utcnow() - date_obj.replace(tzinfo=None)).days
            return days
        except:
            return None
    
    def _is_recent_ioc(self, date_string: str) -> bool:
        """Check if IOC is recent (within last 30 days)."""
        days = self._calculate_days_since(date_string)
        return days is not None and days <= 30
    
    def _determine_risk_level(self, risk_score: int) -> str:
        """Determine risk level from risk score."""
        if risk_score >= 70:
            return 'critical'
        elif risk_score >= 50:
            return 'high'
        elif risk_score >= 30:
            return 'medium'
        elif risk_score >= 15:
            return 'low'
        else:
            return 'minimal'
    
    def _enrich_virustotal(self, ioc: Dict, use_cache: bool = True) -> Optional[Dict[str, Any]]:
        """Enrich IOC with VirusTotal data."""
        ioc_value = ioc.get('ioc_value', '')
        ioc_type = ioc.get('ioc_type', '')
        
        if not ioc_value or not self.virustotal_client:
            return None
        
        # Route to appropriate method based on IOC type
        if ioc_type == 'ip':
            return self._enrich_virustotal_ip(ioc, use_cache=use_cache)
        elif ioc_type == 'domain':
            return self._enrich_virustotal_domain(ioc, use_cache=use_cache)
        elif ioc_type == 'hash':
            # Original hash logic
            cache_key = _virustotal_cache_key('virustotal', 'hash', ioc_value)
            if use_cache:
                cached = self._cache_get(cache_key)
                if cached is not None:
                    return cached
            
            # Get VirusTotal report
            vt_report = self.virustotal_client.get_file_report(ioc_value)
            intel = _virustotal_to_intel(vt_report)
            self._cache_set(cache_key, intel)
            return intel
        
        return None
