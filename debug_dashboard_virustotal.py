#!/usr/bin/env python3

import sys
sys.path.append('.')
from pulselens.enrichment.enrich import IOCEnricher
import config

# Test VirusTotal initialization with dashboard configuration
print('Testing VirusTotal initialization with dashboard config...')

# Use the same configuration as dashboard_runner.py
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
    'SEVERITY_THRESHOLDS': getattr(config, 'SEVERITY_THRESHOLDS', {}),
    'IOC_TYPE_WEIGHTS': getattr(config, 'IOC_TYPE_WEIGHTS', {}),
    'DEFAULT_CONFIDENCE': getattr(config, 'DEFAULT_CONFIDENCE', 'medium'),
    'AUTO_CLEANUP_CACHE': getattr(config, 'AUTO_CLEANUP_CACHE', True)
}

print(f'VIRUSTOTAL_ENABLED: {config_dict.get("VIRUSTOTAL_ENABLED")}')
print(f'VIRUSTOTAL_API_KEY: {"Set" if config_dict.get("VIRUSTOTAL_API_KEY") else "Not set"}')

try:
    enricher = IOCEnricher(config_dict)
    
    print(f'OTX client: {"Initialized" if enricher.otx_client else "Not initialized"}')
    print(f'VirusTotal client: {"Initialized" if enricher.virustotal_client else "Not initialized"}')
    print(f'ThreatFox client: {"Initialized" if enricher.threatfox_client else "Not initialized"}')
    print(f'URLhaus client: {"Initialized" if enricher.urlhaus_client else "Not initialized"}')
    
    # Test the problematic hash
    test_hash = '7da44f06b7d550a73212111e49d29359'
    print(f'\nTesting hash: {test_hash}')
    
    ioc = {'ioc_value': test_hash, 'ioc_type': 'hash'}
    enriched = enricher.enrich_single_ioc(ioc, use_cache=False)
    
    sources = enriched.get('enrichment', {}).get('sources', [])
    print(f'Enrichment sources: {sources}')
    
    threat_intel = enriched.get('enrichment', {}).get('threat_intel', {})
    vt_data = threat_intel.get('virustotal', {})
    if vt_data:
        print(f'VirusTotal data found: {vt_data.get("is_malicious")} ({vt_data.get("positives", 0)}/{vt_data.get("total", 0)})')
    else:
        print('No VirusTotal data found')
        
    # Check scoring
    score = enricher._score_hash_ioc(enriched, enriched['enrichment'])
    print(f'Calculated hash score: {score}')

except Exception as e:
    print(f'Error: {e}')
    import traceback
    traceback.print_exc()
