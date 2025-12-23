#!/usr/bin/env python3

import sys
sys.path.append('.')
from pulselens.enrichment.otx import OTXClient
from config import OTX_API_KEY

# Test with a known malicious hash first
hash_value = "275a021bbfb6480fefbf66dfc6f8d9b3"
known_malicious = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  # Known test hash

print(f"Testing OTX API for hash: {hash_value}")
print(f"API Key: {OTX_API_KEY[:10]}..." if OTX_API_KEY else "No API Key")

try:
    client = OTXClient(api_key=OTX_API_KEY)
    
    # Test the original hash
    print(f"\n--- Testing original hash: {hash_value} ---")
    indicator_data = client.get_indicator_details(hash_value, 'file')
    
    if indicator_data:
        print(f"Indicator found: {indicator_data.get('name', 'Unknown')}")
        reputation = indicator_data.get('reputation', {})
        if isinstance(reputation, dict):
            print(f"Reputation: {reputation.get('reputation', 'Not available')}")
    else:
        print("No indicator data found (hash unknown to OTX)")
    
    # Test with known malicious hash
    print(f"\n--- Testing known malicious hash: {known_malicious} ---")
    malicious_data = client.get_indicator_details(known_malicious, 'file')
    
    if malicious_data:
        print(f"Indicator found: {malicious_data.get('name', 'Unknown')}")
        reputation = malicious_data.get('reputation', {})
        if isinstance(reputation, dict):
            print(f"Reputation: {reputation.get('reputation', 'Not available')}")
            print(f"Threat score: {malicious_data.get('threat_score', 'Not available')}")
    else:
        print("No indicator data found")
    
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
