#!/usr/bin/env python3

import sys
sys.path.append('.')
import requests
from config import VIRUSTOTAL_API_KEY

# Debug VirusTotal API response
print('Debugging VirusTotal API response...')

try:
    # Test direct API call
    api_key = VIRUSTOTAL_API_KEY
    test_hash = '44d88612fea8a8f36de82e1278abb02f'  # EICAR
    
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {
        'apikey': api_key,
        'resource': test_hash
    }
    
    print(f"Testing API URL: {url}")
    print(f"API Key (first 10 chars): {api_key[:10]}...")
    print(f"Hash: {test_hash}")
    
    response = requests.get(url, params=params, timeout=30)
    
    print(f"Status Code: {response.status_code}")
    print(f"Headers: {dict(response.headers)}")
    print(f"Response Content-Type: {response.headers.get('content-type', 'Not specified')}")
    
    # Check if response is JSON
    if 'application/json' in response.headers.get('content-type', ''):
        try:
            data = response.json()
            print(f"JSON Response: {data}")
        except ValueError as e:
            print(f"JSON Parse Error: {e}")
            print(f"Raw Response: {response.text[:500]}...")
    else:
        print(f"Non-JSON Response: {response.text[:500]}...")
        
except Exception as e:
    print(f'Error: {e}')
    import traceback
    traceback.print_exc()
