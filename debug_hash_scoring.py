#!/usr/bin/env python3

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from pulselens.input.validator import IOCValidator
from pulselens.classification.severity import SeverityClassifier

def test_hash_scoring():
    # Test hash
    test_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"  # 32 chars = MD5
    
    # Step 1: Validate the hash
    validator = IOCValidator()
    is_valid, ioc_type, normalized_value = validator.validate_ioc(test_hash)
    print(f"Hash validation result:")
    print(f"  Valid: {is_valid}")
    print(f"  Type: {ioc_type}")
    print(f"  Normalized: {normalized_value}")
    
    # Step 2: Create IOC dict for scoring
    ioc_dict = {
        'ioc_type': ioc_type,
        'ioc_value': normalized_value,
        'enrichment': {
            'verdict': None,  # No verdict for benign hash
            'threat_intel': {
                'pulses': []  # No pulses
            }
        },
        'tags': []
    }
    
    # Step 3: Score the IOC
    config_dict = {}
    classifier = SeverityClassifier(config_dict)
    score = classifier._calculate_severity_score(ioc_dict)
    severity = classifier._determine_severity_level(score, ioc_dict)
    
    print(f"\nScoring result:")
    print(f"  Score: {score}")
    print(f"  Severity: {severity}")
    
    # Step 4: Test with malicious hash
    print(f"\n--- Testing malicious hash ---")
    malicious_ioc = ioc_dict.copy()
    malicious_ioc['enrichment']['verdict'] = 'malicious'
    malicious_ioc['enrichment']['threat_intel']['pulses'] = ['pulse1', 'pulse2', 'pulse3']  # 3 pulses
    malicious_ioc['tags'] = ['test-malware']
    
    malicious_score = classifier._calculate_severity_score(malicious_ioc)
    malicious_severity = classifier._determine_severity_level(malicious_score, malicious_ioc)
    
    print(f"Malicious hash score: {malicious_score}")
    print(f"Malicious hash severity: {malicious_severity}")

if __name__ == "__main__":
    test_hash_scoring()
