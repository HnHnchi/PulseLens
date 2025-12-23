#!/usr/bin/env python3
"""
PulseLens - IOC Analysis System
Main entry point for command-line interface and script execution
"""

import argparse
import sys
import logging
from pathlib import Path
from datetime import datetime
import uuid
from typing import List, Dict, Optional

# Import PulseLens modules
from pulselens.input.reader import IOCReader
from pulselens.input.validator import IOCValidator
from pulselens.normalization.normalize import IOCNormalizer
from pulselens.enrichment.enrich import IOCEnricher
from pulselens.classification.severity import SeverityClassifier
from pulselens.storage.db import IOCDatabase
from pulselens.reporting.json_report import JSONReporter
from pulselens.reporting.html_report import HTMLReporter

# Import configuration
import config

class PulseLens:
    """Main PulseLens application class."""
    
    def __init__(self, config_dict: Dict):
        self.config = config_dict
        self.setup_logging()
        
        # Initialize components
        self.reader = IOCReader()
        self.validator = IOCValidator()
        self.normalizer = IOCNormalizer()
        self.enricher = None
        self.classifier = SeverityClassifier(config_dict)
        
        # Initialize database if configured
        self.db = None
        if config_dict.get('DATABASE_PATH'):
            try:
                self.db = IOCDatabase(
                    db_path=config_dict['DATABASE_PATH'],
                    cache_expiry_hours=config_dict.get('CACHE_EXPIRY_HOURS', 24)
                )
                self.logger.info("Database initialized successfully")
            except Exception as e:
                self.logger.error(f"Failed to initialize database: {e}")

        # Initialize enricher (after DB so caching can be used)
        self.enricher = IOCEnricher(config_dict, db=self.db)
        
        # Initialize reporters
        self.json_reporter = JSONReporter(config_dict)
        self.html_reporter = HTMLReporter(config_dict)
        
        self.logger.info("PulseLens initialized successfully")
    
    def setup_logging(self) -> None:
        """Setup logging configuration."""
        log_level = getattr(logging, self.config.get('LOG_LEVEL', 'INFO'))
        log_format = self.config.get('LOG_FORMAT', 
                                   '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        
        logging.basicConfig(
            level=log_level,
            format=log_format,
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler('pulselens.log')
            ]
        )
        
        self.logger = logging.getLogger(__name__)
    
    def analyze_iocs(self, 
                    input_source: str,
                    output_dir: str = "reports",
                    use_cache: bool = True,
                    save_to_db: bool = True,
                    confidence: str = 'medium') -> Dict:
        """
        Analyze IOCs from input source and generate reports.
        
        Args:
            input_source: Path to file or string containing IOCs
            output_dir: Directory to save reports
            use_cache: Whether to use cached enrichment data
            save_to_db: Whether to save results to database
            
        Returns:
            Analysis results dictionary
        """
        analysis_id = str(uuid.uuid4())
        start_time = datetime.utcnow()
        
        self.logger.info(f"Starting IOC analysis {analysis_id}")
        self.logger.info(f"Input source: {input_source}")
        
        try:
            # Step 1: Read IOCs
            self.logger.info("Step 1: Reading IOCs...")
            raw_iocs = self._read_iocs(input_source)
            self.logger.info(f"Read {len(raw_iocs)} raw IOCs")
            
            if not raw_iocs:
                self.logger.warning("No IOCs to analyze")
                return self._create_empty_result(analysis_id)
            
            # Step 2: Validate IOCs
            self.logger.info("Step 2: Validating IOCs...")
            validation_results = self.validator.validate_batch(raw_iocs)
            valid_iocs = validation_results['valid']
            invalid_iocs = validation_results['invalid']
            
            self.logger.info(f"Valid IOCs: {len(valid_iocs)}, Invalid IOCs: {len(invalid_iocs)}")
            
            if not valid_iocs:
                self.logger.warning("No valid IOCs to analyze")
                return self._create_empty_result(analysis_id, invalid_iocs)
            
            # Step 3: Normalize IOCs
            self.logger.info("Step 3: Normalizing IOCs...")
            normalized_iocs = self.normalizer.normalize_iocs(valid_iocs)
            normalized_iocs = self.normalizer.deduplicate_normalized_iocs(normalized_iocs)
            normalized_iocs = self.normalizer.enrich_with_context(normalized_iocs)
            
            self.logger.info(f"Normalized {len(normalized_iocs)} IOCs")
            
            # Step 4: Enrich IOCs
            self.logger.info("Step 4: Enriching IOCs with threat intelligence...")
            enriched_iocs = self.enricher.enrich_iocs(normalized_iocs, use_cache)
            
            self.logger.info(f"Enriched {len(enriched_iocs)} IOCs")
            
            # Step 5: Classify severity
            self.logger.info("Step 5: Classifying IOC severity...")
            # Add confidence to each IOC before classification
            for ioc in enriched_iocs:
                ioc['confidence'] = confidence
            classified_iocs = self.classifier.classify_iocs(enriched_iocs)
            
            self.logger.info(f"Classified {len(classified_iocs)} IOCs")
            
            # Step 6: Generate reports
            self.logger.info("Step 6: Generating reports...")
            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)
            
            # Generate JSON report
            json_report_path = output_path / f"pulselens_report_{analysis_id}.json"
            json_report = self.json_reporter.generate_report(
                classified_iocs, analysis_id, str(json_report_path)
            )
            
            # Generate HTML report
            html_report_path = output_path / f"pulselens_report_{analysis_id}.html"
            html_report = self.html_reporter.generate_report(
                classified_iocs, analysis_id, str(html_report_path)
            )
            
            self.logger.info(f"Reports generated: {json_report_path}, {html_report_path}")
            
            # Step 7: Save to database if configured
            if save_to_db and self.db:
                self.logger.info("Step 7: Saving to database...")
                saved_count = self.db.save_iocs(classified_iocs)
                
                # Save analysis history
                severity_summary = self.classifier.get_severity_summary(classified_iocs)
                self.db.save_analysis_history(analysis_id, len(classified_iocs), severity_summary)
                
                self.logger.info(f"Saved {saved_count} IOCs to database")
            
            # Calculate analysis duration
            end_time = datetime.utcnow()
            duration = (end_time - start_time).total_seconds()
            
            # Create result summary
            result = {
                'analysis_id': analysis_id,
                'status': 'success',
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration_seconds': duration,
                'input_source': input_source,
                'raw_ioc_count': len(raw_iocs),
                'valid_ioc_count': len(valid_iocs),
                'invalid_ioc_count': len(invalid_iocs),
                'normalized_ioc_count': len(normalized_iocs),
                'enriched_ioc_count': len(enriched_iocs),
                'classified_ioc_count': len(classified_iocs),
                'reports': {
                    'json': str(json_report_path),
                    'html': str(html_report_path)
                },
                'severity_summary': self.classifier.get_severity_summary(classified_iocs),
                'invalid_iocs': invalid_iocs
            }
            
            self.logger.info(f"Analysis {analysis_id} completed successfully in {duration:.2f} seconds")
            return result
            
        except Exception as e:
            self.logger.error(f"Analysis {analysis_id} failed: {e}")
            return {
                'analysis_id': analysis_id,
                'status': 'error',
                'error': str(e),
                'start_time': start_time.isoformat(),
                'end_time': datetime.utcnow().isoformat()
            }
    
    def _read_iocs(self, input_source: str) -> List[str]:
        """Read IOCs from various input sources."""
        input_path = Path(input_source)
        
        if input_path.exists():
            # Read from file
            return self.reader.read_from_file(input_source)
        else:
            # Treat as string containing IOCs
            return self.reader.read_from_string(input_source)
    
    def _create_empty_result(self, analysis_id: str, invalid_iocs: List[Dict] = None) -> Dict:
        """Create result for empty analysis."""
        return {
            'analysis_id': analysis_id,
            'status': 'success',
            'message': 'No valid IOCs to analyze',
            'raw_ioc_count': 0,
            'valid_ioc_count': 0,
            'invalid_ioc_count': len(invalid_iocs) if invalid_iocs else 0,
            'invalid_iocs': invalid_iocs or [],
            'severity_summary': {
                'total_iocs': 0,
                'severity_distribution': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
                'type_distribution': {},
                'average_score': 0.0,
                'high_risk_count': 0
            }
        }
    
    def get_database_stats(self) -> Optional[Dict]:
        """Get database statistics."""
        if self.db:
            return self.db.get_statistics()
        return None
    
    def cleanup_cache(self) -> Optional[int]:
        """Clean up expired cache entries."""
        if self.db:
            return self.db.cleanup_expired_cache()
        return None


def create_sample_data() -> None:
    """Create sample IOC data for testing."""
    sample_iocs = """# Sample IOC data for PulseLens testing
# IP addresses
45.77.89.12
192.168.1.100
10.0.0.1

# Domains
malicious-example.com
suspicious-site.net
legitimate-business.org

# URLs
http://malicious-example.com/malware
https://suspicious-site.net/phishing
http://legitimate-business.org/normal

# File hashes
44d88612fea8a8f36de82e1278abb02f  # EICAR test file
d41d8cd98f00b204e9800998ecf8427e  # Empty file MD5
5d41402abc4b2a76b9719d911017c592  # "hello" MD5

# Emails
attacker@malicious.com
user@suspicious-site.net
admin@legitimate-business.org
"""
    
    data_dir = Path("data")
    data_dir.mkdir(exist_ok=True)
    
    sample_file = data_dir / "sample_iocs.txt"
    with open(sample_file, 'w') as f:
        f.write(sample_iocs)
    
    print(f"Sample IOC data created at: {sample_file}")


def main():
    """Main entry point for command-line interface."""
    parser = argparse.ArgumentParser(
        description="PulseLens - IOC Analysis System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py -f data/sample_iocs.txt -o reports
  python main.py -s "45.77.89.12,malicious.com,44d88612fea8a8f36de82e1278abb02f"
  python main.py --create-sample
  python main.py --stats
        """
    )
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        '-f', '--file',
        help='Input file containing IOCs (one per line or JSON/CSV format)'
    )
    input_group.add_argument(
        '-s', '--string',
        help='String containing IOCs (comma, space, or newline separated)'
    )
    input_group.add_argument(
        '--create-sample',
        action='store_true',
        help='Create sample IOC data file for testing'
    )
    input_group.add_argument(
        '--stats',
        action='store_true',
        help='Show database statistics'
    )
    
    # Output options
    parser.add_argument(
        '-o', '--output',
        default='reports',
        help='Output directory for reports (default: reports)'
    )
    
    # Processing options
    parser.add_argument(
        '--no-cache',
        action='store_true',
        help='Disable caching of enrichment results'
    )
    parser.add_argument(
        '--no-db',
        action='store_true',
        help='Do not save results to database'
    )
    
    # Configuration options
    parser.add_argument(
        '--config',
        help='Path to configuration file (default: config.py)'
    )
    
    # Other options
    parser.add_argument(
        '--cleanup-cache',
        action='store_true',
        help='Clean up expired cache entries'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    # Handle special commands
    if args.create_sample:
        create_sample_data()
        return
    
    # Load configuration
    config_dict = {
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
        'DATABASE_PATH': getattr(config, 'DATABASE_PATH', 'data/cache.db'),
        'CACHE_EXPIRY_HOURS': getattr(config, 'CACHE_EXPIRY_HOURS', 24),
        'LOG_LEVEL': 'DEBUG' if args.verbose else getattr(config, 'LOG_LEVEL', 'INFO'),
        'LOG_FORMAT': getattr(config, 'LOG_FORMAT', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    }
    
    # Initialize PulseLens
    try:
        pulselens = PulseLens(config_dict)
    except Exception as e:
        print(f"Failed to initialize PulseLens: {e}")
        sys.exit(1)
    
    # Handle stats command
    if args.stats:
        stats = pulselens.get_database_stats()
        if stats:
            print("Database Statistics:")
            print(f"  Total IOCs: {stats['total_iocs']}")
            print(f"  IOCs by type: {stats['iocs_by_type']}")
            print(f"  IOCs by severity: {stats['iocs_by_severity']}")
            print(f"  Recent IOCs (24h): {stats['recent_iocs_24h']}")
            print(f"  Cache entries: {stats['cache_entries']}")
            print(f"  Expired cache entries: {stats['expired_cache_entries']}")
        else:
            print("Database not available")
        return
    
    # Handle cache cleanup
    if args.cleanup_cache:
        count = pulselens.cleanup_cache()
        if count is not None:
            print(f"Cleaned up {count} expired cache entries")
        else:
            print("Database not available")
        return
    
    # Determine input source
    input_source = args.file if args.file else args.string
    
    # Run analysis
    print(f"Starting IOC analysis...")
    print(f"Input: {input_source}")
    print(f"Output: {args.output}")
    print("-" * 50)
    
    result = pulselens.analyze_iocs(
        input_source=input_source,
        output_dir=args.output,
        use_cache=not args.no_cache,
        save_to_db=not args.no_db
    )
    
    # Display results
    print("\nAnalysis Results:")
    print(f"Analysis ID: {result['analysis_id']}")
    print(f"Status: {result['status']}")
    
    if result['status'] == 'success':
        print(f"Duration: {result.get('duration_seconds', 0):.2f} seconds")
        print(f"Raw IOCs: {result['raw_ioc_count']}")
        print(f"Valid IOCs: {result['valid_ioc_count']}")
        print(f"Invalid IOCs: {result['invalid_ioc_count']}")
        print(f"Final IOCs: {result['classified_ioc_count']}")
        
        # Show severity summary
        severity_summary = result.get('severity_summary', {})
        severity_dist = severity_summary.get('severity_distribution', {})
        high_risk = severity_summary.get('high_risk_count', 0)
        
        print(f"\nSeverity Distribution:")
        for level, count in severity_dist.items():
            if count > 0:
                print(f"  {level.capitalize()}: {count}")
        
        print(f"\nHigh-Risk Indicators: {high_risk}")
        
        # Show report locations
        reports = result.get('reports', {})
        print(f"\nReports Generated:")
        for report_type, path in reports.items():
            print(f"  {report_type.upper()}: {path}")
        
        # Show invalid IOCs if any
        invalid_iocs = result.get('invalid_iocs', [])
        if invalid_iocs:
            print(f"\nInvalid IOCs ({len(invalid_iocs)}):")
            for ioc in invalid_iocs[:5]:  # Show first 5
                print(f"  - {ioc['original']}: {ioc['reason']}")
            if len(invalid_iocs) > 5:
                print(f"  ... and {len(invalid_iocs) - 5} more")
    
    else:
        print(f"Error: {result.get('error', 'Unknown error')}")
    
    print("-" * 50)
    print("Analysis complete!")


if __name__ == "__main__":
    main()
