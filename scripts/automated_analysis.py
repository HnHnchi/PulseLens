#!/usr/bin/env python3
"""
PulseLens Automated IOC Analysis Script
Runs automated IOC analysis on schedules or demand
"""

import sys
import os
import argparse
from pathlib import Path
from datetime import datetime, timedelta
import json
from typing import List, Dict, Optional

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from pulselens.utils.logger import get_logger, PerformanceLogger, log_errors
from pulselens.main import PulseLens
import config


class AutomatedAnalyzer:
    """Handles automated IOC analysis workflows."""
    
    def __init__(self):
        """Initialize the automated analyzer."""
        self.logger = get_logger()
        self.pulselens = None
        self._initialize_pulselens()
    
    def _initialize_pulselens(self):
        """Initialize PulseLens instance."""
        try:
            config_dict = {
                'DATABASE_PATH': getattr(config, 'DATABASE_PATH', 'data/cache.db'),
                'CACHE_EXPIRY_HOURS': getattr(config, 'CACHE_EXPIRY_HOURS', 24),
                'FLASK_SECRET_KEY': getattr(config, 'FLASK_SECRET_KEY', 'pulselens-secret-key'),
                'OTX_API_KEY': getattr(config, 'OTX_API_KEY', ''),
                'OTX_BASE_URL': getattr(config, 'OTX_BASE_URL', 'https://otx.alienvault.com/api/v1'),
                'OTX_RATE_LIMIT': getattr(config, 'OTX_RATE_LIMIT', 60),
                'SEVERITY_THRESHOLDS': getattr(config, 'SEVERITY_THRESHOLDS', {}),
                'IOC_TYPE_WEIGHTS': getattr(config, 'IOC_TYPE_WEIGHTS', {}),
                'DEFAULT_CONFIDENCE': getattr(config, 'DEFAULT_CONFIDENCE', 'medium'),
                'AUTO_CLEANUP_CACHE': getattr(config, 'AUTO_CLEANUP_CACHE', True)
            }
            
            self.pulselens = PulseLens(config_dict)
            self.logger.info("PulseLens initialized for automated analysis")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize PulseLens: {str(e)}")
            raise
    
    @log_errors()
    def analyze_file(self, file_path: str, output_dir: str = "reports") -> Dict:
        """
        Analyze IOCs from a file.
        
        Args:
            file_path: Path to IOC file
            output_dir: Directory to save reports
            
        Returns:
            Analysis results
        """
        with PerformanceLogger("analyze_file", self.logger):
            self.logger.info(f"Starting automated analysis of file: {file_path}")
            
            # Validate input file
            file_path = Path(file_path)
            if not file_path.exists():
                raise FileNotFoundError(f"Input file not found: {file_path}")
            
            # Run analysis
            result = self.pulselens.analyze_iocs(str(file_path), use_cache=True, save_to_db=True)
            
            # Generate reports
            if result.get('status') == 'success':
                self._generate_reports(result, output_dir)
                self.logger.info(f"Analysis completed: {result['classified_ioc_count']} IOCs processed")
            else:
                self.logger.error(f"Analysis failed: {result.get('error', 'Unknown error')}")
            
            return result
    
    @log_errors()
    def analyze_directory(self, input_dir: str, output_dir: str = "reports", 
                        file_pattern: str = "*.txt") -> List[Dict]:
        """
        Analyze all IOC files in a directory.
        
        Args:
            input_dir: Directory containing IOC files
            output_dir: Directory to save reports
            file_pattern: File pattern to match (e.g., "*.txt", "*.json")
            
        Returns:
            List of analysis results
        """
        with PerformanceLogger("analyze_directory", self.logger):
            self.logger.info(f"Starting batch analysis of directory: {input_dir}")
            
            input_dir = Path(input_dir)
            if not input_dir.exists():
                raise FileNotFoundError(f"Input directory not found: {input_dir}")
            
            # Find matching files
            files = list(input_dir.glob(file_pattern))
            if not files:
                self.logger.warning(f"No files found matching pattern: {file_pattern}")
                return []
            
            self.logger.info(f"Found {len(files)} files to analyze")
            
            results = []
            for file_path in files:
                try:
                    result = self.analyze_file(str(file_path), output_dir)
                    results.append(result)
                except Exception as e:
                    self.logger.error(f"Failed to analyze file {file_path}: {str(e)}")
                    continue
            
            # Generate summary report
            self._generate_batch_summary(results, output_dir)
            
            return results
    
    @log_errors()
    def analyze_recent_feeds(self, hours: int = 24, output_dir: str = "reports") -> Dict:
        """
        Analyze recent threat feeds.
        
        Args:
            hours: Number of hours to look back
            output_dir: Directory to save reports
            
        Returns:
            Analysis results
        """
        with PerformanceLogger("analyze_recent_feeds", self.logger):
            self.logger.info(f"Analyzing recent threat feeds from last {hours} hours")
            
            # This would integrate with threat feed APIs
            # For now, we'll simulate with recent database entries
            try:
                # Get recent IOCs from database
                recent_iocs = self._get_recent_database_iocs(hours)
                
                if not recent_iocs:
                    self.logger.info("No recent IOCs found for analysis")
                    return {'status': 'success', 'message': 'No recent IOCs found'}
                
                # Create temporary file with recent IOCs
                temp_file = self._create_temp_ioc_file(recent_iocs)
                
                try:
                    # Analyze recent IOCs
                    result = self.pulselens.analyze_iocs(temp_file, use_cache=True, save_to_db=True)
                    
                    if result.get('status') == 'success':
                        self._generate_reports(result, output_dir, prefix="recent_feeds")
                        self.logger.info(f"Recent feeds analysis completed: {result['classified_ioc_count']} IOCs")
                    
                    return result
                    
                finally:
                    # Clean up temp file
                    if os.path.exists(temp_file):
                        os.remove(temp_file)
                        
            except Exception as e:
                self.logger.error(f"Error analyzing recent feeds: {str(e)}")
                raise
    
    def _get_recent_database_iocs(self, hours: int) -> List[str]:
        """Get recent IOCs from database."""
        try:
            if not self.pulselens.db:
                return []
            
            # Get recent IOCs from database
            cutoff_time = datetime.now() - timedelta(hours=hours)
            recent_iocs = self.pulselens.db.get_iocs_since(cutoff_time)
            
            return [ioc['ioc_value'] for ioc in recent_iocs]
            
        except Exception as e:
            self.logger.error(f"Error getting recent IOCs from database: {str(e)}")
            return []
    
    def _create_temp_ioc_file(self, iocs: List[str]) -> str:
        """Create temporary file with IOCs."""
        temp_file = f"temp_iocs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        try:
            with open(temp_file, 'w') as f:
                for ioc in iocs:
                    f.write(f"{ioc}\n")
            
            return temp_file
            
        except Exception as e:
            self.logger.error(f"Error creating temp IOC file: {str(e)}")
            raise
    
    def _generate_reports(self, result: Dict, output_dir: str, prefix: str = ""):
        """Generate analysis reports."""
        if result.get('status') != 'success':
            return
        
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Generate JSON report
        if self.pulselens.json_reporter:
            try:
                json_report = self.pulselens.json_reporter.generate_report(result)
                self.logger.info(f"JSON report generated: {json_report}")
            except Exception as e:
                self.logger.error(f"Error generating JSON report: {str(e)}")
        
        # Generate HTML report
        if self.pulselens.html_reporter:
            try:
                html_report = self.pulselens.html_reporter.generate_report(result)
                self.logger.info(f"HTML report generated: {html_report}")
            except Exception as e:
                self.logger.error(f"Error generating HTML report: {str(e)}")
        
        # Generate PDF report if available
        if hasattr(self.pulselens, 'pdf_reporter') and self.pulselens.pdf_reporter:
            try:
                pdf_report = self.pulselens.pdf_reporter.generate_report(result)
                self.logger.info(f"PDF report generated: {pdf_report}")
            except Exception as e:
                self.logger.error(f"Error generating PDF report: {str(e)}")
    
    def _generate_batch_summary(self, results: List[Dict], output_dir: str):
        """Generate batch analysis summary."""
        if not results:
            return
        
        successful_analyses = [r for r in results if r.get('status') == 'success']
        failed_analyses = [r for r in results if r.get('status') != 'success']
        
        summary = {
            'batch_metadata': {
                'timestamp': datetime.now().isoformat(),
                'total_files': len(results),
                'successful_analyses': len(successful_analyses),
                'failed_analyses': len(failed_analyses),
                'total_iocs_processed': sum(r.get('classified_ioc_count', 0) for r in successful_analyses)
            },
            'successful_results': successful_analyses,
            'failed_results': failed_analyses
        }
        
        # Save summary
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        summary_file = output_path / f"batch_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            with open(summary_file, 'w') as f:
                json.dump(summary, f, indent=2, default=str)
            
            self.logger.info(f"Batch summary generated: {summary_file}")
            
        except Exception as e:
            self.logger.error(f"Error generating batch summary: {str(e)}")


def main():
    """Main entry point for automated analysis."""
    parser = argparse.ArgumentParser(description='PulseLens Automated IOC Analysis')
    parser.add_argument('--mode', choices=['file', 'directory', 'recent'], required=True,
                       help='Analysis mode')
    parser.add_argument('--input', required=True,
                       help='Input file or directory path')
    parser.add_argument('--output', default='reports',
                       help='Output directory for reports')
    parser.add_argument('--pattern', default='*.txt',
                       help='File pattern for directory mode')
    parser.add_argument('--hours', type=int, default=24,
                       help='Hours to look back for recent mode')
    
    args = parser.parse_args()
    
    try:
        analyzer = AutomatedAnalyzer()
        
        if args.mode == 'file':
            result = analyzer.analyze_file(args.input, args.output)
            print(f"File analysis completed: {result.get('classified_ioc_count', 0)} IOCs processed")
            
        elif args.mode == 'directory':
            results = analyzer.analyze_directory(args.input, args.output, args.pattern)
            print(f"Directory analysis completed: {len(results)} files processed")
            
        elif args.mode == 'recent':
            result = analyzer.analyze_recent_feeds(args.hours, args.output)
            print(f"Recent feeds analysis completed: {result.get('classified_ioc_count', 0)} IOCs processed")
            
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Analysis failed: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
