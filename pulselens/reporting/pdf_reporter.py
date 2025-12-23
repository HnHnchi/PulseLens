#!/usr/bin/env python3
"""
PulseLens PDF Reporter
Generates PDF reports for IOC analysis results
"""

import os
import sys
from typing import Dict, List, Optional
from pathlib import Path
from datetime import datetime
import json

from ..utils.logger import get_logger, log_errors, PerformanceLogger


class PDFReporter:
    """Generates PDF reports for IOC analysis results."""
    
    def __init__(self, config: Dict):
        """
        Initialize PDF reporter.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.logger = get_logger()
        self.pdfkit_available = self._check_pdfkit_availability()
        
        if not self.pdfkit_available:
            self.logger.warning("pdfkit not available - PDF reporting will be disabled")
    
    def _check_pdfkit_availability(self) -> bool:
        """Check if pdfkit is available."""
        try:
            import pdfkit
            return True
        except ImportError:
            return False
    
    @log_errors()
    def generate_report(self, analysis_data: Dict, output_path: Optional[str] = None) -> str:
        """
        Generate PDF report from analysis data.
        
        Args:
            analysis_data: Analysis results data
            output_path: Optional output file path
            
        Returns:
            Path to generated PDF file
            
        Raises:
            RuntimeError: If pdfkit is not available
            ValueError: If analysis data is invalid
        """
        if not self.pdfkit_available:
            raise RuntimeError("PDF reporting requires pdfkit. Install with: pip install pdfkit")
        
        with PerformanceLogger("generate_pdf_report", self.logger):
            if not analysis_data or not isinstance(analysis_data, dict):
                raise ValueError("Invalid analysis data provided")
            
            # Generate output path if not provided
            if not output_path:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                analysis_id = analysis_data.get('analysis_id', 'unknown')
                output_path = f"reports/pulselens_report_{analysis_id}_{timestamp}.pdf"
            
            # Ensure reports directory exists
            reports_dir = Path(output_path).parent
            reports_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate HTML content
            html_content = self._generate_html_report(analysis_data)
            
            # Convert HTML to PDF
            return self._html_to_pdf(html_content, output_path)
    
    def _generate_html_report(self, analysis_data: Dict) -> str:
        """Generate HTML content for PDF report."""
        html_template = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>PulseLens IOC Analysis Report</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            margin: 40px; 
            line-height: 1.6;
            color: #333;
        }
        .header { 
            text-align: center; 
            border-bottom: 3px solid #6f42c1; 
            padding-bottom: 20px; 
            margin-bottom: 30px;
        }
        .header h1 { 
            color: #6f42c1; 
            margin: 0;
        }
        .header .subtitle { 
            color: #666; 
            margin-top: 5px;
        }
        .summary { 
            background: #f8f9fa; 
            padding: 20px; 
            border-radius: 5px; 
            margin-bottom: 30px;
        }
        .summary h2 { 
            color: #6f42c1; 
            margin-top: 0;
        }
        .stats-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 15px; 
            margin: 20px 0;
        }
        .stat-card { 
            background: white; 
            padding: 15px; 
            border-left: 4px solid #6f42c1; 
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .stat-number { 
            font-size: 24px; 
            font-weight: bold; 
            color: #6f42c1;
        }
        .stat-label { 
            color: #666; 
            font-size: 14px;
        }
        .ioc-table { 
            width: 100%; 
            border-collapse: collapse; 
            margin: 20px 0;
        }
        .ioc-table th, .ioc-table td { 
            border: 1px solid #ddd; 
            padding: 8px; 
            text-align: left;
        }
        .ioc-table th { 
            background: #6f42c1; 
            color: white;
        }
        .severity-critical { color: #dc3545; font-weight: bold; }
        .severity-high { color: #fd7e14; font-weight: bold; }
        .severity-medium { color: #ffc107; font-weight: bold; }
        .severity-low { color: #28a745; font-weight: bold; }
        .severity-info { color: #17a2b8; font-weight: bold; }
        .recommendations { 
            background: #e7f3ff; 
            padding: 20px; 
            border-radius: 5px; 
            margin: 20px 0;
        }
        .recommendations h3 { 
            color: #0066cc; 
            margin-top: 0;
        }
        .footer { 
            margin-top: 50px; 
            padding-top: 20px; 
            border-top: 1px solid #ddd; 
            text-align: center; 
            color: #666; 
            font-size: 12px;
        }
        .page-break { page-break-before: always; }
    </style>
</head>
<body>
    <div class="header">
        <h1>PulseLens IOC Analysis Report</h1>
        <div class="subtitle">Threat Intelligence Analysis Results</div>
        <div class="subtitle">Generated: {generated_at}</div>
    </div>

    <div class="summary">
        <h2>Executive Summary</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">{total_iocs}</div>
                <div class="stat-label">Total IOCs Analyzed</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{high_risk_count}</div>
                <div class="stat-label">High Risk Indicators</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{duration_seconds}s</div>
                <div class="stat-label">Analysis Duration</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{analysis_id}</div>
                <div class="stat-label">Analysis ID</div>
            </div>
        </div>
    </div>

    <h2>IOC Analysis Results</h2>
    <table class="ioc-table">
        <thead>
            <tr>
                <th>IOC Value</th>
                <th>Type</th>
                <th>Severity</th>
                <th>Score</th>
                <th>Confidence</th>
            </tr>
        </thead>
        <tbody>
            {ioc_rows}
        </tbody>
    </table>

    <div class="recommendations">
        <h3>Security Recommendations</h3>
        <ul>
            {recommendation_items}
        </ul>
    </div>

    <div class="footer">
        <p>Generated by PulseLens IOC Analysis System</p>
        <p>Report generated on {generated_at}</p>
    </div>
</body>
</html>
        """
        
        # Extract data
        iocs = analysis_data.get('iocs', [])
        total_iocs = len(iocs)
        high_risk_count = len([ioc for ioc in iocs 
                              if ioc.get('severity', {}).get('level') in ['critical', 'high']])
        duration_seconds = analysis_data.get('duration_seconds', 0)
        analysis_id = analysis_data.get('analysis_id', 'unknown')
        generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Generate IOC table rows
        ioc_rows = ""
        for ioc in iocs[:50]:  # Limit to 50 IOCs for PDF
            ioc_value = ioc.get('ioc_value', '')
            ioc_type = ioc.get('ioc_type', '')
            severity = ioc.get('severity', {})
            severity_level = severity.get('level', 'info')
            severity_score = severity.get('score', 0)
            confidence = ioc.get('confidence', 'medium')
            
            ioc_rows += f"""
            <tr>
                <td><code>{ioc_value}</code></td>
                <td>{ioc_type.upper()}</td>
                <td><span class="severity-{severity_level}">{severity_level.upper()}</span></td>
                <td>{severity_score}</td>
                <td>{confidence}</td>
            </tr>
            """
        
        # Generate recommendations
        recommendations = analysis_data.get('recommendations', [])
        recommendation_items = ""
        for rec in recommendations[:10]:  # Limit to 10 recommendations
            recommendation_items += f"<li>{rec}</li>"
        
        if not recommendation_items:
            recommendation_items = "<li>Monitor all identified IOCs for suspicious activity</li>"
        
        # Fill template
        return html_template.format(
            generated_at=generated_at,
            total_iocs=total_iocs,
            high_risk_count=high_risk_count,
            duration_seconds=duration_seconds,
            analysis_id=analysis_id,
            ioc_rows=ioc_rows,
            recommendation_items=recommendation_items
        )
    
    def _html_to_pdf(self, html_content: str, output_path: str) -> str:
        """Convert HTML content to PDF."""
        try:
            import pdfkit
            
            # PDF options
            options = {
                'page-size': 'A4',
                'margin-top': '0.75in',
                'margin-right': '0.75in',
                'margin-bottom': '0.75in',
                'margin-left': '0.75in',
                'encoding': "UTF-8",
                'no-outline': None,
                'enable-local-file-access': None
            }
            
            # Generate PDF
            pdfkit.from_string(html_content, output_path, options=options)
            
            self.logger.info(f"PDF report generated: {output_path}")
            return output_path
            
        except Exception as e:
            self.logger.error(f"Error generating PDF: {str(e)}")
            raise RuntimeError(f"PDF generation failed: {str(e)}")
    
    def is_available(self) -> bool:
        """Check if PDF reporting is available."""
        return self.pdfkit_available
    
    def get_requirements(self) -> List[str]:
        """Get requirements for PDF reporting."""
        return [
            "pdfkit: Install with 'pip install pdfkit'",
            "wkhtmltopdf: Install system package (wkhtmltopdf on Ubuntu/Debian, wkhtmltopdf on macOS/Windows)"
        ]


def setup_pdf_reporting(config: Dict) -> Optional[PDFReporter]:
    """
    Setup PDF reporting with fallback.
    
    Args:
        config: Configuration dictionary
        
    Returns:
        PDFReporter instance or None if not available
    """
    try:
        reporter = PDFReporter(config)
        if reporter.is_available():
            return reporter
        else:
            logger = get_logger()
            logger.warning("PDF reporting not available - missing dependencies")
            return None
    except Exception as e:
        logger = get_logger()
        logger.error(f"Failed to setup PDF reporting: {str(e)}")
        return None
