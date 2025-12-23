from typing import Dict, List, Optional
from datetime import datetime
from pathlib import Path
import logging

class HTMLReporter:
    """Generate HTML reports for IOC analysis results."""
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
    
    def generate_report(self, 
                       classified_iocs: List[Dict], 
                       analysis_id: str,
                       output_path: Optional[str] = None) -> str:
        """
        Generate a comprehensive HTML report.
        
        Args:
            classified_iocs: List of classified IOC dictionaries
            analysis_id: Unique identifier for this analysis
            output_path: Optional file path to save report
            
        Returns:
            HTML report as string
        """
        # Generate report sections
        html_content = self._generate_html_template(
            analysis_id,
            classified_iocs
        )
        
        # Save to file if path provided
        if output_path:
            self._save_report(html_content, output_path)
        
        return html_content
    
    def _generate_html_template(self, analysis_id: str, iocs: List[Dict]) -> str:
        """Generate the complete HTML template."""
        
        # Generate summary statistics
        summary = self._calculate_summary(iocs)
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PulseLens IOC Analysis Report - {analysis_id}</title>
    <style>
        {self._get_css_styles()}
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <h1>PulseLens IOC Analysis Report</h1>
            <div class="report-info">
                <span class="report-id">Analysis ID: {analysis_id}</span>
                <span class="generated-time">Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</span>
            </div>
        </header>

        <section class="summary">
            <h2>Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-card">
                    <h3>Total IOCs</h3>
                    <div class="stat-number">{summary['total_iocs']}</div>
                </div>
                <div class="summary-card critical">
                    <h3>Critical</h3>
                    <div class="stat-number">{summary['severity_counts']['critical']}</div>
                </div>
                <div class="summary-card high">
                    <h3>High</h3>
                    <div class="stat-number">{summary['severity_counts']['high']}</div>
                </div>
                <div class="summary-card medium">
                    <h3>Medium</h3>
                    <div class="stat-number">{summary['severity_counts']['medium']}</div>
                </div>
                <div class="summary-card low">
                    <h3>Low</h3>
                    <div class="stat-number">{summary['severity_counts']['low']}</div>
                </div>
                <div class="summary-card info">
                    <h3>Info</h3>
                    <div class="stat-number">{summary['severity_counts']['info']}</div>
                </div>
            </div>
            <div class="risk-indicator">
                <h3>Risk Assessment</h3>
                <div class="risk-bar">
                    <div class="risk-segment critical" style="width: {summary['risk_percentages']['critical']}%"></div>
                    <div class="risk-segment high" style="width: {summary['risk_percentages']['high']}%"></div>
                    <div class="risk-segment medium" style="width: {summary['risk_percentages']['medium']}%"></div>
                    <div class="risk-segment low" style="width: {summary['risk_percentages']['low']}%"></div>
                    <div class="risk-segment info" style="width: {summary['risk_percentages']['info']}%"></div>
                </div>
                <p>High-Risk Indicators: {summary['high_risk_count']} ({summary['high_risk_percentage']}%)</p>
            </div>
        </section>

        <section class="ioc-types">
            <h2>IOC Type Distribution</h2>
            <div class="type-grid">
                {self._generate_type_cards(summary['type_counts'])}
            </div>
        </section>

        <section class="high-risk">
            <h2>High-Risk Indicators</h2>
            <div class="table-container">
                <table class="ioc-table">
                    <thead>
                        <tr>
                            <th>IOC Value</th>
                            <th>Type</th>
                            <th>Severity</th>
                            <th>Score</th>
                            <th>Confidence</th>
                            <th>Recommended Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {self._generate_high_risk_rows(iocs)}
                    </tbody>
                </table>
            </div>
        </section>

        <section class="detailed-iocs">
            <h2>Detailed IOC Analysis</h2>
            <div class="table-container">
                <table class="ioc-table">
                    <thead>
                        <tr>
                            <th>IOC Value</th>
                            <th>Type</th>
                            <th>Severity</th>
                            <th>Score</th>
                            <th>Tags</th>
                            <th>Threat Intel</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {self._generate_detailed_rows(iocs)}
                    </tbody>
                </table>
            </div>
        </section>

        <section class="recommendations">
            <h2>Recommendations</h2>
            <div class="recommendation-grid">
                {self._generate_recommendations(iocs)}
            </div>
        </section>

        <footer class="footer">
            <p>Generated by PulseLens IOC Analysis System v1.0.0</p>
            <p>Report created on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        </footer>
    </div>

    <script>
        {self._get_javascript()}
    </script>
</body>
</html>"""
        
        return html
    
    def _get_css_styles(self) -> str:
        """Return CSS styles for the HTML report."""
        return """
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: white;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }

        .header {
            text-align: center;
            margin-bottom: 30px;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 8px;
        }

        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }

        .report-info {
            display: flex;
            justify-content: space-between;
            font-size: 0.9em;
            opacity: 0.9;
        }

        .summary {
            margin-bottom: 40px;
        }

        .summary h2 {
            color: #333;
            margin-bottom: 20px;
            font-size: 1.8em;
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-left: 4px solid #ddd;
        }

        .summary-card.critical {
            border-left-color: #dc3545;
        }

        .summary-card.high {
            border-left-color: #fd7e14;
        }

        .summary-card.medium {
            border-left-color: #ffc107;
        }

        .summary-card.low {
            border-left-color: #28a745;
        }

        .summary-card.info {
            border-left-color: #17a2b8;
        }

        .stat-number {
            font-size: 2.5em;
            font-weight: bold;
            color: #333;
        }

        .risk-indicator {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-top: 20px;
        }

        .risk-bar {
            height: 30px;
            background: #e9ecef;
            border-radius: 15px;
            overflow: hidden;
            margin: 15px 0;
            display: flex;
        }

        .risk-segment {
            height: 100%;
            transition: width 0.3s ease;
        }

        .risk-segment.critical {
            background: #dc3545;
        }

        .risk-segment.high {
            background: #fd7e14;
        }

        .risk-segment.medium {
            background: #ffc107;
        }

        .risk-segment.low {
            background: #28a745;
        }

        .risk-segment.info {
            background: #17a2b8;
        }

        .ioc-types {
            margin-bottom: 40px;
        }

        .ioc-types h2 {
            color: #333;
            margin-bottom: 20px;
            font-size: 1.8em;
        }

        .type-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
        }

        .type-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-left: 4px solid #007bff;
        }

        .type-card h3 {
            color: #007bff;
            margin-bottom: 10px;
        }

        .type-count {
            font-size: 2em;
            font-weight: bold;
            color: #333;
        }

        .high-risk, .detailed-iocs {
            margin-bottom: 40px;
        }

        .high-risk h2, .detailed-iocs h2 {
            color: #333;
            margin-bottom: 20px;
            font-size: 1.8em;
        }

        .table-container {
            overflow-x: auto;
        }

        .ioc-table {
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }

        .ioc-table th {
            background: #f8f9fa;
            padding: 15px;
            text-align: left;
            font-weight: 600;
            color: #333;
            border-bottom: 2px solid #dee2e6;
        }

        .ioc-table td {
            padding: 15px;
            border-bottom: 1px solid #dee2e6;
        }

        .ioc-table tr:hover {
            background: #f8f9fa;
        }

        .severity-badge {
            padding: 4px 8px;
            border-radius: 4px;
            color: white;
            font-size: 0.8em;
            font-weight: bold;
        }

        .severity-badge.critical {
            background: #dc3545;
        }

        .severity-badge.high {
            background: #fd7e14;
        }

        .severity-badge.medium {
            background: #ffc107;
            color: #333;
        }

        .severity-badge.low {
            background: #28a745;
        }

        .severity-badge.info {
            background: #17a2b8;
        }

        .tags {
            display: flex;
            flex-wrap: wrap;
            gap: 4px;
        }

        .tag {
            background: #e9ecef;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.8em;
            color: #495057;
        }

        .actions {
            display: flex;
            flex-wrap: wrap;
            gap: 4px;
        }

        .action {
            background: #007bff;
            color: white;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.8em;
        }

        .recommendations {
            margin-bottom: 40px;
        }

        .recommendations h2 {
            color: #333;
            margin-bottom: 20px;
            font-size: 1.8em;
        }

        .recommendation-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
        }

        .recommendation-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-left: 4px solid #28a745;
        }

        .recommendation-card h3 {
            color: #28a745;
            margin-bottom: 10px;
        }

        .recommendation-card ul {
            list-style: none;
            padding-left: 0;
        }

        .recommendation-card li {
            padding: 5px 0;
            border-bottom: 1px solid #f8f9fa;
        }

        .recommendation-card li:last-child {
            border-bottom: none;
        }

        .footer {
            text-align: center;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 8px;
            color: #6c757d;
            margin-top: 40px;
        }

        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }

            .summary-grid {
                grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
                gap: 10px;
            }

            .stat-number {
                font-size: 2em;
            }

            .table-container {
                font-size: 0.9em;
            }

            .ioc-table th, .ioc-table td {
                padding: 10px;
            }
        }
        """
    
    def _get_javascript(self) -> str:
        """Return JavaScript for interactive features."""
        return """
        // Add interactive features
        document.addEventListener('DOMContentLoaded', function() {
            // Add click handlers for IOC rows
            const rows = document.querySelectorAll('.ioc-table tbody tr');
            rows.forEach(row => {
                row.addEventListener('click', function() {
                    // Toggle detailed view
                    const details = this.querySelector('.ioc-details');
                    if (details) {
                        details.style.display = details.style.display === 'none' ? 'block' : 'none';
                    }
                });
            });

            // Add filtering functionality
            const filterButtons = document.querySelectorAll('.filter-btn');
            filterButtons.forEach(button => {
                button.addEventListener('click', function() {
                    const filter = this.dataset.filter;
                    filterTable(filter);
                });
            });
        });

        function filterTable(filter) {
            const rows = document.querySelectorAll('.ioc-table tbody tr');
            rows.forEach(row => {
                if (filter === 'all' || row.classList.contains(filter)) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        }

        function exportToCSV() {
            const table = document.querySelector('.ioc-table');
            const rows = table.querySelectorAll('tr');
            let csv = [];

            rows.forEach(row => {
                const cols = row.querySelectorAll('th, td');
                const rowData = Array.from(cols).map(col => col.textContent);
                csv.push(rowData.join(','));
            });

            const csvContent = csv.join('\\n');
            const blob = new Blob([csvContent], { type: 'text/csv' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'ioc_analysis.csv';
            a.click();
        }
        """
    
    def _calculate_summary(self, iocs: List[Dict]) -> Dict:
        """Calculate summary statistics."""
        total_iocs = len(iocs)
        
        # Count severity levels
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for ioc in iocs:
            severity = ioc.get('severity', {})
            level = severity.get('level', 'info')
            severity_counts[level] += 1
        
        # Calculate percentages
        risk_percentages = {}
        for level in severity_counts:
            risk_percentages[level] = round((severity_counts[level] / total_iocs * 100), 1) if total_iocs > 0 else 0
        
        # Count IOC types
        type_counts = {}
        for ioc in iocs:
            ioc_type = ioc.get('ioc_type', 'unknown')
            type_counts[ioc_type] = type_counts.get(ioc_type, 0) + 1
        
        high_risk_count = severity_counts['critical'] + severity_counts['high']
        high_risk_percentage = round((high_risk_count / total_iocs * 100), 1) if total_iocs > 0 else 0
        
        return {
            'total_iocs': total_iocs,
            'severity_counts': severity_counts,
            'risk_percentages': risk_percentages,
            'type_counts': type_counts,
            'high_risk_count': high_risk_count,
            'high_risk_percentage': high_risk_percentage
        }
    
    def _generate_type_cards(self, type_counts: Dict[str, int]) -> str:
        """Generate HTML for IOC type cards."""
        cards = []
        if isinstance(type_counts, dict):
            for ioc_type, count in type_counts.items():
                cards.append(f"""
            <div class="type-card">
                <h3>{ioc_type.upper()}</h3>
                <div class="type-count">{count}</div>
            </div>
            """)
        return ''.join(cards)
    
    def _generate_high_risk_rows(self, iocs: List[Dict]) -> str:
        """Generate HTML rows for high-risk IOCs."""
        rows = []
        
        # Filter high-risk IOCs and sort by severity score
        high_risk_iocs = [ioc for ioc in iocs 
                         if ioc.get('severity', {}).get('level') in ['critical', 'high']]
        high_risk_iocs.sort(key=lambda x: x.get('severity', {}).get('score', 0), reverse=True)
        
        for ioc in high_risk_iocs:
            severity = ioc.get('severity', {})
            level = severity.get('level', 'info')
            score = severity.get('score', 0)
            confidence = severity.get('confidence', 'low')
            actions = severity.get('recommended_actions', [])
            
            actions_html = ' '.join([f'<span class="action">{action}</span>' for action in actions[:3]])
            
            rows.append(f"""
            <tr class="high-risk-row">
                <td><code>{ioc.get('ioc_value', '')}</code></td>
                <td>{ioc.get('ioc_type', '')}</td>
                <td><span class="severity-badge {level}">{level.upper()}</span></td>
                <td>{score}</td>
                <td>{confidence}</td>
                <td class="actions">{actions_html}</td>
            </tr>
            """)
        
        return ''.join(rows)
    
    def _generate_detailed_rows(self, iocs: List[Dict]) -> str:
        """Generate HTML rows for all IOCs."""
        rows = []
        
        for ioc in iocs:
            severity = ioc.get('severity', {})
            level = severity.get('level', 'info')
            score = severity.get('score', 0)
            tags = ioc.get('tags', [])
            actions = severity.get('recommended_actions', [])
            
            # Generate tags HTML
            tags_html = ' '.join([f'<span class="tag">{tag}</span>' for tag in tags[:5]])
            
            # Generate threat intel summary
            enrichment = ioc.get('enrichment', {})
            threat_intel = enrichment.get('threat_intel', {})
            otx_data = threat_intel.get('otx', {})
            
            intel_summary = f"Pulses: {otx_data.get('pulse_count', 0)}"
            if otx_data.get('reputation', {}).get('reputation'):
                intel_summary += f" | Rep: {otx_data['reputation']['reputation']}"
            
            # Generate actions HTML
            actions_html = ' '.join([f'<span class="action">{action}</span>' for action in actions[:2]])
            
            rows.append(f"""
            <tr class="{level}-row">
                <td><code>{ioc.get('ioc_value', '')}</code></td>
                <td>{ioc.get('ioc_type', '')}</td>
                <td><span class="severity-badge {level}">{level.upper()}</span></td>
                <td>{score}</td>
                <td class="tags">{tags_html}</td>
                <td>{intel_summary}</td>
                <td class="actions">{actions_html}</td>
            </tr>
            """)
        
        return ''.join(rows)
    
    def _generate_recommendations(self, iocs: List[Dict]) -> str:
        """Generate HTML recommendations."""
        # Analyze IOCs for recommendations
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        type_counts = {}
        
        for ioc in iocs:
            # Count severities
            severity = ioc.get('severity', {})
            level = severity.get('level', 'info')
            severity_counts[level] += 1
            
            # Count types
            ioc_type = ioc.get('ioc_type', 'unknown')
            type_counts[ioc_type] = type_counts.get(ioc_type, 0) + 1
        
        recommendations = []
        
        # Immediate actions
        immediate_actions = []
        if severity_counts['critical'] > 0:
            immediate_actions.append(f"Block and investigate {severity_counts['critical']} critical indicators")
        if severity_counts['high'] > 0:
            immediate_actions.append(f"Prioritize investigation of {severity_counts['high']} high-risk indicators")
        
        if immediate_actions:
            recommendations.append(f"""
            <div class="recommendation-card">
                <h3>Immediate Actions</h3>
                <ul>
                    {''.join([f'<li>{action}</li>' for action in immediate_actions])}
                </ul>
            </div>
            """)
        
        # Type-specific recommendations
        type_recommendations = []
        if type_counts.get('ip', 0) > 0:
            type_recommendations.append(f"Update firewall rules for {type_counts['ip']} IP addresses")
        if type_counts.get('domain', 0) > 0:
            type_recommendations.append(f"Update DNS blocklists for {type_counts['domain']} domains")
        if type_counts.get('hash', 0) > 0:
            type_recommendations.append(f"Update AV signatures for {type_counts['hash']} file hashes")
        
        if type_recommendations:
            recommendations.append(f"""
            <div class="recommendation-card">
                <h3>Prevention Measures</h3>
                <ul>
                    {''.join([f'<li>{action}</li>' for action in type_recommendations])}
                </ul>
            </div>
            """)
        
        # Monitoring recommendations
        monitoring_actions = [
            "Implement continuous monitoring of detected indicators",
            "Set up alerts for future detections of these IOCs",
            "Review security logs for related activity"
        ]
        
        recommendations.append(f"""
        <div class="recommendation-card">
            <h3>Monitoring & Detection</h3>
            <ul>
                {''.join([f'<li>{action}</li>' for action in monitoring_actions])}
            </ul>
        </div>
        """)
        
        return ''.join(recommendations)
    
    def _save_report(self, html_content: str, output_path: str) -> None:
        """Save HTML report to file."""
        try:
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.logger.info(f"HTML report saved to {output_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to save HTML report: {e}")
            raise
