import json
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path
import logging

class JSONReporter:
    """Generate JSON reports for IOC analysis results."""
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
    
    def generate_report(self, 
                       classified_iocs: List[Dict], 
                       analysis_id: str,
                       output_path: Optional[str] = None) -> str:
        """
        Generate a comprehensive JSON report.
        
        Args:
            classified_iocs: List of classified IOC dictionaries
            analysis_id: Unique identifier for this analysis
            output_path: Optional file path to save report
            
        Returns:
            JSON report as string
        """
        # Generate report structure
        report = {
            'report_metadata': self._generate_report_metadata(analysis_id),
            'summary': self._generate_summary(classified_iocs),
            'severity_breakdown': self._generate_severity_breakdown(classified_iocs),
            'ioc_type_breakdown': self._generate_type_breakdown(classified_iocs),
            'high_risk_iocs': self._extract_high_risk_iocs(classified_iocs),
            'detailed_iocs': self._generate_detailed_iocs(classified_iocs),
            'recommendations': self._generate_recommendations(classified_iocs),
            'appendix': self._generate_appendix(classified_iocs)
        }
        
        # Convert to JSON string
        json_report = json.dumps(report, indent=2, default=str)
        
        # Save to file if path provided
        if output_path:
            self._save_report(json_report, output_path)
        
        return json_report
    
    def _generate_report_metadata(self, analysis_id: str) -> Dict:
        """Generate report metadata."""
        return {
            'report_id': analysis_id,
            'generated_at': datetime.utcnow().isoformat(),
            'generated_by': 'PulseLens IOC Analysis System',
            'version': '1.0.0',
            'analysis_type': 'threat_intelligence_assessment',
            'data_sources': ['otx', 'internal_analysis'],
            'classification_engine': 'rule_based_v1.0'
        }
    
    def _generate_summary(self, iocs: List[Dict]) -> Dict:
        """Generate executive summary."""
        total_iocs = len(iocs)
        
        # Count severity levels
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for ioc in iocs:
            severity = ioc.get('severity', {})
            level = severity.get('level', 'info')
            severity_counts[level] += 1
        
        # Calculate risk metrics
        high_risk_count = severity_counts['critical'] + severity_counts['high']
        high_risk_percentage = (high_risk_count / total_iocs * 100) if total_iocs > 0 else 0
        
        # Find most common IOC types
        type_counts = {}
        for ioc in iocs:
            ioc_type = ioc.get('ioc_type', 'unknown')
            type_counts[ioc_type] = type_counts.get(ioc_type, 0) + 1
        
        most_common_type = max(type_counts.items(), key=lambda x: x[1])[0] if isinstance(type_counts, dict) and type_counts else 'unknown'
        
        return {
            'total_iocs_analyzed': total_iocs,
            'high_risk_indicators': high_risk_count,
            'high_risk_percentage': round(high_risk_percentage, 2),
            'severity_distribution': severity_counts,
            'most_common_ioc_type': most_common_type,
            'ioc_type_distribution': type_counts,
            'analysis_duration': 'N/A',  # Would be calculated from timestamps
            'data_quality_score': self._calculate_data_quality_score(iocs)
        }
    
    def _generate_severity_breakdown(self, iocs: List[Dict]) -> Dict:
        """Generate detailed severity breakdown."""
        severity_data = {
            'critical': {'count': 0, 'iocs': [], 'common_factors': []},
            'high': {'count': 0, 'iocs': [], 'common_factors': []},
            'medium': {'count': 0, 'iocs': [], 'common_factors': []},
            'low': {'count': 0, 'iocs': [], 'common_factors': []},
            'info': {'count': 0, 'iocs': [], 'common_factors': []}
        }
        
        all_factors = {'critical': [], 'high': [], 'medium': [], 'low': [], 'info': []}
        
        for ioc in iocs:
            severity = ioc.get('severity', {})
            level = severity.get('level', 'info')
            
            severity_data[level]['count'] += 1
            
            # Add IOC summary (not full details to keep report manageable)
            ioc_summary = {
                'ioc_value': ioc.get('ioc_value'),
                'ioc_type': ioc.get('ioc_type'),
                'score': severity.get('score', 0),
                'confidence': severity.get('confidence', 'low'),
                'recommended_actions': severity.get('recommended_actions', [])
            }
            severity_data[level]['iocs'].append(ioc_summary)
            
            # Collect classification factors
            factors = severity.get('classification_factors', {})
            if factors:
                all_factors[level].append(factors)
        
        # Analyze common factors for each severity level
        for level in severity_data:
            if all_factors[level]:
                severity_data[level]['common_factors'] = self._analyze_common_factors(all_factors[level])
        
        return severity_data
    
    def _generate_type_breakdown(self, iocs: List[Dict]) -> Dict:
        """Generate IOC type breakdown."""
        type_data = {}
        
        for ioc in iocs:
            ioc_type = ioc.get('ioc_type', 'unknown')
            
            if ioc_type not in type_data:
                type_data[ioc_type] = {
                    'count': 0,
                    'severity_distribution': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
                    'average_score': 0.0,
                    'sample_iocs': []
                }
            
            type_data[ioc_type]['count'] += 1
            
            # Update severity distribution
            severity = ioc.get('severity', {})
            level = severity.get('level', 'info')
            type_data[ioc_type]['severity_distribution'][level] += 1
            
            # Add to score for averaging
            score = severity.get('score', 0)
            type_data[ioc_type]['average_score'] += score
            
            # Add sample IOC (limit to 5 per type)
            if len(type_data[ioc_type]['sample_iocs']) < 5:
                type_data[ioc_type]['sample_iocs'].append({
                    'ioc_value': ioc.get('ioc_value'),
                    'severity_level': level,
                    'severity_score': score
                })
        
        # Calculate average scores
        for ioc_type in type_data:
            count = type_data[ioc_type]['count']
            if count > 0:
                type_data[ioc_type]['average_score'] = round(
                    type_data[ioc_type]['average_score'] / count, 2
                )
        
        return type_data
    
    def _extract_high_risk_iocs(self, iocs: List[Dict]) -> List[Dict]:
        """Extract high-risk IOCs for focused attention."""
        high_risk = []
        
        for ioc in iocs:
            severity = ioc.get('severity', {})
            level = severity.get('level', 'info')
            
            if level in ['critical', 'high']:
                # Create detailed high-risk IOC entry
                high_risk_ioc = {
                    'ioc_value': ioc.get('ioc_value'),
                    'ioc_type': ioc.get('ioc_type'),
                    'original_value': ioc.get('original_value'),
                    'severity': severity,
                    'enrichment': ioc.get('enrichment', {}),
                    'tags': ioc.get('tags', []),
                    'threat_intelligence': self._extract_threat_intel(ioc),
                    'immediate_actions': severity.get('recommended_actions', [])
                }
                high_risk.append(high_risk_ioc)
        
        # Sort by severity score (highest first)
        high_risk.sort(key=lambda x: x['severity'].get('score', 0), reverse=True)
        
        return high_risk
    
    def _generate_detailed_iocs(self, iocs: List[Dict]) -> List[Dict]:
        """Generate detailed IOC information."""
        detailed_iocs = []
        
        for ioc in iocs:
            detailed_ioc = {
                'ioc_value': ioc.get('ioc_value'),
                'ioc_type': ioc.get('ioc_type'),
                'original_value': ioc.get('original_value'),
                'feed_source': ioc.get('feed_source'),
                'first_seen': ioc.get('first_seen'),
                'last_seen': ioc.get('last_seen'),
                'confidence': ioc.get('confidence'),
                'tags': ioc.get('tags', []),
                'metadata': ioc.get('metadata', {}),
                'severity': ioc.get('severity', {}),
                'enrichment_summary': self._create_enrichment_summary(ioc.get('enrichment', {})),
                'classification_factors': ioc.get('severity', {}).get('classification_factors', {}),
                'recommended_actions': ioc.get('severity', {}).get('recommended_actions', [])
            }
            detailed_iocs.append(detailed_ioc)
        
        return detailed_iocs
    
    def _generate_recommendations(self, iocs: List[Dict]) -> Dict:
        """Generate actionable recommendations."""
        recommendations = {
            'immediate_actions': [],
            'short_term_actions': [],
            'long_term_actions': [],
            'monitoring_recommendations': [],
            'prevention_measures': []
        }
        
        # Analyze all IOCs for common patterns
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        type_counts = {}
        common_actions = {}
        
        for ioc in iocs:
            # Count severities
            severity = ioc.get('severity', {})
            level = severity.get('level', 'info')
            severity_counts[level] += 1
            
            # Count types
            ioc_type = ioc.get('ioc_type', 'unknown')
            type_counts[ioc_type] = type_counts.get(ioc_type, 0) + 1
            
            # Collect recommended actions
            actions = severity.get('recommended_actions', [])
            for action in actions:
                common_actions[action] = common_actions.get(action, 0) + 1
        
        # Generate immediate actions based on critical/high risk IOCs
        if severity_counts['critical'] > 0:
            recommendations['immediate_actions'].append(
                f"Immediately block and investigate {severity_counts['critical']} critical indicators"
            )
        
        if severity_counts['high'] > 0:
            recommendations['immediate_actions'].append(
                f"Prioritize investigation of {severity_counts['high']} high-risk indicators"
            )
        
        # Generate short-term actions
        if severity_counts['critical'] + severity_counts['high'] > 5:
            recommendations['short_term_actions'].append(
                "Conduct comprehensive threat hunting for related indicators"
            )
        
        # Generate prevention measures based on IOC types
        if type_counts.get('ip', 0) > 0:
            recommendations['prevention_measures'].append(
                "Update firewall rules to block malicious IP addresses"
            )
        
        if type_counts.get('domain', 0) > 0:
            recommendations['prevention_measures'].append(
                "Update DNS sinkhole/blocklist configurations"
            )
        
        if type_counts.get('hash', 0) > 0:
            recommendations['prevention_measures'].append(
                "Update antivirus/EDR signatures with malicious file hashes"
            )
        
        # Add most common recommended actions
        if isinstance(common_actions, dict):
            sorted_actions = sorted(common_actions.items(), key=lambda x: x[1], reverse=True)
            for action, count in sorted_actions[:5]:
                if count > 1:
                    recommendations['monitoring_recommendations'].append(
                        f"{action} (applies to {count} indicators)"
                )
        
        return recommendations
    
    def _generate_appendix(self, iocs: List[Dict]) -> Dict:
        """Generate appendix with additional information."""
        return {
            'data_sources_used': {
                'otx': {
                    'description': 'AlienVault Open Threat Exchange',
                    'data_points': len([ioc for ioc in iocs if 'otx' in ioc.get('enrichment', {}).get('sources', [])]),
                    'last_updated': datetime.utcnow().isoformat()
                },
                'internal_analysis': {
                    'description': 'Internal rule-based analysis',
                    'data_points': len(iocs),
                    'last_updated': datetime.utcnow().isoformat()
                }
            },
            'classification_rules': {
                'severity_scoring': 'Based on reputation, threat intelligence, IOC type, risk factors, and temporal analysis',
                'confidence_levels': 'Determined by data source reliability and corroboration',
                'recommendation_engine': 'Rule-based actions mapped to severity levels and IOC types'
            },
            'technical_notes': {
                'ioc_normalization': 'All IOCs normalized to standard formats before analysis',
                'deduplication': 'Duplicate IOCs removed based on type and value',
                'cache_utilization': 'External API responses cached for 24 hours to optimize performance',
                'rate_limiting': 'OTX API requests limited to 60 per minute'
            },
            'glossary': {
                'IOC': 'Indicator of Compromise - artifacts observed on a network or in an operating system that indicate potential intrusion',
                'OTX': 'Open Threat Exchange - a crowdsourced threat intelligence platform',
                'Pulse': 'A collection of related indicators and associated metadata in OTX',
                'Threat Score': 'Numerical representation of threat level (0-10 scale)',
                'Confidence': 'Reliability assessment of the classification (high/medium/low)'
            }
        }
    
    def _calculate_data_quality_score(self, iocs: List[Dict]) -> float:
        """Calculate overall data quality score."""
        if not iocs:
            return 0.0
        
        total_score = 0.0
        
        for ioc in iocs:
            ioc_score = 0.0
            
            # Check for enrichment data
            enrichment = ioc.get('enrichment', {})
            if enrichment.get('sources'):
                ioc_score += 25
            
            # Check for severity classification
            if ioc.get('severity'):
                ioc_score += 25
            
            # Check for metadata
            if ioc.get('metadata'):
                ioc_score += 25
            
            # Check for tags
            if ioc.get('tags'):
                ioc_score += 25
            
            total_score += ioc_score
        
        return round(total_score / len(iocs), 2)
    
    def _analyze_common_factors(self, factors_list: List[Dict]) -> List[str]:
        """Analyze common factors across IOCs."""
        factor_counts = {}
        factor_key = None  # Initialize to prevent unbound variable error
        
        for factors in factors_list:
            if isinstance(factors, dict):
                for category, category_factors in factors.items():
                    if isinstance(category_factors, list):
                        for factor in category_factors:
                            key = f"{category}:{factor}"
                            factor_counts[key] = factor_counts.get(key, 0) + 1
                    elif isinstance(category_factors, dict):
                        for key, value in category_factors.items():
                            factor_key = f"{category}:{key}"
                            factor_counts[factor_key] = factor_counts.get(factor_key, 0) + 1
                    # Handle other data types to prevent factor_key error
                    else:
                        # Skip or log unexpected data types
                        pass
        
        # Return most common factors
        sorted_factors = sorted(factor_counts.items(), key=lambda x: x[1], reverse=True)
        return [factor for factor, count in sorted_factors[:5]]
    def _extract_threat_intel(self, ioc: Dict) -> Dict:
        """Extract relevant threat intelligence for high-risk IOCs."""
        enrichment = ioc.get('enrichment', {})
        threat_intel = enrichment.get('threat_intel', {})
        
        extracted = {}
        
        # OTX data
        otx_data = threat_intel.get('otx', {})
        if otx_data:
            extracted['otx'] = {
                'pulse_count': otx_data.get('pulse_count', 0),
                'threat_score': otx_data.get('threat_score', 0),
                'reputation': otx_data.get('reputation', {}).get('reputation', 'unknown'),
                'malicious_samples': otx_data.get('malicious_samples', 0),
                'references': otx_data.get('references', [])[:5]  # Limit references
            }
        
        # Other threat intel sources
        if isinstance(threat_intel, dict):
            for source, data in threat_intel.items():
                if source != 'otx' and isinstance(data, dict):
                    extracted[source] = {
                        'is_malicious': data.get('is_malicious', False),
                        'is_suspicious': data.get('is_suspicious', False),
                        'confidence': data.get('confidence', 'low')
                    }
        
        return extracted
    
    def _create_enrichment_summary(self, enrichment: Dict) -> Dict:
        """Create a summary of enrichment data."""
        summary = {
            'sources': enrichment.get('sources', []),
            'reputation': enrichment.get('reputation', {}),
            'risk_assessment': enrichment.get('risk_assessment', {}),
            'data_sources_count': len(enrichment.get('sources', []))
        }
        
        return summary
    
    def _save_report(self, json_report: str, output_path: str) -> None:
        """Save JSON report to file."""
        try:
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(json_report)
            
            self.logger.info(f"JSON report saved to {output_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to save JSON report: {e}")
            raise
    
    def generate_summary_report(self, classified_iocs: List[Dict]) -> str:
        """Generate a concise summary JSON report."""
        summary = {
            'summary': self._generate_summary(classified_iocs),
            'high_risk_count': len([ioc for ioc in classified_iocs 
                                 if ioc.get('severity', {}).get('level') in ['critical', 'high']]),
            'generated_at': datetime.utcnow().isoformat()
        }
        
        return json.dumps(summary, indent=2, default=str)
