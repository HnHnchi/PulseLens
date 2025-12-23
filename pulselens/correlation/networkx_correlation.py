#!/usr/bin/env python3
"""
PulseLens NetworkX Correlation Engine
Provides IOC correlation analysis using NetworkX graphs
"""

import sys
from typing import Dict, List, Optional, Tuple, Set
from datetime import datetime, timedelta
import json
from pathlib import Path

# Try to import NetworkX
try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False

from ..utils.logger import get_logger, log_errors, PerformanceLogger


class NetworkXCorrelation:
    """IOC correlation analysis using NetworkX graphs."""
    
    def __init__(self, config: Dict):
        """
        Initialize NetworkX correlation engine.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.logger = get_logger()
        
        if not NETWORKX_AVAILABLE:
            self.logger.warning("NetworkX not available - correlation features disabled")
            self.enabled = False
        else:
            self.enabled = True
            self.graph = nx.Graph()
            self.logger.info("NetworkX correlation engine initialized")
    
    def is_available(self) -> bool:
        """Check if NetworkX correlation is available."""
        return NETWORKX_AVAILABLE and self.enabled
    
    @log_errors()
    def build_correlation_graph(self, iocs: List[Dict]) -> nx.Graph:
        """
        Build correlation graph from IOC data.
        
        Args:
            iocs: List of IOC dictionaries
            
        Returns:
            NetworkX graph
        """
        if not self.is_available():
            raise RuntimeError("NetworkX correlation not available")
        
        with PerformanceLogger("build_correlation_graph", self.logger):
            self.graph.clear()
            
            # Add IOC nodes
            for ioc in iocs:
                ioc_value = ioc.get('ioc_value', '')
                ioc_type = ioc.get('ioc_type', '')
                
                if ioc_value:
                    self.graph.add_node(ioc_value, 
                                       type=ioc_type,
                                       severity=ioc.get('severity', {}),
                                       confidence=ioc.get('confidence', ''),
                                       tags=ioc.get('tags', []),
                                       first_seen=ioc.get('first_seen', ''),
                                       last_seen=ioc.get('last_seen', ''))
            
            # Build correlations based on various factors
            self._add_ip_domain_correlations(iocs)
            self._add_temporal_correlations(iocs)
            self._add_severity_correlations(iocs)
            self._add_tag_correlations(iocs)
            self._add_feed_correlations(iocs)
            
            self.logger.info(f"Built correlation graph with {self.graph.number_of_nodes()} nodes and {self.graph.number_of_edges()} edges")
            return self.graph
    
    def _add_ip_domain_correlations(self, iocs: List[Dict]):
        """Add correlations between IPs and domains."""
        ip_iocs = [ioc for ioc in iocs if ioc.get('ioc_type') == 'ip']
        domain_iocs = [ioc for ioc in iocs if ioc.get('ioc_type') == 'domain']
        
        for ip_ioc in ip_iocs:
            ip_value = ip_ioc.get('ioc_value', '')
            
            for domain_ioc in domain_iocs:
                domain_value = domain_ioc.get('ioc_value', '')
                
                # Check if domain resolves to IP (simplified check)
                if self._is_ip_domain_related(ip_value, domain_value):
                    self.graph.add_edge(ip_value, domain_value, 
                                      relation='dns_resolution',
                                      confidence='medium')
    
    def _add_temporal_correlations(self, iocs: List[Dict]):
        """Add correlations based on temporal proximity."""
        for i in, ioc1 in enumerate(iocs):
            for j, ioc2 in enumerate(iocs[i+1:], i+1):
                if self._are_temporally_related(ioc1, ioc2):
                    ioc1_value = ioc1.get('ioc_value', '')
                    ioc2_value = ioc2.get('ioc_value', '')
                    
                    if self.graph.has_node(ioc1_value) and self.graph.has_node(ioc2_value):
                        self.graph.add_edge(ioc1_value, ioc2_value,
                                          relation='temporal',
                                          confidence='low')
    
    def _add_severity_correlations(self, iocs: List[Dict]):
        """Add correlations based on severity levels."""
        high_severity_iocs = [ioc for ioc in iocs 
                             if ioc.get('severity', {}).get('level') in ['critical', 'high']]
        
        for i, ioc1 in enumerate(high_severity_iocs):
            for j, ioc2 in enumerate(high_severity_iocs[i+1:], i+1):
                ioc1_value = ioc1.get('ioc_value', '')
                ioc2_value = ioc2.get('ioc_value', '')
                
                if self.graph.has_node(ioc1_value) and self.graph.has_node(ioc2_value):
                    self.graph.add_edge(ioc1_value, ioc2_value,
                                      relation='high_severity',
                                      confidence='medium')
    
    def _add_tag_correlations(self, iocs: List[Dict]):
        """Add correlations based on shared tags."""
        for i, ioc1 in enumerate(iocs):
            for j, ioc2 in enumerate(iocs[i+1:], i+1):
                tags1 = set(ioc1.get('tags', []))
                tags2 = set(ioc2.get('tags', []))
                
                if tags1 & tags2:  # Shared tags
                    ioc1_value = ioc1.get('ioc_value', '')
                    ioc2_value = ioc2.get('ioc_value', '')
                    
                    if self.graph.has_node(ioc1_value) and self.graph.has_node(ioc2_value):
                        shared_tags = list(tags1 & tags2)
                        self.graph.add_edge(ioc1_value, ioc2_value,
                                          relation='shared_tags',
                                          tags=shared_tags,
                                          confidence='low')
    
    def _add_feed_correlations(self, iocs: List[Dict]):
        """Add correlations based on feed sources."""
        feed_groups = {}
        
        for ioc in iocs:
            feed_source = ioc.get('feed_source', 'unknown')
            if feed_source not in feed_groups:
                feed_groups[feed_source] = []
            feed_groups[feed_source].append(ioc)
        
        for feed_source, feed_iocs in feed_groups.items():
            if len(feed_iocs) > 1:
                for i, ioc1 in enumerate(feed_iocs):
                    for j, ioc2 in enumerate(feed_iocs[i+1:], i+1):
                        ioc1_value = ioc1.get('ioc_value', '')
                        ioc2_value = ioc2.get('ioc_value', '')
                        
                        if self.graph.has_node(ioc1_value) and self.graph.has_node(ioc2_value):
                            self.graph.add_edge(ioc1_value, ioc2_value,
                                              relation='same_feed',
                                              feed=feed_source,
                                              confidence='medium')
    
    def _is_ip_domain_related(self, ip: str, domain: str) -> bool:
        """Check if IP and domain are related (simplified)."""
        # This is a simplified check - in practice, you'd use DNS resolution
        # For now, we'll use some heuristics
        
        # Check if domain contains IP (rare but possible)
        if ip.replace('.', '') in domain.replace('.', ''):
            return True
        
        # Add more sophisticated checks here in a real implementation
        return False
    
    def _are_temporally_related(self, ioc1: Dict, ioc2: Dict) -> bool:
        """Check if two IOCs are temporally related."""
        try:
            first_seen1 = datetime.fromisoformat(ioc1.get('first_seen', '').replace('Z', '+00:00'))
            first_seen2 = datetime.fromisoformat(ioc2.get('first_seen', '').replace('Z', '+00:00'))
            
            # Check if first seen within 24 hours
            time_diff = abs((first_seen1 - first_seen2).total_seconds())
            return time_diff <= 24 * 3600  # 24 hours
            
        except (ValueError, AttributeError):
            return False
    
    @log_errors()
    def find_correlated_clusters(self, min_cluster_size: int = 3) -> List[List[str]]:
        """
        Find clusters of correlated IOCs.
        
        Args:
            min_cluster_size: Minimum size of clusters to return
            
        Returns:
            List of IOC clusters
        """
        if not self.is_available():
            raise RuntimeError("NetworkX correlation not available")
        
        with PerformanceLogger("find_correlated_clusters", self.logger):
            # Find connected components
            clusters = []
            for component in nx.connected_components(self.graph):
                if len(component) >= min_cluster_size:
                    clusters.append(list(component))
            
            self.logger.info(f"Found {len(clusters)} correlation clusters")
            return clusters
    
    @log_errors()
    def find_central_ioCs(self, top_n: int = 10) -> List[Tuple[str, float]]:
        """
        Find most central IOCs in the correlation graph.
        
        Args:
            top_n: Number of top IOCs to return
            
        Returns:
            List of (IOC, centrality_score) tuples
        """
        if not self.is_available():
            raise RuntimeError("NetworkX correlation not available")
        
        with PerformanceLogger("find_central_iocs", self.logger):
            # Calculate betweenness centrality
            centrality = nx.betweenness_centrality(self.graph)
            
            # Sort by centrality score
            sorted_iocs = sorted(centrality.items(), key=lambda x: x[1], reverse=True)
            
            return sorted_iocs[:top_n]
    
    @log_errors()
    def analyze_correlation_patterns(self) -> Dict:
        """
        Analyze correlation patterns in the graph.
        
        Returns:
            Correlation analysis results
        """
        if not self.is_available():
            raise RuntimeError("NetworkX correlation not available")
        
        with PerformanceLogger("analyze_correlation_patterns", self.logger):
            analysis = {
                'graph_metrics': {
                    'total_nodes': self.graph.number_of_nodes(),
                    'total_edges': self.graph.number_of_edges(),
                    'density': nx.density(self.graph),
                    'connected_components': nx.number_connected_components(self.graph)
                },
                'node_metrics': {},
                'edge_types': {},
                'clusters': [],
                'central_iocs': []
            }
            
            # Node type distribution
            node_types = {}
            for node, data in self.graph.nodes(data=True):
                node_type = data.get('type', 'unknown')
                node_types[node_type] = node_types.get(node_type, 0) + 1
            
            analysis['node_metrics']['type_distribution'] = node_types
            
            # Edge type distribution
            edge_types = {}
            for u, v, data in self.graph.edges(data=True):
                edge_type = data.get('relation', 'unknown')
                edge_types[edge_type] = edge_types.get(edge_type, 0) + 1
            
            analysis['edge_types'] = edge_types
            
            # Find clusters
            clusters = self.find_correlated_clusters()
            analysis['clusters'] = [
                {'size': len(cluster), 'iocs': cluster}
                for cluster in clusters
            ]
            
            # Find central IOCs
            central_iocs = self.find_central_ioCs(10)
            analysis['central_iocs'] = [
                {'ioc': ioc, 'centrality': score}
                for ioc, score in central_iocs
            ]
            
            return analysis
    
    @log_errors()
    def export_graph(self, format: str = 'graphml', output_path: Optional[str] = None) -> str:
        """
        Export correlation graph to file.
        
        Args:
            format: Export format ('graphml', 'gexf', 'json')
            output_path: Output file path
            
        Returns:
            Path to exported file
        """
        if not self.is_available():
            raise RuntimeError("NetworkX correlation not available")
        
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"reports/correlation_graph_{timestamp}.{format}"
        
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            if format == 'graphml':
                nx.write_graphml(self.graph, output_path)
            elif format == 'gexf':
                nx.write_gexf(self.graph, output_path)
            elif format == 'json':
                # Export as JSON (custom format)
                graph_data = {
                    'nodes': [
                        {'id': node, **data}
                        for node, data in self.graph.nodes(data=True)
                    ],
                    'edges': [
                        {'source': u, 'target': v, **data}
                        for u, v, data in self.graph.edges(data=True)
                    ]
                }
                
                with open(output_path, 'w') as f:
                    json.dump(graph_data, f, indent=2, default=str)
            else:
                raise ValueError(f"Unsupported export format: {format}")
            
            self.logger.info(f"Correlation graph exported: {output_path}")
            return str(output_path)
            
        except Exception as e:
            self.logger.error(f"Failed to export graph: {str(e)}")
            raise
    
    def get_requirements(self) -> List[str]:
        """Get requirements for NetworkX correlation."""
        return [
            "networkx: Install with 'pip install networkx'",
            "Optional: matplotlib for graph visualization"
        ]
    
    def visualize_graph(self, output_path: Optional[str] = None):
        """
        Create visualization of correlation graph.
        
        Args:
            output_path: Output file path for visualization
        """
        if not self.is_available():
            raise RuntimeError("NetworkX correlation not available")
        
        try:
            import matplotlib.pyplot as plt
            
            if not output_path:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_path = f"reports/correlation_visualization_{timestamp}.png"
            
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Create layout
            pos = nx.spring_layout(self.graph, k=1, iterations=50)
            
            # Create visualization
            plt.figure(figsize=(12, 8))
            
            # Draw nodes
            node_colors = []
            for node in self.graph.nodes():
                node_data = self.graph.nodes[node]
                severity = node_data.get('severity', {}).get('level', 'info')
                
                color_map = {
                    'critical': 'red',
                    'high': 'orange',
                    'medium': 'yellow',
                    'low': 'green',
                    'info': 'blue'
                }
                node_colors.append(color_map.get(severity, 'blue'))
            
            nx.draw_networkx_nodes(self.graph, pos, node_color=node_colors, 
                                 node_size=300, alpha=0.7)
            
            # Draw edges
            nx.draw_networkx_edges(self.graph, pos, alpha=0.5)
            
            # Draw labels for important nodes
            central_nodes = dict(self.find_central_ioCs(5))
            important_labels = {node: node[:10] + '...' if len(node) > 10 else node 
                              for node in central_nodes.keys()}
            
            nx.draw_networkx_labels(self.graph, pos, labels=important_labels, font_size=8)
            
            plt.title("PulseLens IOC Correlation Graph")
            plt.axis('off')
            plt.tight_layout()
            plt.savefig(output_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            self.logger.info(f"Graph visualization created: {output_path}")
            
        except ImportError:
            self.logger.error("matplotlib not available for visualization")
            raise RuntimeError("matplotlib required for visualization")
        except Exception as e:
            self.logger.error(f"Failed to create visualization: {str(e)}")
            raise


def setup_networkx_correlation(config: Dict) -> Optional[NetworkXCorrelation]:
    """
    Setup NetworkX correlation with fallback.
    
    Args:
        config: Configuration dictionary
        
    Returns:
        NetworkXCorrelation instance or None if not available
    """
    try:
        correlation = NetworkXCorrelation(config)
        if correlation.is_available():
            return correlation
        else:
            logger = get_logger()
            logger.warning("NetworkX correlation not available - missing dependencies")
            return None
    except Exception as e:
        logger = get_logger()
        logger.error(f"Failed to setup NetworkX correlation: {str(e)}")
        return None
