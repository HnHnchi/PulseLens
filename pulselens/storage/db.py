import sqlite3
import json
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from pathlib import Path
import logging

class IOCDatabase:
    """SQLite database for caching IOC data and maintaining history."""
    
    def __init__(self, db_path: str, cache_expiry_hours: int = 24):
        self.db_path = Path(db_path)
        self.cache_expiry_hours = cache_expiry_hours
        self.logger = logging.getLogger(__name__)
        
        # Create database and tables
        self._initialize_database()
    
    def _initialize_database(self) -> None:
        """Initialize database tables."""
        # Create directory if it doesn't exist
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Create IOCs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS iocs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ioc_value TEXT NOT NULL,
                    ioc_type TEXT NOT NULL,
                    original_value TEXT NOT NULL,
                    feed_source TEXT DEFAULT 'manual',
                    first_seen TEXT,
                    last_seen TEXT,
                    confidence TEXT DEFAULT 'medium',
                    tags TEXT,  -- JSON array
                    metadata TEXT,  -- JSON object
                    enrichment TEXT,  -- JSON object
                    severity TEXT,  -- JSON object
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(ioc_value, ioc_type)
                )
            ''')
            
            # Create cache table for external API results
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS api_cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cache_key TEXT NOT NULL UNIQUE,
                    source TEXT NOT NULL,
                    data TEXT NOT NULL,  -- JSON object
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    expires_at TEXT NOT NULL
                )
            ''')
            
            # Create analysis history table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS analysis_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_id TEXT NOT NULL,
                    ioc_count INTEGER NOT NULL,
                    severity_summary TEXT,  -- JSON object
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create indexes for better performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(ioc_value)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(ioc_type)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_iocs_severity ON iocs(severity)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_cache_key ON api_cache(cache_key)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_cache_expires ON api_cache(expires_at)')
            
            conn.commit()
    
    def save_iocs(self, iocs: List[Dict]) -> int:
        """
        Save IOCs to database.
        
        Args:
            iocs: List of IOC dictionaries
            
        Returns:
            Number of IOCs saved
        """
        saved_count = 0
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            for ioc in iocs:
                try:
                    # Convert complex objects to JSON strings
                    tags_json = json.dumps(ioc.get('tags', []))
                    metadata_json = json.dumps(ioc.get('metadata', {}))
                    enrichment_json = json.dumps(ioc.get('enrichment', {}))
                    severity_json = json.dumps(ioc.get('severity', {}))
                    
                    cursor.execute('''
                        INSERT OR REPLACE INTO iocs (
                            ioc_value, ioc_type, original_value, feed_source,
                            first_seen, last_seen, confidence, tags,
                            metadata, enrichment, severity, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        ioc.get('ioc_value'),
                        ioc.get('ioc_type'),
                        ioc.get('original_value'),
                        ioc.get('feed_source', 'manual'),
                        ioc.get('first_seen'),
                        ioc.get('last_seen'),
                        ioc.get('confidence', 'medium'),
                        tags_json,
                        metadata_json,
                        enrichment_json,
                        severity_json,
                        datetime.utcnow().isoformat()
                    ))
                    
                    saved_count += 1
                    
                except sqlite3.Error as e:
                    self.logger.error(f"Failed to save IOC {ioc.get('ioc_value', 'unknown')}: {e}")
            
            conn.commit()
        
        return saved_count
    
    def get_ioc(self, ioc_value: str, ioc_type: str) -> Optional[Dict]:
        """
        Get a single IOC from database.
        
        Args:
            ioc_value: The IOC value
            ioc_type: The IOC type
            
        Returns:
            IOC dictionary or None if not found
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM iocs WHERE ioc_value = ? AND ioc_type = ?
            ''', (ioc_value, ioc_type))
            
            row = cursor.fetchone()
            
            if row:
                return self._row_to_ioc_dict(row)
            
            return None
    
    def get_iocs_by_type(self, ioc_type: str, limit: Optional[int] = None) -> List[Dict]:
        """
        Get IOCs by type.
        
        Args:
            ioc_type: The IOC type
            limit: Maximum number of results
            
        Returns:
            List of IOC dictionaries
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            query = 'SELECT * FROM iocs WHERE ioc_type = ? ORDER BY updated_at DESC'
            params = [ioc_type]
            
            if limit:
                query += ' LIMIT ?'
                params.append(limit)
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            return [self._row_to_ioc_dict(row) for row in rows]
    
    def get_iocs_by_severity(self, severity_level: str, limit: Optional[int] = None) -> List[Dict]:
        """
        Get IOCs by severity level.
        
        Args:
            severity_level: The severity level
            limit: Maximum number of results
            
        Returns:
            List of IOC dictionaries
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            query = '''
                SELECT * FROM iocs 
                WHERE JSON_EXTRACT(severity, '$.level') = ? 
                ORDER BY updated_at DESC
            '''
            params = [severity_level]
            
            if limit:
                query += ' LIMIT ?'
                params.append(limit)
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            return [self._row_to_ioc_dict(row) for row in rows]
    
    def search_iocs(self, query: str, limit: Optional[int] = None) -> List[Dict]:
        """
        Search IOCs by value.
        
        Args:
            query: Search query
            limit: Maximum number of results
            
        Returns:
            List of IOC dictionaries
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            search_query = '''
                SELECT * FROM iocs 
                WHERE ioc_value LIKE ? OR original_value LIKE ?
                ORDER BY updated_at DESC
            '''
            params = [f'%{query}%', f'%{query}%']
            
            if limit:
                search_query += ' LIMIT ?'
                params.append(limit)
            
            cursor.execute(search_query, params)
            rows = cursor.fetchall()
            
            return [self._row_to_ioc_dict(row) for row in rows]
    
    def get_recent_iocs(self, hours: int = 24, limit: Optional[int] = None) -> List[Dict]:
        """
        Get recently added/updated IOCs.
        
        Args:
            hours: Number of hours to look back
            limit: Maximum number of results
            
        Returns:
            List of IOC dictionaries
        """
        cutoff_time = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            query = '''
                SELECT * FROM iocs 
                WHERE updated_at > ? 
                ORDER BY updated_at DESC
            '''
            params = [cutoff_time]
            
            if limit:
                query += ' LIMIT ?'
                params.append(limit)
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            return [self._row_to_ioc_dict(row) for row in rows]
    
    def cache_api_result(self, cache_key: str, source: str, data: Dict) -> None:
        """
        Cache API result to reduce external calls.
        
        Args:
            cache_key: Unique cache key
            source: API source name
            data: Data to cache
        """
        expires_at = (datetime.utcnow() + timedelta(hours=self.cache_expiry_hours)).isoformat()
        data_json = json.dumps(data)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO api_cache (cache_key, source, data, expires_at)
                VALUES (?, ?, ?, ?)
            ''', (cache_key, source, data_json, expires_at))
            
            conn.commit()
    
    def get_cached_result(self, cache_key: str) -> Optional[Dict]:
        """
        Get cached API result.
        
        Args:
            cache_key: Unique cache key
            
        Returns:
            Cached data or None if not found/expired
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT data FROM api_cache 
                WHERE cache_key = ? AND expires_at > ?
            ''', (cache_key, datetime.utcnow().isoformat()))
            
            row = cursor.fetchone()
            
            if row:
                return json.loads(row[0])
            
            return None
    
    def cleanup_expired_cache(self) -> int:
        """Remove expired cache entries."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                DELETE FROM api_cache WHERE expires_at <= ?
            ''', (datetime.utcnow().isoformat(),))
            
            deleted_count = cursor.rowcount
            
            conn.commit()
            
            return deleted_count
    
    def save_analysis_history(self, analysis_id: str, ioc_count: int, severity_summary: Dict) -> None:
        """
        Save analysis history.
        
        Args:
            analysis_id: Unique analysis identifier
            ioc_count: Number of IOCs analyzed
            severity_summary: Summary of severity distribution
        """
        summary_json = json.dumps(severity_summary)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO analysis_history (analysis_id, ioc_count, severity_summary)
                VALUES (?, ?, ?)
            ''', (analysis_id, ioc_count, summary_json))
            
            conn.commit()
    
    def get_analysis_history(self, limit: int = 10) -> List[Dict]:
        """
        Get analysis history.
        
        Args:
            limit: Maximum number of results
            
        Returns:
            List of analysis history entries
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM analysis_history 
                ORDER BY created_at DESC 
                LIMIT ?
            ''', (limit,))
            
            rows = cursor.fetchall()
            
            history = []
            for row in rows:
                history.append({
                    'id': row[0],
                    'analysis_id': row[1],
                    'ioc_count': row[2],
                    'severity_summary': json.loads(row[3]) if row[3] else {},
                    'created_at': row[4]
                })
            
            return history
    
    def get_statistics(self) -> Dict:
        """Get database statistics."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Total IOCs
            cursor.execute('SELECT COUNT(*) FROM iocs')
            total_iocs = cursor.fetchone()[0]
            
            # IOCs by type
            cursor.execute('''
                SELECT ioc_type, COUNT(*) FROM iocs 
                GROUP BY ioc_type
            ''')
            raw_types = cursor.fetchall()
            iocs_by_type = {
                (str(ioc_type) if ioc_type is not None else 'unknown'): int(count or 0)
                for ioc_type, count in raw_types
            }
            
            # IOCs by severity
            cursor.execute('''
                SELECT 
                    JSON_EXTRACT(severity, '$.level') as level,
                    COUNT(*) 
                FROM iocs 
                WHERE severity IS NOT NULL
                GROUP BY level
            ''')
            raw_sev = cursor.fetchall()
            # JSON_EXTRACT can yield NULL -> Python None key, which breaks jsonify
            iocs_by_severity = {
                (str(level) if level is not None else 'unknown'): int(count or 0)
                for level, count in raw_sev
            }
            
            # Recent IOCs (last 24 hours)
            recent_cutoff = (datetime.utcnow() - timedelta(hours=24)).isoformat()
            cursor.execute('SELECT COUNT(*) FROM iocs WHERE updated_at > ?', (recent_cutoff,))
            recent_iocs = cursor.fetchone()[0]
            
            # Cache statistics
            cursor.execute('SELECT COUNT(*) FROM api_cache')
            cache_entries = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM api_cache WHERE expires_at <= ?', 
                          (datetime.utcnow().isoformat(),))
            expired_cache = cursor.fetchone()[0]
            
            return {
                'total_iocs': total_iocs,
                'iocs_by_type': iocs_by_type,
                'iocs_by_severity': iocs_by_severity,
                'recent_iocs_24h': recent_iocs,
                'cache_entries': cache_entries,
                'expired_cache_entries': expired_cache
            }

    def get_stats_history(self, days: int = 30) -> List[Dict[str, Any]]:
        """Get daily IOC stats history for the last N days."""
        if days < 1:
            days = 1

        cutoff_time = (datetime.utcnow() - timedelta(days=days)).isoformat()

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute(
                '''
                SELECT
                    SUBSTR(updated_at, 1, 10) as day,
                    COUNT(*) as total,
                    SUM(
                        CASE
                            WHEN JSON_EXTRACT(severity, '$.level') IN ('critical', 'high') THEN 1
                            ELSE 0
                        END
                    ) as high_risk
                FROM iocs
                WHERE updated_at >= ?
                GROUP BY day
                ORDER BY day ASC
                ''',
                (cutoff_time,)
            )

            rows = cursor.fetchall()

        history: List[Dict[str, Any]] = []
        for day, total, high_risk in rows:
            history.append({
                'day': day,
                'total_iocs': int(total or 0),
                'high_risk_count': int(high_risk or 0)
            })

        return history
    
    def _row_to_ioc_dict(self, row) -> Dict:
        """Convert database row to IOC dictionary."""
        return {
            'id': row[0],
            'ioc_value': row[1],
            'ioc_type': row[2],
            'original_value': row[3],
            'feed_source': row[4],
            'first_seen': row[5],
            'last_seen': row[6],
            'confidence': row[7],
            'tags': json.loads(row[8]) if row[8] else [],
            'metadata': json.loads(row[9]) if row[9] else {},
            'enrichment': json.loads(row[10]) if row[10] else {},
            'severity': json.loads(row[11]) if row[11] else {},
            'created_at': row[12],
            'updated_at': row[13]
        }
    
    def export_iocs(self, format: str = 'json', filters: Optional[Dict] = None) -> str:
        """
        Export IOCs from database.
        
        Args:
            format: Export format ('json' or 'csv')
            filters: Optional filters to apply
            
        Returns:
            Exported data as string
        """
        # Build query based on filters
        query = 'SELECT * FROM iocs'
        params = []
        
        where_clauses = []
        if filters:
            if filters.get('ioc_type'):
                where_clauses.append('ioc_type = ?')
                params.append(filters['ioc_type'])
            
            if filters.get('severity_level'):
                where_clauses.append('JSON_EXTRACT(severity, "$.level") = ?')
                params.append(filters['severity_level'])
            
            if filters.get('hours_recent'):
                cutoff = (datetime.utcnow() - timedelta(hours=filters['hours_recent'])).isoformat()
                where_clauses.append('updated_at > ?')
                params.append(cutoff)
        
        if where_clauses:
            query += ' WHERE ' + ' AND '.join(where_clauses)
        
        query += ' ORDER BY updated_at DESC'
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            iocs = [self._row_to_ioc_dict(row) for row in rows]
        
        if format == 'json':
            return json.dumps(iocs, indent=2)
        elif format == 'csv':
            return self._iocs_to_csv(iocs)
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def _iocs_to_csv(self, iocs: List[Dict]) -> str:
        """Convert IOCs to CSV format."""
        import csv
        import io
        
        output = io.StringIO()
        
        if not iocs:
            return ''
        
        # Define CSV headers
        headers = [
            'ioc_value', 'ioc_type', 'original_value', 'feed_source',
            'first_seen', 'last_seen', 'confidence', 'severity_level',
            'severity_score', 'tags'
        ]
        
        writer = csv.DictWriter(output, fieldnames=headers)
        writer.writeheader()
        
        for ioc in iocs:
            severity = ioc.get('severity', {})
            row = {
                'ioc_value': ioc.get('ioc_value', ''),
                'ioc_type': ioc.get('ioc_type', ''),
                'original_value': ioc.get('original_value', ''),
                'feed_source': ioc.get('feed_source', ''),
                'first_seen': ioc.get('first_seen', ''),
                'last_seen': ioc.get('last_seen', ''),
                'confidence': ioc.get('confidence', ''),
                'severity_level': severity.get('level', ''),
                'severity_score': severity.get('score', ''),
                'tags': ';'.join(ioc.get('tags', []))
            }
            writer.writerow(row)
        
        return output.getvalue()
    
    def close(self) -> None:
        """Close database connection (if needed)."""
        # SQLite connections are automatically closed when using context managers
        pass
