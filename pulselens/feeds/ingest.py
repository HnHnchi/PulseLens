from __future__ import annotations

import csv
import io
import logging
from urllib.parse import urlparse
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests

from ..input.validator import IOCValidator


@dataclass
class FeedIngestResult:
    source: str
    fetched: bool
    parsed_rows: int
    accepted: int
    rejected: int
    saved: int
    errors: List[str]


def _confidence_from_percent(value: Optional[str]) -> str:
    try:
        if value is None:
            return 'medium'
        v = int(str(value).strip().strip('"'))
        if v >= 90:
            return 'high'
        if v >= 60:
            return 'medium'
        return 'low'
    except Exception:
        return 'medium'


def _split_tags(tags: Any) -> List[str]:
    if tags is None:
        return []
    if isinstance(tags, list):
        return [str(t).strip() for t in tags if str(t).strip()]
    s = str(tags).strip().strip('"')
    if not s or s.lower() == 'none':
        return []
    return [t.strip() for t in s.split(',') if t.strip()]


def fetch_text(url: str, timeout: int = 60) -> str:
    resp = requests.get(
        url,
        headers={
            'User-Agent': 'PulseLens/1.0 (+https://localhost)',
            'Accept': '*/*'
        },
        timeout=timeout,
    )
    resp.raise_for_status()
    return resp.text


def parse_urlhaus_csv(text: str, source: str = 'urlhaus_feed') -> Tuple[List[Dict[str, Any]], int, int, int]:
    """Parse URLhaus CSV (recent/online) exports."""
    validator = IOCValidator()
    parsed_rows = 0
    accepted = 0
    rejected = 0

    out: List[Dict[str, Any]] = []

    # URLhaus exports may include comment lines starting with '#'
    lines = []
    for line in text.splitlines():
        if not line:
            continue
        if line.lstrip().startswith('#'):
            continue
        lines.append(line)

    if not lines:
        return out, 0, 0, 0

    delimiter = ';' if lines[0].count(';') > lines[0].count(',') else ','

    reader = csv.reader(io.StringIO('\n'.join(lines)), delimiter=delimiter, skipinitialspace=True)
    for row in reader:
        if not row:
            continue

        # Some exports may include a header row; detect and skip it.
        first = str(row[0]).strip().strip('"').lower()
        if first == 'id':
            continue

        parsed_rows += 1

        # Expected URLhaus columns:
        # id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
        url_value = str(row[2]).strip().strip('"') if len(row) > 2 else ''
        if not url_value:
            rejected += 1
            continue

        normalized: Optional[str] = None
        # URLhaus provides URLs - but IOCValidator checks domain before URL.
        # If we pass a URL into validate_ioc(), it will often be classified as a domain.
        try:
            if '://' in url_value:
                parsed = urlparse(url_value)
                if parsed.scheme and parsed.netloc:
                    normalized = f"{parsed.scheme}://{parsed.netloc.lower()}"
                    if parsed.path:
                        normalized += parsed.path
                    if parsed.query:
                        normalized += f"?{parsed.query}"
        except Exception:
            normalized = None

        if not normalized:
            is_valid, detected_type, detected_value = validator.validate_ioc(url_value)
            if not is_valid or not detected_value:
                rejected += 1
                continue
            # If we couldn't parse as a URL, accept only if it's a URL.
            if detected_type != 'url':
                rejected += 1
                continue
            normalized = detected_value

        tags = _split_tags(row[6] if len(row) > 6 else None)
        tags.extend(['feed', 'urlhaus'])

        out.append({
            'ioc_value': normalized,
            'ioc_type': 'url',
            'original_value': url_value,
            'feed_source': source,
            'first_seen': str(row[1]).strip().strip('"') if len(row) > 1 else None,
            'last_seen': str(row[4]).strip().strip('"') if len(row) > 4 else None,
            'confidence': 'high',
            'tags': list(dict.fromkeys([t for t in tags if t])),
            'metadata': {
                'urlhaus_id': str(row[0]).strip().strip('"') if len(row) > 0 else None,
                'url_status': str(row[3]).strip().strip('"') if len(row) > 3 else None,
                'threat': str(row[5]).strip().strip('"') if len(row) > 5 else None,
                'urlhaus_link': str(row[7]).strip().strip('"') if len(row) > 7 else None,
                'reporter': str(row[8]).strip().strip('"') if len(row) > 8 else None,
            },
            'enrichment': {},
            'severity': {},
        })
        accepted += 1

    return out, parsed_rows, accepted, rejected


def _normalize_threatfox_ioc(ioc_value: str, ioc_type: str, validator: IOCValidator) -> Tuple[bool, Optional[str], Optional[str]]:
    v = (ioc_value or '').strip().strip('"')
    t = (ioc_type or '').strip().strip('"').lower()

    if not v or not t:
        return False, None, None

    if t in ['ip:port', 'ip-port']:
        # split last ':' (ipv4 only here)
        if ':' in v:
            v = v.split(':', 1)[0]
        is_valid, detected, normalized = validator.validate_ioc(v)
        if is_valid and detected == 'ip':
            return True, 'ip', normalized
        return False, None, None

    if t in ['md5', 'sha1', 'sha256', 'sha512']:
        is_valid, detected, normalized = validator.validate_ioc(v)
        if is_valid and detected == 'hash':
            return True, 'hash', normalized
        return False, None, None

    # domain/url/ip are compatible
    is_valid, detected, normalized = validator.validate_ioc(v)
    if not is_valid:
        return False, None, None

    if detected not in ['domain', 'url', 'ip', 'hash', 'email']:
        return False, None, None

    return True, detected, normalized


def parse_threatfox_csv(text: str, source: str = 'threatfox_feed') -> Tuple[List[Dict[str, Any]], int, int, int]:
    """Parse ThreatFox CSV recent export."""
    validator = IOCValidator()

    parsed_rows = 0
    accepted = 0
    rejected = 0

    out: List[Dict[str, Any]] = []

    # ThreatFox CSV is quoted and sometimes has spaces after commas.
    reader = csv.reader(io.StringIO(text), skipinitialspace=True)

    for row in reader:
        if not row:
            continue

        # Comment/header lines
        first = str(row[0]).strip()
        if first.startswith('#'):
            continue

        # If this is the header row, skip
        if first.strip('"').lower() == 'first_seen_utc':
            continue

        parsed_rows += 1

        # Expected columns (may vary slightly)
        # 0 first_seen_utc
        # 1 ioc_id
        # 2 ioc_value
        # 3 ioc_type
        # 4 threat_type
        # 5 fk_malware
        # 6 malware_alias
        # 7 malware_printable
        # 8 last_seen_utc
        # 9 confidence_level
        # 10 reference
        # 11 tags
        # 12 anonymous
        # 13 reporter
        ioc_value = row[2] if len(row) > 2 else ''
        ioc_type = row[3] if len(row) > 3 else ''

        ok, normalized_type, normalized_value = _normalize_threatfox_ioc(ioc_value, ioc_type, validator)
        if not ok or not normalized_type or not normalized_value:
            rejected += 1
            continue

        tags = _split_tags(row[11] if len(row) > 11 else None)
        tags.extend(['feed', 'threatfox'])

        out.append({
            'ioc_value': normalized_value,
            'ioc_type': normalized_type,
            'original_value': str(ioc_value).strip(),
            'feed_source': source,
            'first_seen': str(row[0]).strip().strip('"') if len(row) > 0 else None,
            'last_seen': str(row[8]).strip().strip('"') if len(row) > 8 else None,
            'confidence': _confidence_from_percent(row[9] if len(row) > 9 else None),
            'tags': list(dict.fromkeys([t for t in tags if t])),
            'metadata': {
                'threatfox_ioc_id': str(row[1]).strip().strip('"') if len(row) > 1 else None,
                'threat_type': str(row[4]).strip().strip('"') if len(row) > 4 else None,
                'malware_printable': str(row[7]).strip().strip('"') if len(row) > 7 else None,
                'reference': str(row[10]).strip().strip('"') if len(row) > 10 else None,
                'reporter': str(row[13]).strip().strip('"') if len(row) > 13 else None,
            },
            'enrichment': {},
            'severity': {},
        })
        accepted += 1

    return out, parsed_rows, accepted, rejected


def ingest_to_db(db: Any, iocs: List[Dict[str, Any]]) -> int:
    """Save parsed IOC dicts into IOCDatabase."""
    if not db:
        return 0
    return int(db.save_iocs(iocs))


def refresh_feeds(
    db: Any,
    urlhaus_csv_url: Optional[str] = None,
    threatfox_csv_url: Optional[str] = None,
    urlhaus_enabled: bool = True,
    threatfox_enabled: bool = True,
) -> List[FeedIngestResult]:
    logger = logging.getLogger(__name__)
    results: List[FeedIngestResult] = []

    if urlhaus_enabled and urlhaus_csv_url:
        errors: List[str] = []
        try:
            txt = fetch_text(urlhaus_csv_url)
            iocs, parsed, accepted, rejected = parse_urlhaus_csv(txt)
            saved = ingest_to_db(db, iocs)
            results.append(FeedIngestResult('urlhaus', True, parsed, accepted, rejected, saved, errors))
        except Exception as e:
            msg = str(e)
            logger.error(f"URLhaus feed refresh failed: {msg}")
            errors.append(msg)
            results.append(FeedIngestResult('urlhaus', False, 0, 0, 0, 0, errors))

    if threatfox_enabled and threatfox_csv_url:
        errors = []
        try:
            txt = fetch_text(threatfox_csv_url)
            iocs, parsed, accepted, rejected = parse_threatfox_csv(txt)
            saved = ingest_to_db(db, iocs)
            results.append(FeedIngestResult('threatfox', True, parsed, accepted, rejected, saved, errors))
        except Exception as e:
            msg = str(e)
            logger.error(f"ThreatFox feed refresh failed: {msg}")
            errors.append(msg)
            results.append(FeedIngestResult('threatfox', False, 0, 0, 0, 0, errors))

    return results
