#!/usr/bin/env python3

import argparse
import json
import logging
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

import config

from pulselens.storage.db import IOCDatabase
from pulselens.feeds.ingest import refresh_feeds


def main() -> int:
    parser = argparse.ArgumentParser(description='Refresh keyless threat intel feeds (URLhaus/ThreatFox) into SQLite')
    parser.add_argument('--urlhaus', action='store_true', help='Enable URLhaus CSV recent ingestion')
    parser.add_argument('--threatfox', action='store_true', help='Enable ThreatFox CSV recent ingestion')
    parser.add_argument('--all', action='store_true', help='Enable all feeds')
    parser.add_argument('--output', help='Write JSON summary to file')

    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, getattr(config, 'LOG_LEVEL', 'INFO')))

    db = IOCDatabase(str(getattr(config, 'DATABASE_PATH', 'data/cache.db')), cache_expiry_hours=getattr(config, 'CACHE_EXPIRY_HOURS', 24))

    urlhaus_enabled = args.all or args.urlhaus or getattr(config, 'URLHAUS_FEED_ENABLED', True)
    threatfox_enabled = args.all or args.threatfox or getattr(config, 'THREATFOX_FEED_ENABLED', True)

    results = refresh_feeds(
        db=db,
        urlhaus_csv_url=getattr(config, 'URLHAUS_FEED_CSV_RECENT_URL', None),
        threatfox_csv_url=getattr(config, 'THREATFOX_FEED_CSV_RECENT_URL', None),
        urlhaus_enabled=urlhaus_enabled,
        threatfox_enabled=threatfox_enabled,
    )

    payload = {
        'status': 'success',
        'results': [r.__dict__ for r in results]
    }

    out = json.dumps(payload, indent=2)
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(out)
    else:
        print(out)

    # exit non-zero if any feed failed
    if any((not r.fetched) for r in results):
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
