from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import logging
import time
from typing import Any, Dict

import requests


@dataclass
class _RateLimiter:
    requests_per_minute: int
    _window_start: float = 0.0
    _count: int = 0

    def wait_if_needed(self) -> None:
        if self.requests_per_minute <= 0:
            return

        now = time.monotonic()
        if self._window_start == 0.0 or now - self._window_start >= 60.0:
            self._window_start = now
            self._count = 0

        if self._count >= self.requests_per_minute:
            sleep_s = max(0.0, 60.0 - (now - self._window_start))
            time.sleep(sleep_s)
            self._window_start = time.monotonic()
            self._count = 0

        self._count += 1


class ThreatFoxClient:
    """Keyless ThreatFox (abuse.ch) IOC lookups."""

    def __init__(self, base_url: str = "https://threatfox-api.abuse.ch/api/v1/", rate_limit: int = 60, auth_key: Optional[str] = None):
        self.base_url = base_url
        self.logger = logging.getLogger(__name__)
        self.session = requests.Session()
        headers = {
            'User-Agent': 'PulseLens/1.0 (+https://localhost)',
            'Accept': 'application/json'
        }
        if auth_key:
            headers['Auth-Key'] = auth_key
        self.session.headers.update(headers)
        self._rl = _RateLimiter(rate_limit)

    def _post_json(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        self._rl.wait_if_needed()
        resp = self.session.post(self.base_url, json=payload, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, dict):
            return {"raw": data}
        return data

    def lookup_ioc(self, ioc_value: str) -> Dict[str, Any]:
        return self._post_json({"query": "search_ioc", "search_term": ioc_value})


def build_cache_key(source: str, ioc_type: str, ioc_value: str) -> str:
    h = hashlib.sha256()
    h.update(f"{source}|{ioc_type}|{ioc_value}".encode("utf-8"))
    return h.hexdigest()


def to_threat_intel(payload: Dict[str, Any], ioc_value: str = "") -> Dict[str, Any]:
    status = payload.get("query_status")

    intel: Dict[str, Any] = {
        "queried_at": datetime.utcnow().isoformat(),
        "query_status": status,
        "is_malicious": False,
        "matches": [],
        "match_count": 0,
    }

    if status == "ok":
        data = payload.get("data")
        if isinstance(data, list) and data:
            # ThreatFox can return partial/related matches; require exact match on the IOC value.
            query = (ioc_value or "").strip().lower()
            exact = []
            for row in data:
                if not isinstance(row, dict):
                    continue
                cand = str(row.get("ioc") or row.get("ioc_value") or "").strip().lower()
                if query and cand == query:
                    exact.append(row)

            if exact:
                intel["is_malicious"] = True
                intel["matches"] = exact[:10]
                intel["match_count"] = len(exact)
            else:
                intel["matches"] = data[:10]
                intel["match_count"] = len(data)

    return intel
