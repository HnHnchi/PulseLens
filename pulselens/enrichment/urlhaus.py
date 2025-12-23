from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import logging
import time
from typing import Any, Dict, Optional

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


class URLhausClient:
    """Keyless URLhaus (abuse.ch) lookups for URLs and hosts."""

    def __init__(self, base_url: str = "https://urlhaus-api.abuse.ch/v1", rate_limit: int = 60, auth_key: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
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

    def _post_form(self, endpoint: str, form: Dict[str, Any]) -> Dict[str, Any]:
        self._rl.wait_if_needed()
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        resp = self.session.post(url, data=form, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, dict):
            return {"raw": data}
        return data

    def lookup_url(self, url_value: str) -> Dict[str, Any]:
        return self._post_form("url/", {"url": url_value})

    def lookup_host(self, host_value: str) -> Dict[str, Any]:
        return self._post_form("host/", {"host": host_value})


def build_cache_key(source: str, ioc_type: str, ioc_value: str) -> str:
    h = hashlib.sha256()
    h.update(f"{source}|{ioc_type}|{ioc_value}".encode("utf-8"))
    return h.hexdigest()


def to_threat_intel(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize URLhaus response into a compact structure."""
    status = payload.get("query_status")

    intel: Dict[str, Any] = {
        "queried_at": datetime.utcnow().isoformat(),
        "query_status": status,
        "is_malicious": False,
    }

    if status == "ok":
        intel["is_malicious"] = True
        intel["urlhaus_reference"] = payload.get("urlhaus_reference")
        intel["url_status"] = payload.get("url_status")
        intel["threat"] = payload.get("threat")
        intel["tags"] = payload.get("tags") or []
        intel["host"] = payload.get("host")
        intel["date_added"] = payload.get("date_added")
        intel["reporter"] = payload.get("reporter")
        intel["blacklists"] = payload.get("blacklists") or {}
        intel["payloads"] = payload.get("payloads") or []

    return intel
