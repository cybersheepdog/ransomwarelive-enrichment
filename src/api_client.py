"""Thin client for the ransomware.live PRO API.

Only GET endpoints are used. Auth is a single ``X-API-KEY`` header.
The PRO free tier allows ~3000 calls/day, so the connector is designed to run
on a daily (or slower) schedule -- see README for the call-budget maths.
"""

from __future__ import annotations

import time
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class RansomwareLiveAPIError(Exception):
    """Raised for any non-recoverable error talking to the PRO API."""


_MAX_RETRIES = 5
_RETRY_BACKOFF_FACTOR = 30  # seconds; PRO tier is rate-limited
_REQUEST_TIMEOUT = 30  # seconds


class RansomwareLiveClient:
    def __init__(self, api_key: str, base_url: str, logger):
        """
        :param api_key: ransomware.live PRO API key (from my.ransomware.live)
        :param base_url: e.g. https://api-pro.ransomware.live
        :param logger: OpenCTIConnectorHelper.connector_logger
        """
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.logger = logger
        self._session = self._build_session()

    @staticmethod
    def _build_session() -> requests.Session:
        retry = Retry(
            total=_MAX_RETRIES,
            status_forcelist=[429, 500, 502, 503, 504],
            backoff_factor=_RETRY_BACKOFF_FACTOR,
            allowed_methods=["GET"],
            respect_retry_after_header=True,
        )
        adapter = HTTPAdapter(max_retries=retry)
        session = requests.Session()
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        return session

    def _get(self, path: str, *, allow_404: bool = False) -> Any:
        """GET {base}/{path}. Returns parsed JSON, or None on an allowed 404.

        Some group sub-resources (yara/iocs) legitimately 404 when a group has
        none; callers pass allow_404=True so that is treated as "no data".
        """
        url = f"{self.base_url}/{path.lstrip('/')}"
        try:
            resp = self._session.get(
                url,
                headers={
                    "accept": "application/json",
                    "X-API-KEY": self.api_key,
                    "User-Agent": "OpenCTI-RansomwareLive-Enrichment",
                },
                timeout=_REQUEST_TIMEOUT,
            )
            if resp.status_code == 404 and allow_404:
                return None
            resp.raise_for_status()
            if not resp.content:
                return None
            # /yara/<group> can return raw text rather than JSON.
            ctype = resp.headers.get("Content-Type", "")
            if "application/json" in ctype:
                return resp.json()
            try:
                return resp.json()
            except ValueError:
                return resp.text
        except requests.exceptions.HTTPError as err:
            status = getattr(err.response, "status_code", "?")
            body = getattr(err.response, "text", "") or ""
            self.logger.error(
                "PRO API HTTP error",
                {"url": f"GET {url}", "status": status, "body": body[:300]},
            )
            raise RansomwareLiveAPIError(f"HTTP {status} for {url}") from err
        except requests.RequestException as err:
            self.logger.error("PRO API request error", {"url": f"GET {url}", "error": str(err)})
            raise RansomwareLiveAPIError(f"Request failed for {url}: {err}") from err

    # ---- endpoint wrappers -------------------------------------------------

    def list_groups(self) -> list[dict]:
        """GET /groups -> list of group records.

        Free v2 returns a bare list; the PRO API wraps it in an envelope
        (e.g. ``{"client": ..., "groups": [...]}``). Accept both, and normalise
        bare-string entries to ``{"name": <str>}``."""
        data = self._get("/groups")
        raw = self._extract_list(data, ("groups", "data", "results", "items"))
        groups = self._normalize_groups(raw)
        if not groups and data:
            self.logger.warning(
                "No group list found in /groups payload",
                {"shape": list(data.keys()) if isinstance(data, dict) else type(data).__name__},
            )
        return groups

    @staticmethod
    def _normalize_groups(raw: list) -> list[dict]:
        """Ensure every group record exposes a ``name``. The PRO ``/groups`` feed
        names the group with the ``group`` key (e.g. ``{"group": "8base", ...}``),
        while the free v2 feed uses ``name``; bare strings are wrapped."""
        groups: list[dict] = []
        for item in raw:
            if isinstance(item, dict):
                if not item.get("name") and item.get("group"):
                    item = {**item, "name": item["group"]}
                if item.get("name"):
                    groups.append(item)
            elif isinstance(item, str) and item.strip():
                groups.append({"name": item.strip()})
        return groups

    @staticmethod
    def _extract_list(data: Any, keys: tuple) -> list:
        """Return the first list found: ``data`` itself if it's a list, else the
        first matching envelope key, else the first list-valued item in the dict."""
        if data is None:
            return []
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for key in keys:
                if isinstance(data.get(key), list):
                    return data[key]
            for value in data.values():
                if isinstance(value, list):
                    return value
        return []

    def get_group(self, name: str) -> dict | None:
        """GET /groups/<name> -> full group detail (tools, ttps, description...).

        Accepts a bare object, a single-element list, or a PRO envelope that
        nests the group object under ``group``/``data``/``result``."""
        data = self._get(f"/groups/{requests.utils.quote(name, safe='')}", allow_404=True)
        if data is None:
            return None
        if isinstance(data, list):
            data = next((d for d in data if isinstance(d, dict)), None)
        if not isinstance(data, dict):
            return None
        # If the detail fields aren't at the top level, unwrap a nested envelope.
        if "tools" not in data and "ttps" not in data:
            for key in ("group", "data", "result"):
                nested = data.get(key)
                if isinstance(nested, dict) and ("tools" in nested or "ttps" in nested):
                    return nested
        return data

    def get_group_iocs(self, name: str) -> list[dict]:
        """GET /iocs/<name> -> list of IOC dicts (best-effort shape)."""
        data = self._get(f"/iocs/{requests.utils.quote(name, safe='')}", allow_404=True)
        return self._as_ioc_list(data)

    def get_group_yara(self, name: str) -> str | None:
        """GET /yara/<name> -> raw YARA rule text (or None)."""
        data = self._get(f"/yara/{requests.utils.quote(name, safe='')}", allow_404=True)
        if data is None:
            return None
        if isinstance(data, str):
            return data.strip() or None
        # If JSON, try common shapes: {"rule": "..."} / [{"rule": "..."}] / {"yara": "..."}
        if isinstance(data, dict):
            for key in ("rule", "yara", "content", "rules"):
                val = data.get(key)
                if isinstance(val, str) and val.strip():
                    return val.strip()
        if isinstance(data, list):
            parts = []
            for item in data:
                if isinstance(item, str) and item.strip():
                    parts.append(item.strip())
                elif isinstance(item, dict):
                    for key in ("rule", "yara", "content"):
                        if isinstance(item.get(key), str) and item[key].strip():
                            parts.append(item[key].strip())
                            break
            return "\n\n".join(parts) if parts else None
        return None

    @staticmethod
    def _as_ioc_list(data: Any) -> list[dict]:
        """Normalise the many shapes /iocs/<group> can take into a flat list of
        IOC records. The confirmed PRO shape is:
            {"group": "...", "ioc_types": [...],
             "iocs": {"sha1": ["..."], "tox": ["..."]}}
        i.e. the real IOCs are nested under ``iocs`` as a dict keyed by type.
        We also tolerate ``iocs`` being a plain list, other envelope keys, and a
        bare top-level type->list map."""
        if data is None:
            return []
        if isinstance(data, list):
            return [i for i in data if isinstance(i, (dict, str))]
        if not isinstance(data, dict):
            return []

        # Prefer the nested payload under a known envelope key; fall back to the
        # whole object only if none is present (so sibling keys like
        # ``ioc_types`` are never mistaken for IOCs).
        inner: Any = None
        for key in ("iocs", "indicators", "data", "results"):
            if key in data:
                inner = data[key]
                break
        if inner is None:
            inner = data

        if isinstance(inner, list):
            return [i for i in inner if isinstance(i, (dict, str))]

        if isinstance(inner, dict):
            # dict keyed by IOC type: {"sha1": [...], "tox": [...]}
            flattened: list[dict] = []
            for k, v in inner.items():
                if isinstance(v, list):
                    for val in v:
                        if isinstance(val, str):
                            flattened.append({"type": k, "value": val})
                        elif isinstance(val, dict):
                            flattened.append({"type": k, **val})
                elif isinstance(v, str):
                    flattened.append({"type": k, "value": v})
            return flattened
        return []
