"""Optional secondary source for CVEs a ransomware group is known to weaponise.

The ransomware.live PRO API does NOT expose the vulnerability matrix (its
``/groups/<name>.vulnerabilities`` is empty and ``/vulnerabilities/<group>``
404s). The "Vulnerabilities Exploited" data shown on the website comes from the
public BushidoUK/Ransomware-Vulnerability-Matrix project. That repo's README
links a small set of category files under ``Vulnerabilities/`` whose tables read:

    | Product | CVE(s) | Ransomware Group(s) | Source(s) |

We fetch the README (for the category list), fetch each category file, and build
a ``normalised-group -> {CVEs}`` map once. No API key and no GitHub API (raw CDN
only, so we avoid the unauthenticated api.github.com rate limit).
"""

from __future__ import annotations

import re

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_CAT_RE = re.compile(r"(Vulnerabilities/[A-Za-z0-9._%-]+\.md)")
_REQUEST_TIMEOUT = 30


def _norm(name: str) -> str:
    """lowercase, alphanumeric-only key for matching group names."""
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


class VulnMatrixClient:
    def __init__(
        self,
        logger,
        repo: str = "BushidoUK/Ransomware-Vulnerability-Matrix",
        branch: str = "main",
    ):
        self.logger = logger
        self.base = f"https://raw.githubusercontent.com/{repo}/{branch}/"
        retry = Retry(total=3, backoff_factor=2,
                      status_forcelist=[429, 500, 502, 503, 504])
        self._session = requests.Session()
        self._session.mount("https://", HTTPAdapter(max_retries=retry))
        self._map: dict[str, set] | None = None  # normalised group -> {CVEs}

    def _get(self, path: str) -> str | None:
        try:
            r = self._session.get(
                self.base + path,
                headers={"User-Agent": "OpenCTI-RansomwareLive-Enrichment"},
                timeout=_REQUEST_TIMEOUT,
            )
            r.raise_for_status()
            return r.text
        except Exception as e:  # noqa: BLE001
            self.logger.error("vuln-matrix fetch failed", {"path": path, "error": str(e)})
            return None

    @staticmethod
    def _row_cells(line: str) -> list[str]:
        cells = [c.strip() for c in line.split("|")]
        if cells and cells[0] == "":
            cells = cells[1:]
        if cells and cells[-1] == "":
            cells = cells[:-1]
        return cells

    def _build_map(self) -> dict[str, set]:
        if self._map is not None:
            return self._map
        mapping: dict[str, set] = {}
        readme = self._get("README.md")
        cats = sorted(set(_CAT_RE.findall(readme))) if readme else []
        for cat in cats:
            text = self._get(cat)
            if not text:
                continue
            for line in text.splitlines():
                if "CVE-" not in line.upper() or "|" not in line:
                    continue
                cells = self._row_cells(line)
                cve_idx = next(
                    (i for i, c in enumerate(cells) if _CVE_RE.search(c)), None)
                if cve_idx is None or cve_idx + 1 >= len(cells):
                    continue
                cves = {m.group(0).upper() for m in _CVE_RE.finditer(cells[cve_idx])}
                if not cves:
                    continue
                # the cell right after the CVE column holds the group list
                for grp in cells[cve_idx + 1].split(","):
                    key = _norm(grp)
                    if key:
                        mapping.setdefault(key, set()).update(cves)
        self._map = mapping
        self.logger.info(
            "Loaded vuln-matrix", {"categories": len(cats), "groups_mapped": len(mapping)}
        )
        return mapping

    def get_cves(self, group_name: str) -> list[str]:
        """Sorted CVE ids weaponised by the group, or [] if none/unknown."""
        return sorted(self._build_map().get(_norm(group_name), set()))
