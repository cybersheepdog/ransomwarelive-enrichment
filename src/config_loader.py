"""Configuration loader (classic OpenCTI connector style).

Reads from environment variables, falling back to an optional config.yml in the
working directory. Uses pycti.get_config_variable so it behaves like every other
OpenCTI connector.
"""

from __future__ import annotations

import os

import yaml
from pycti import get_config_variable


def _bool_list(raw) -> list[str]:
    if not raw:
        return []
    if isinstance(raw, list):
        return [str(x).strip() for x in raw if str(x).strip()]
    return [x.strip() for x in str(raw).split(",") if x.strip()]


class ConnectorConfig:
    def __init__(self):
        config_file = os.path.join(os.path.dirname(__file__), "config.yml")
        file_config = {}
        if os.path.isfile(config_file):
            with open(config_file, "r", encoding="utf-8") as fh:
                file_config = yaml.safe_load(fh) or {}
        self._file = file_config

        # ---- OpenCTI core ----
        self.opencti_url = get_config_variable("OPENCTI_URL", ["opencti", "url"], file_config)
        self.opencti_token = get_config_variable(
            "OPENCTI_TOKEN", ["opencti", "token"], file_config
        )

        # ---- connector core ----
        self.connector_id = get_config_variable("CONNECTOR_ID", ["connector", "id"], file_config)
        self.connector_name = (
            get_config_variable("CONNECTOR_NAME", ["connector", "name"], file_config)
            or "Ransomware.live PRO Enrichment"
        )
        self.connector_scope = (
            get_config_variable("CONNECTOR_SCOPE", ["connector", "scope"], file_config)
            or "intrusion-set,tool,attack-pattern,vulnerability,indicator"
        )
        self.log_level = (
            get_config_variable("CONNECTOR_LOG_LEVEL", ["connector", "log_level"], file_config)
            or "info"
        )
        self.duration_period = (
            get_config_variable(
                "CONNECTOR_DURATION_PERIOD", ["connector", "duration_period"], file_config
            )
            or "P1D"
        )

        # ---- ransomware.live PRO ----
        self.api_key = get_config_variable(
            "RANSOMWARELIVE_API_KEY", ["ransomwarelive", "api_key"], file_config
        )
        self.base_url = (
            get_config_variable(
                "RANSOMWARELIVE_BASE_URL", ["ransomwarelive", "base_url"], file_config
            )
            or "https://api-pro.ransomware.live"
        )
        self.tlp_marking = (
            get_config_variable(
                "RANSOMWARELIVE_TLP", ["ransomwarelive", "tlp"], file_config
            )
            or "TLP:CLEAR"
        )

        # feature toggles (all default true)
        self.enable_tools = self._flag("RANSOMWARELIVE_ENABLE_TOOLS", "enable_tools", True)
        self.enable_ttps = self._flag("RANSOMWARELIVE_ENABLE_TTPS", "enable_ttps", True)
        self.enable_cves = self._flag("RANSOMWARELIVE_ENABLE_CVES", "enable_cves", True)
        self.enable_yara = self._flag("RANSOMWARELIVE_ENABLE_YARA", "enable_yara", True)
        self.enable_iocs = self._flag("RANSOMWARELIVE_ENABLE_IOCS", "enable_iocs", True)
        self.enable_locations = self._flag(
            "RANSOMWARELIVE_ENABLE_LOCATIONS", "enable_locations", True)
        self.enable_ransomnotes = self._flag(
            "RANSOMWARELIVE_ENABLE_RANSOMNOTES", "enable_ransomnotes", True)
        # Pull CVEs from the public Ransomware-Vulnerability-Matrix repo, since
        # the PRO API does not expose them. Set false to disable the extra source.
        self.enable_cve_matrix = self._flag(
            "RANSOMWARELIVE_ENABLE_CVE_MATRIX", "enable_cve_matrix", True)
        # When a technique isn't already imported by the MITRE ATT&CK connector,
        # create a stub AttackPattern (with its tactic) so the ATT&CK matrix is
        # populated instead of silently empty. Set false to only link techniques
        # that already exist in OpenCTI.
        self.create_missing_ttp = self._flag(
            "RANSOMWARELIVE_CREATE_MISSING_TTP", "create_missing_ttp", True
        )
        # Cap groups processed per run so a rate-limited/blocked run covers a
        # slice and the rest roll to the next run (0 = no cap, process all).
        # Combined with the resumable rotation in connector.py, this guarantees
        # every group is reached over time instead of always restarting from the
        # top of the list.
        self.max_groups_per_run = self._int(
            "RANSOMWARELIVE_MAX_GROUPS_PER_RUN", "max_groups_per_run", 0
        )
        # optional allow-list to enrich only some groups (comma separated)
        self.only_groups = _bool_list(
            get_config_variable(
                "RANSOMWARELIVE_ONLY_GROUPS", ["ransomwarelive", "only_groups"], file_config
            )
        )

        self._validate()

    def _flag(self, env: str, yaml_key: str, default: bool) -> bool:
        val = get_config_variable(env, ["ransomwarelive", yaml_key], self._file, default=default)
        if isinstance(val, bool):
            return val
        return str(val).strip().lower() in ("true", "1", "yes", "on")

    def _int(self, env: str, yaml_key: str, default: int) -> int:
        val = get_config_variable(env, ["ransomwarelive", yaml_key], self._file, default=default)
        try:
            return max(0, int(val))
        except (TypeError, ValueError):
            return default

    def _validate(self):
        missing = [
            n
            for n, v in (
                ("OPENCTI_URL", self.opencti_url),
                ("OPENCTI_TOKEN", self.opencti_token),
                ("CONNECTOR_ID", self.connector_id),
                ("RANSOMWARELIVE_API_KEY", self.api_key),
            )
            if not v
        ]
        if missing:
            raise ValueError(f"Missing required configuration: {', '.join(missing)}")

    @property
    def raw(self) -> dict:
        """Config dict passed to OpenCTIConnectorHelper."""
        return {
            "opencti": {"url": self.opencti_url, "token": self.opencti_token},
            "connector": {
                "id": self.connector_id,
                "type": "EXTERNAL_IMPORT",
                "name": self.connector_name,
                "scope": self.connector_scope,
                "log_level": self.log_level,
                "duration_period": self.duration_period,
            },
        }
