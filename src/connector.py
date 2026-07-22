"""RansomwareLive PRO enrichment connector for OpenCTI.

External-import connector. On each scheduled tick it walks every ransomware
group known to ransomware.live PRO and, for each, emits the tools / TTPs / CVEs
/ YARA / IOCs that the official ``ransomwarelive`` connector does not ingest --
all linked to the same Intrusion Set entity.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone

import stix2
from pycti import OpenCTIConnectorHelper

from api_client import RansomwareLiveAPIError, RansomwareLiveClient
from config_loader import ConnectorConfig
from converter import RansomwareStixConverter

_TLP = {
    "TLP:CLEAR": stix2.TLP_WHITE,
    "TLP:WHITE": stix2.TLP_WHITE,
    "TLP:GREEN": stix2.TLP_GREEN,
    "TLP:AMBER": stix2.TLP_AMBER,
    "TLP:RED": stix2.TLP_RED,
}


class RansomwareLiveEnrichmentConnector:
    def __init__(self):
        self.config = ConnectorConfig()
        self.helper = OpenCTIConnectorHelper(self.config.raw)
        self.logger = self.helper.connector_logger

        self.client = RansomwareLiveClient(
            api_key=self.config.api_key,
            base_url=self.config.base_url,
            logger=self.logger,
        )

        author = RansomwareStixConverter.build_author()
        tlp = _TLP.get(self.config.tlp_marking, stix2.TLP_WHITE)
        self.author = author
        self.tlp = tlp
        self.converter = RansomwareStixConverter(author, tlp, self.logger)

        # small in-memory cache so repeated technique ids don't hammer the API layer
        self._ap_cache: dict[str, str | None] = {}

    # -- ATT&CK resolution ---------------------------------------------------

    def _resolve_attack_pattern(self, technique_id: str) -> str | None:
        """Return the standard_id of an AttackPattern already in OpenCTI,
        matched by its MITRE id (x_mitre_id), or None."""
        if technique_id in self._ap_cache:
            return self._ap_cache[technique_id]
        result = None
        try:
            found = self.helper.api.attack_pattern.read(
                filters={
                    "mode": "and",
                    "filters": [
                        {"key": "x_mitre_id", "values": [technique_id], "operator": "eq"}
                    ],
                    "filterGroups": [],
                }
            )
            if found and found.get("standard_id"):
                result = found["standard_id"]
        except Exception as err:  # noqa: BLE001 - never let one lookup kill the run
            self.logger.error(
                "AttackPattern lookup failed", {"technique_id": technique_id, "error": str(err)}
            )
        self._ap_cache[technique_id] = result
        return result

    # -- per-group enrichment ------------------------------------------------

    def _enrich_group(self, group_name: str) -> list:
        is_ref = self.converter.intrusion_set_ref(group_name)
        objects: list = [self.author, self.tlp, self.converter.intrusion_set_stub(group_name)]

        detail = self.client.get_group(group_name)
        if detail:
            if self.config.enable_tools:
                objects += self.converter.convert_tools(is_ref, detail.get("tools"))
            if self.config.enable_ttps:
                objects += self.converter.convert_ttps(
                    is_ref,
                    detail.get("ttps"),
                    self._resolve_attack_pattern,
                    self.config.create_missing_ttp,
                )
            if self.config.enable_cves:
                objects += self.converter.convert_cves(is_ref, detail)

        if self.config.enable_yara:
            try:
                yara = self.client.get_group_yara(group_name)
                if yara:
                    objects += self.converter.convert_yara(is_ref, group_name, yara)
            except RansomwareLiveAPIError:
                pass  # already logged in the client

        if self.config.enable_iocs:
            try:
                iocs = self.client.get_group_iocs(group_name)
                if iocs:
                    objects += self.converter.convert_iocs(is_ref, group_name, iocs)
            except RansomwareLiveAPIError:
                pass

        return objects

    def _send(self, objects: list, work_id: str) -> int:
        # de-duplicate by id within this bundle
        unique = list({o.id: o for o in objects}.values())
        if len(unique) <= 2:  # just author + marking, nothing useful
            return 0
        bundle = stix2.Bundle(objects=unique, allow_custom=True).serialize()
        self.helper.send_stix2_bundle(bundle, work_id=work_id, cleanup_inconsistent_bundle=True)
        return len(unique)

    # -- main run ------------------------------------------------------------

    def process(self):
        now = datetime.now(timezone.utc)
        friendly = f"Ransomware.live PRO enrichment @ {now.isoformat()}"
        self.logger.info("Starting enrichment run", {"time": friendly})
        work_id = self.helper.api.work.initiate_work(self.helper.connect_id, friendly)

        try:
            groups = self.client.list_groups()
        except RansomwareLiveAPIError as err:
            self.logger.error("Could not list groups; aborting run", {"error": str(err)})
            self.helper.api.work.to_processed(work_id, "Failed: could not list groups", in_error=True)
            return

        names = [
            str(g.get("name")).strip()
            for g in groups
            if isinstance(g, dict) and g.get("name")
        ]
        fetched = len(names)
        if self.config.only_groups:
            wanted = {n.lower() for n in self.config.only_groups}
            names = [n for n in names if n.lower() in wanted]
            if not names:
                self.logger.warning(
                    "ONLY_GROUPS filter matched no groups; nothing to enrich",
                    {
                        "fetched_from_api": fetched,
                        "only_groups": sorted(wanted),
                        "sample_available": sorted(
                            g.get("name") for g in groups[:10] if isinstance(g, dict) and g.get("name")
                        ),
                    },
                )

        self.logger.info(
            "Groups to enrich",
            {"count": len(names), "fetched_from_api": fetched,
             "filter_active": bool(self.config.only_groups)},
        )
        total_sent = 0
        for name in names:
            try:
                objects = self._enrich_group(name)
                sent = self._send(objects, work_id)
                total_sent += sent
                self.logger.info("Enriched group", {"group": name, "objects": sent})
            except RansomwareLiveAPIError as err:
                self.logger.error("Skipping group (API error)", {"group": name, "error": str(err)})
            except Exception as err:  # noqa: BLE001
                self.logger.error("Skipping group (unexpected)", {"group": name, "error": str(err)})

        msg = f"Enrichment finished: {len(names)} groups, {total_sent} objects sent"
        self.logger.info(msg)
        self.helper.api.work.to_processed(work_id, msg)

    def run(self):
        self.logger.info("Ransomware.live PRO enrichment connector starting")
        self.helper.schedule_iso(
            message_callback=self.process,
            duration_period=self.config.duration_period,
        )


if __name__ == "__main__":
    try:
        RansomwareLiveEnrichmentConnector().run()
    except Exception:
        import traceback

        traceback.print_exc()
        sys.exit(1)
