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
from matrix_client import VulnMatrixClient

_TLP = {
    "TLP:CLEAR": stix2.TLP_WHITE,
    "TLP:WHITE": stix2.TLP_WHITE,
    "TLP:GREEN": stix2.TLP_GREEN,
    "TLP:AMBER": stix2.TLP_AMBER,
    "TLP:RED": stix2.TLP_RED,
}


def prioritize_groups(names, progress, cap=0):
    """Order a run's groups so coverage is fair and resumable.

    ``progress`` maps group name -> ISO timestamp of last successful processing.
    Groups with no timestamp (never done, or failed/skipped last run) go first,
    then the least-recently-succeeded (ISO strings sort chronologically). With a
    positive ``cap`` the run takes the first ``cap`` groups and returns the rest
    as ``deferred`` for the next run — so a blocked/rate-limited run advances
    through the list instead of always restarting from the top.

    Returns ``(ordered, deferred)``.
    """
    def _key(pair):
        idx, name = pair
        ts = progress.get(name)
        # (0, "", idx) -> never succeeded, keep input order at the front
        # (1, ts, idx) -> succeeded before, oldest first
        return (0, "", idx) if not ts else (1, ts, idx)

    ordered = [n for _, n in sorted(enumerate(names), key=_key)]
    if cap and cap > 0 and len(ordered) > cap:
        return ordered[:cap], ordered[cap:]
    return ordered, []


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
        self.matrix_client = (
            VulnMatrixClient(self.logger) if self.config.enable_cve_matrix else None
        )

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
        counts = {"tools": 0, "ttp_links": 0, "cves": 0, "yara": 0, "iocs": 0,
                  "channels": 0, "locations": 0, "ransomnotes": 0, "detail_keys": None}

        detail = self.client.get_group(group_name)
        if detail:
            counts["detail_keys"] = sorted(detail.keys())
            if self.config.enable_tools:
                t = self.converter.convert_tools(is_ref, detail.get("tools"))
                counts["tools"] = sum(1 for o in t if o.type == "tool")
                objects += t
            if self.config.enable_ttps:
                p = self.converter.convert_ttps(
                    is_ref, detail.get("ttps"),
                    self._resolve_attack_pattern, self.config.create_missing_ttp,
                )
                counts["ttp_links"] = sum(
                    1 for o in p if getattr(o, "relationship_type", None) == "uses")
                objects += p
            if self.config.enable_cves:
                c = self.converter.convert_cves(is_ref, detail)
                counts["cves"] = sum(1 for o in c if o.type == "vulnerability")
                objects += c
            if self.config.enable_locations:
                loc = self.converter.convert_locations(is_ref, detail.get("locations"))
                counts["locations"] = sum(1 for o in loc if o.type == "domain-name")
                objects += loc

        # CVEs from the external Ransomware-Vulnerability-Matrix (PRO API has none).
        if self.matrix_client is not None:
            try:
                mcves = self.matrix_client.get_cves(group_name)
                if mcves:
                    mc = self.converter.convert_cve_ids(is_ref, mcves)
                    counts["cves"] += sum(1 for o in mc if o.type == "vulnerability")
                    objects += mc
            except Exception as e:  # noqa: BLE001
                self.logger.error(
                    "vuln-matrix enrichment failed", {"group": group_name, "error": str(e)})

        if self.config.enable_ransomnotes:
            try:
                rnotes = self.client.get_group_ransomnotes(group_name)
                if rnotes:
                    rn = self.converter.convert_ransomnotes(is_ref, group_name, rnotes)
                    counts["ransomnotes"] = sum(1 for o in rn if o.type == "file")
                    objects += rn
            except RansomwareLiveAPIError:
                pass

        if self.config.enable_yara:
            try:
                yara = self.client.get_group_yara(group_name)
                if yara:
                    y = self.converter.convert_yara(is_ref, group_name, yara)
                    counts["yara"] = sum(1 for o in y if o.type == "indicator")
                    objects += y
            except RansomwareLiveAPIError:
                pass  # already logged in the client

        if self.config.enable_iocs:
            try:
                iocs = self.client.get_group_iocs(group_name)
                if iocs:
                    ic = self.converter.convert_iocs(is_ref, group_name, iocs)
                    counts["iocs"] = sum(1 for o in ic if o.type == "indicator")
                    counts["channels"] = sum(1 for o in ic if o.type == "channel")
                    objects += ic
            except RansomwareLiveAPIError:
                pass

        self.logger.info("Enrichment breakdown", {"group": group_name, **counts})
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

        # Resumable rotation: remember when each group was last successfully
        # processed (persisted in the connector's OpenCTI state). Groups never
        # done yet — or failed/skipped last run (no success timestamp) — go
        # first, then the least-recently-succeeded. With MAX_GROUPS_PER_RUN the
        # rest defer to the next run, so a blocked run advances through the list.
        state = self.helper.get_state() or {}
        progress = dict(state.get("group_last_success") or {})
        ordered, deferred = prioritize_groups(
            names, progress, cap=self.config.max_groups_per_run
        )

        self.logger.info(
            "Groups to enrich",
            {
                "selected": len(ordered),
                "deferred_to_next_run": len(deferred),
                "total_after_filter": len(names),
                "fetched_from_api": fetched,
                "filter_active": bool(self.config.only_groups),
                "max_groups_per_run": self.config.max_groups_per_run or None,
                "never_processed": sum(1 for n in ordered if n not in progress),
            },
        )
        total_sent = 0
        processed = 0
        for name in ordered:
            try:
                objects = self._enrich_group(name)
                sent = self._send(objects, work_id)
                total_sent += sent
                processed += 1
                # Record success only on a clean fetch, so a failed/skipped group
                # keeps its old (or missing) timestamp and is retried first next
                # run. Persist immediately so progress survives a mid-run block.
                progress[name] = datetime.now(timezone.utc).isoformat()
                state["group_last_success"] = progress
                self.helper.set_state(state)
                self.logger.info("Enriched group", {"group": name, "objects": sent})
            except RansomwareLiveAPIError as err:
                self.logger.error("Skipping group (API error)", {"group": name, "error": str(err)})
            except Exception as err:  # noqa: BLE001
                self.logger.error("Skipping group (unexpected)", {"group": name, "error": str(err)})

        msg = (
            f"Enrichment finished: {processed}/{len(ordered)} groups processed, "
            f"{total_sent} objects sent, {len(deferred)} deferred to next run"
        )
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
