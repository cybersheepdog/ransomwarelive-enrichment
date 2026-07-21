"""Map ransomware.live PRO group data into STIX 2.1 objects for OpenCTI.

Everything is attached to the *same* Intrusion Set the official ``ransomwarelive``
connector creates. That connector builds the intrusion set with
``pycti.IntrusionSet.generate_id(name)`` (collapsing ``lockbit3``/``lockbit2`` to
``lockbit``). We reproduce that ID exactly, so our tools / TTPs / CVEs / YARA /
IOC relationships land on the existing entity instead of creating a duplicate.
"""

from __future__ import annotations

import re
from typing import Optional

import stix2
from pycti import (
    AttackPattern,
    Identity,
    Indicator,
    IntrusionSet,
    StixCoreRelationship,
    Tool,
    Vulnerability,
)

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Regexes to infer an observable type from a bare IOC value when the API record
# doesn't declare one.
_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$")


def canonical_group_name(name: str) -> str:
    """Match the stock connector's intrusion-set naming."""
    if name in ("lockbit3", "lockbit2"):
        return "lockbit"
    return name


class RansomwareStixConverter:
    def __init__(self, author: stix2.Identity, tlp_marking, logger):
        self.author = author
        self.tlp = tlp_marking
        self.logger = logger

    # -- shared builders -----------------------------------------------------

    @staticmethod
    def build_author() -> stix2.Identity:
        return stix2.Identity(
            id=Identity.generate_id("Ransomware.live", "organization"),
            name="Ransomware.live",
            identity_class="organization",
            description="Enrichment from the ransomware.live PRO API "
            "(tools, TTPs, CVEs, YARA, IOCs).",
        )

    def intrusion_set_ref(self, group_name: str) -> str:
        """Deterministic STIX id of the intrusion set for this group."""
        return IntrusionSet.generate_id(canonical_group_name(group_name))

    def intrusion_set_stub(self, group_name: str) -> stix2.IntrusionSet:
        """Minimal IntrusionSet so relationships resolve even if the stock
        connector hasn't emitted this group yet. Carries only the name, so an
        OpenCTI upsert cannot clobber a richer existing description."""
        name = canonical_group_name(group_name)
        return stix2.IntrusionSet(
            id=self.intrusion_set_ref(group_name),
            name=name,
            created_by_ref=self.author.id,
            object_marking_refs=[self.tlp.id],
            allow_custom=True,
        )

    def _rel(self, source_ref: str, rel_type: str, target_ref: str) -> stix2.Relationship:
        return stix2.Relationship(
            id=StixCoreRelationship.generate_id(rel_type, source_ref, target_ref),
            relationship_type=rel_type,
            source_ref=source_ref,
            target_ref=target_ref,
            created_by_ref=self.author.id,
            object_marking_refs=[self.tlp.id],
            allow_custom=True,
        )

    # -- tools ---------------------------------------------------------------

    def convert_tools(self, is_ref: str, tools_field) -> list:
        """`tools` is an array whose single element is a dict of
        {category: [tool names]}. Emit a Tool per name + `uses` relationship."""
        objects: list = []
        seen: set[str] = set()
        for block in tools_field or []:
            if not isinstance(block, dict):
                continue
            for category, names in block.items():
                if not isinstance(names, list):
                    continue
                for raw in names:
                    name = str(raw).strip()
                    if not name or name.lower() in seen:
                        continue
                    seen.add(name.lower())
                    tool = stix2.Tool(
                        id=Tool.generate_id(name),
                        name=name,
                        labels=[str(category)] if category else None,
                        created_by_ref=self.author.id,
                        object_marking_refs=[self.tlp.id],
                        allow_custom=True,
                    )
                    objects.append(tool)
                    objects.append(self._rel(is_ref, "uses", tool.id))
        return objects

    # -- TTPs ----------------------------------------------------------------

    def convert_ttps(
        self,
        is_ref: str,
        ttps_field,
        resolve_attack_pattern,
        create_missing: bool,
    ) -> list:
        """`ttps` is an array of tactic dicts, each with `techniques` carrying
        `technique_id`. Prefer resolving the AttackPattern already imported by
        the MITRE connector (lookup by x_mitre_id); optionally create a stub if
        missing so the matrix is never silently dropped."""
        objects: list = []
        seen: set[str] = set()
        for tactic in ttps_field or []:
            if not isinstance(tactic, dict):
                continue
            for tech in tactic.get("techniques") or []:
                if not isinstance(tech, dict):
                    continue
                tech_id = (tech.get("technique_id") or "").strip()
                if not tech_id or tech_id in seen:
                    continue
                seen.add(tech_id)
                ap_ref = resolve_attack_pattern(tech_id)
                if ap_ref is None and create_missing:
                    ap = self._build_attack_pattern(tech_id, tech.get("technique_name"))
                    objects.append(ap)
                    ap_ref = ap.id
                if ap_ref:
                    objects.append(self._rel(is_ref, "uses", ap_ref))
                else:
                    self.logger.debug(
                        "ATT&CK technique not found in OpenCTI; skipped",
                        {"technique_id": tech_id},
                    )
        return objects

    def _build_attack_pattern(self, tech_id: str, tech_name: Optional[str]) -> stix2.AttackPattern:
        name = tech_name or tech_id
        ext = stix2.ExternalReference(
            source_name="mitre-attack",
            external_id=tech_id,
            url=f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/",
        )
        return stix2.AttackPattern(
            id=AttackPattern.generate_id(name, tech_id),
            name=name,
            external_references=[ext],
            created_by_ref=self.author.id,
            object_marking_refs=[self.tlp.id],
            custom_properties={"x_mitre_id": tech_id},
            allow_custom=True,
        )

    # -- CVEs ----------------------------------------------------------------

    def convert_cves(self, is_ref: str, group_detail: dict) -> list:
        """CVEs aren't a dedicated field; scan explicit fields plus the whole
        detail blob for CVE-XXXX-NNNN tokens. Emit Vulnerability + `targets`."""
        objects: list = []
        found: set[str] = set()

        # explicit fields first
        for key in ("cve", "cves", "vulnerabilities", "vulnerability"):
            val = group_detail.get(key)
            if isinstance(val, str):
                found.update(m.group(0).upper() for m in CVE_RE.finditer(val))
            elif isinstance(val, list):
                for item in val:
                    found.update(m.group(0).upper() for m in CVE_RE.finditer(str(item)))

        # fallback: scan description + ttps details for CVE mentions
        blob_parts = [str(group_detail.get("description") or "")]
        for tactic in group_detail.get("ttps") or []:
            if isinstance(tactic, dict):
                for tech in tactic.get("techniques") or []:
                    if isinstance(tech, dict):
                        blob_parts.append(str(tech.get("technique_details") or ""))
        found.update(m.group(0).upper() for m in CVE_RE.finditer(" ".join(blob_parts)))

        for cve in sorted(found):
            vuln = stix2.Vulnerability(
                id=Vulnerability.generate_id(cve),
                name=cve,
                created_by_ref=self.author.id,
                object_marking_refs=[self.tlp.id],
                allow_custom=True,
            )
            objects.append(vuln)
            objects.append(self._rel(is_ref, "targets", vuln.id))
        return objects

    # -- YARA ----------------------------------------------------------------

    def convert_yara(self, is_ref: str, group_name: str, yara_text: str) -> list:
        if not yara_text or not yara_text.strip():
            return []
        rule_name = self._first_yara_rule_name(yara_text) or f"{group_name}.yar"
        indicator = stix2.Indicator(
            id=Indicator.generate_id(yara_text),
            name=rule_name,
            description=f"YARA rule for ransomware group '{group_name}' (ransomware.live).",
            pattern_type="yara",
            pattern=yara_text,
            valid_from=self.author.created,
            created_by_ref=self.author.id,
            object_marking_refs=[self.tlp.id],
            custom_properties={"x_opencti_main_observable_type": "StixFile"},
            allow_custom=True,
        )
        return [indicator, self._rel(indicator.id, "indicates", is_ref)]

    @staticmethod
    def _first_yara_rule_name(text: str) -> Optional[str]:
        m = re.search(r"\brule\s+([A-Za-z0-9_]+)", text)
        return m.group(1) if m else None

    # -- IOCs ----------------------------------------------------------------

    def convert_iocs(self, is_ref: str, group_name: str, iocs: list) -> list:
        objects: list = []
        skipped: list[str] = []
        for item in iocs or []:
            value, ioc_type = self._extract_ioc(item)
            if not value:
                continue
            pattern, main_type = self._stix_pattern(value, ioc_type)
            if pattern is None:
                skipped.append(value)
                continue
            indicator = stix2.Indicator(
                id=Indicator.generate_id(pattern),
                name=value,
                pattern_type="stix",
                pattern=pattern,
                valid_from=self.author.created,
                created_by_ref=self.author.id,
                object_marking_refs=[self.tlp.id],
                labels=["ransomware", group_name],
                custom_properties={
                    "x_opencti_main_observable_type": main_type,
                    # Let OpenCTI auto-create the observable + based-on relationship.
                    "x_opencti_create_observables": True,
                },
                allow_custom=True,
            )
            objects.append(indicator)
            objects.append(self._rel(indicator.id, "indicates", is_ref))
        if skipped:
            self.logger.info(
                "IOCs skipped (no STIX observable mapping, e.g. tox/session ids)",
                {"group": group_name, "count": len(skipped)},
            )
        return objects

    @staticmethod
    def _extract_ioc(item) -> tuple[Optional[str], Optional[str]]:
        if isinstance(item, str):
            return item.strip(), None
        if not isinstance(item, dict):
            return None, None
        value = None
        for key in ("value", "ioc", "indicator", "hash", "sha256", "sha1", "md5",
                    "domain", "ip", "url", "email", "address"):
            if item.get(key):
                value = str(item[key]).strip()
                break
        ioc_type = None
        for key in ("type", "ioc_type", "category", "kind"):
            if item.get(key):
                ioc_type = str(item[key]).strip().lower()
                break
        return value, ioc_type

    @staticmethod
    def _stix_pattern(value: str, ioc_type: Optional[str]) -> tuple[Optional[str], Optional[str]]:
        """Return (stix_pattern, x_opencti_main_observable_type) or (None, None)."""
        t = (ioc_type or "").lower()

        # hashes (by declared type or by shape)
        if "sha256" in t or _SHA256_RE.match(value):
            return f"[file:hashes.'SHA-256' = '{value.lower()}']", "StixFile"
        if "sha1" in t or _SHA1_RE.match(value):
            return f"[file:hashes.'SHA-1' = '{value.lower()}']", "StixFile"
        if "md5" in t or _MD5_RE.match(value):
            return f"[file:hashes.'MD5' = '{value.lower()}']", "StixFile"
        if "url" in t or _URL_RE.match(value):
            return f"[url:value = '{value}']", "Url"
        if "email" in t or _EMAIL_RE.match(value):
            return f"[email-addr:value = '{value}']", "Email-Addr"
        if t in ("ip", "ipv4", "ip-src", "ip-dst") or _IPV4_RE.match(value):
            return f"[ipv4-addr:value = '{value}']", "IPv4-Addr"
        if "domain" in t or "host" in t or _DOMAIN_RE.match(value):
            return f"[domain-name:value = '{value}']", "Domain-Name"
        return None, None
