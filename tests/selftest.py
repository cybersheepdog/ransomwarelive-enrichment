"""Offline self-test: feed the converter the real thegentlemen data shapes and
assert the STIX objects / relationships / IDs come out right. No network, no
OpenCTI needed."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import stix2
from pycti import IntrusionSet, Tool, Vulnerability
from converter import RansomwareStixConverter, canonical_group_name


class _Log:
    def debug(self, *a, **k): pass
    def info(self, *a, **k): pass
    def error(self, *a, **k): print("ERROR", a, k)


author = RansomwareStixConverter.build_author()
tlp = stix2.TLP_WHITE
conv = RansomwareStixConverter(author, tlp, _Log())

GROUP = "thegentlemen"
is_ref = conv.intrusion_set_ref(GROUP)

# 1. Intrusion-set ID must match what the stock connector produces.
assert is_ref == IntrusionSet.generate_id("thegentlemen"), "IS id mismatch"
assert conv.intrusion_set_ref("lockbit3") == IntrusionSet.generate_id("lockbit"), "lockbit collapse failed"
assert canonical_group_name("lockbit2") == "lockbit"
print("OK  intrusion-set id parity:", is_ref)

# 2. Tools (real shape from /v2/group/thegentlemen)
tools_field = [{
    "CredentialTheft": ["Hydra", "KslDump"],
    "Exfiltration": ["rclone"],
    "RMM-Tools": ["AnyDesk"],
}]
tool_objs = conv.convert_tools(is_ref, tools_field)
tools = [o for o in tool_objs if o.type == "tool"]
rels = [o for o in tool_objs if o.type == "relationship"]
assert len(tools) == 4, f"expected 4 tools, got {len(tools)}"
assert all(r.relationship_type == "uses" and r.source_ref == is_ref for r in rels)
assert {t.name for t in tools} == {"Hydra", "KslDump", "rclone", "AnyDesk"}
# Tool id parity with pycti
assert any(t.id == Tool.generate_id("AnyDesk") for t in tools)
print("OK  tools ->", len(tools), "Tool +", len(rels), "uses rels")

# 3. TTPs (real shape) with a fake resolver: T1078 resolves, T1078.002 doesn't
def resolver(tid):
    return "attack-pattern--11111111-1111-4111-8111-111111111111" if tid == "T1078" else None

ttps_field = [{
    "tactic_id": "TA0001", "tactic_name": "Initial Access",
    "techniques": [
        {"technique_id": "T1078", "technique_name": "Valid Accounts"},
        {"technique_id": "T1078.002", "technique_name": "Valid Accounts: Domain Accounts"},
    ],
}]
# resolve-only mode: only the resolved technique yields a uses rel
ttp_objs = conv.convert_ttps(is_ref, ttps_field, resolver, create_missing=False)
uses = [o for o in ttp_objs if getattr(o, "relationship_type", None) == "uses"]
assert len(uses) == 1, f"resolve-only should give 1 uses, got {len(uses)}"
assert uses[0].target_ref == "attack-pattern--11111111-1111-4111-8111-111111111111"
# create-missing mode: the unresolved technique now becomes a stub AttackPattern
ttp_objs2 = conv.convert_ttps(is_ref, ttps_field, resolver, create_missing=True)
aps = [o for o in ttp_objs2 if o.type == "attack-pattern"]
uses2 = [o for o in ttp_objs2 if getattr(o, "relationship_type", None) == "uses"]
assert len(aps) == 1 and aps[0].x_mitre_id == "T1078.002"
assert len(uses2) == 2
print("OK  ttps -> resolve-only:1 uses ; create-missing:1 stub +2 uses")

# 4. CVEs scanned from detail fields + free text
detail = {
    "description": "Exploits Fortinet CVE-2024-21762 and cve-2023-27997 for access.",
    "cves": ["CVE-2024-55591"],
    "ttps": ttps_field,
}
cve_objs = conv.convert_cves(is_ref, detail)
vulns = [o for o in cve_objs if o.type == "vulnerability"]
names = sorted(v.name for v in vulns)
assert names == ["CVE-2023-27997", "CVE-2024-21762", "CVE-2024-55591"], names
assert any(v.id == Vulnerability.generate_id("CVE-2024-21762") for v in vulns)
assert all(
    r.relationship_type == "targets" and r.source_ref == is_ref
    for r in cve_objs if r.type == "relationship"
)
print("OK  cves ->", names)

# 5. YARA
yara = 'rule TheGentlemen {\n  strings: $a = "x"\n  condition: $a\n}'
yara_objs = conv.convert_yara(is_ref, GROUP, yara)
ind = [o for o in yara_objs if o.type == "indicator"][0]
assert ind.pattern_type == "yara" and ind.pattern == yara and ind.name == "TheGentlemen"
rel = [o for o in yara_objs if o.type == "relationship"][0]
assert rel.relationship_type == "indicates" and rel.source_ref == ind.id and rel.target_ref == is_ref
print("OK  yara -> indicator (pattern_type=yara) indicates intrusion-set")

# 6. IOCs of mixed shapes (dict with type, bare hash string, tox id skipped)
iocs = [
    {"type": "sha1", "value": "aabbccddeeff00112233445566778899aabbccdd"},
    "8.8.8.8",
    {"type": "domain", "value": "evil-leak.example"},
    {"type": "tox", "value": "ABCDEF0123456789"},  # unmappable -> skipped
    {"type": "url", "value": "http://evil.example/x"},
]
ioc_objs = conv.convert_iocs(is_ref, GROUP, iocs)
inds = [o for o in ioc_objs if o.type == "indicator"]
patterns = sorted(i.pattern for i in inds)
assert len(inds) == 4, f"expected 4 indicators (tox skipped), got {len(inds)}"
assert any("SHA-1" in p for p in patterns)
assert any("ipv4-addr" in p for p in patterns)
assert any("domain-name" in p for p in patterns)
assert any("url:value" in p for p in patterns)
assert all(
    r.relationship_type == "indicates" and r.target_ref == is_ref
    for r in ioc_objs if r.type == "relationship"
)
print("OK  iocs -> 4 indicators (tox skipped) all indicate intrusion-set")

# 7. Everything serializes into one valid STIX bundle
allobj = [author, tlp, conv.intrusion_set_stub(GROUP)]
allobj += tool_objs + ttp_objs2 + cve_objs + yara_objs + ioc_objs
unique = list({o.id: o for o in allobj}.values())
bundle = stix2.Bundle(objects=unique, allow_custom=True).serialize()
assert '"type": "bundle"' in bundle
print(f"OK  bundle serialized: {len(unique)} unique objects")
print("\nALL SELFTESTS PASSED")
