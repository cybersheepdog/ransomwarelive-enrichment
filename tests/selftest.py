"""Offline self-test: feed the converter the real thegentlemen data shapes and
assert the STIX objects / relationships / IDs come out right. No network, no
OpenCTI needed."""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
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

# 5b. TTP stub carries a kill_chain_phase (tactic) so it lands on the ATT&CK matrix
ap_stub = [o for o in ttp_objs2 if o.type == "attack-pattern"][0]
kcp = ap_stub.get("kill_chain_phases")
assert kcp and kcp[0]["kill_chain_name"] == "mitre-attack", "missing kill_chain_phase"
assert kcp[0]["phase_name"] == "initial-access", kcp[0]["phase_name"]
print("OK  ttp stub -> kill_chain_phase(mitre-attack, initial-access) for matrix")

# 5c. Ransom note Artifact must carry hashes (OpenCTI rejects it otherwise)
notes = [{"filename": "readme.txt", "content": "pay us or else"}]
rn_objs = conv.convert_ransomnotes(is_ref, GROUP, notes)
art = [o for o in rn_objs if o.type == "artifact"][0]
fil = [o for o in rn_objs if o.type == "file"][0]
assert art.get("hashes"), "artifact has no hashes"
assert set(art["hashes"]) == {"MD5", "SHA-1", "SHA-256"}, art["hashes"].keys()
import hashlib as _h
assert art["hashes"]["SHA-256"] == _h.sha256(b"pay us or else").hexdigest()
assert fil.content_ref == art.id and fil.name == "readme.txt"
print("OK  ransomnote -> Artifact(hashes MD5/SHA-1/SHA-256) + File content_ref")

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
channels = [o for o in ioc_objs if o.type == "channel"]
patterns = sorted(i.pattern for i in inds)
assert len(inds) == 4, f"expected 4 indicators, got {len(inds)}"
assert len(channels) == 1 and channels[0].channel_types == ["Tox"], "tox -> Channel"
assert any("SHA-1" in p for p in patterns)
assert any("ipv4-addr" in p for p in patterns)
assert any("domain-name" in p for p in patterns)
assert any("url:value" in p for p in patterns)
# indicator relationships indicate the IS; the channel is used-by the IS
indicates = [r for r in ioc_objs if getattr(r, "relationship_type", None) == "indicates"]
uses = [r for r in ioc_objs if getattr(r, "relationship_type", None) == "uses"]
assert len(indicates) == 4 and all(r.target_ref == is_ref for r in indicates)
assert len(uses) == 1 and uses[0].source_ref == is_ref and uses[0].target_ref == channels[0].id
print("OK  iocs -> 4 indicators indicate IS; tox -> Channel used-by IS")

# 7. Everything serializes into one valid STIX bundle
allobj = [author, tlp, conv.intrusion_set_stub(GROUP)]
allobj += tool_objs + ttp_objs2 + cve_objs + yara_objs + ioc_objs
unique = list({o.id: o for o in allobj}.values())
bundle = stix2.Bundle(objects=unique, allow_custom=True).serialize()
assert '"type": "bundle"' in bundle
print(f"OK  bundle serialized: {len(unique)} unique objects")

# 8. Real PRO /iocs/thegentlemen payload shape (dict keyed by type under "iocs")
from api_client import RansomwareLiveClient
real_payload = {
    "client": "x@example.com", "group": "thegentlemen", "filter_type": None,
    "ioc_types": ["tox", "sha1"],
    "iocs": {
        "tox": ["F8E24C7F5B12CD69C44C73F438F65E9BF560ADF35EBBDF92CF9A9B84079F8F04060FF98D098E"],
        "sha1": [
            "c12c4d58541cc4f75ae19b65295a52c559570054",
            "c0979ec20b87084317d1bfa50405f7149c3b5c5f",
            "df249727c12741ca176d5f1ccba3ce188a546d28",
            "e00293ce0eb534874efd615ae590cf6aa3858ba4",
        ],
    },
}
records = RansomwareLiveClient._as_ioc_list(real_payload)
assert len(records) == 5, f"expected 5 ioc records (1 tox + 4 sha1), got {len(records)}"
assert sum(1 for r in records if r["type"] == "sha1") == 4
assert not any(r["value"] in ("tox", "sha1") for r in records), "picked up type names as values"
real_objs = conv.convert_iocs(is_ref, GROUP, records)
real_inds = [o for o in real_objs if o.type == "indicator"]
assert len(real_inds) == 4, f"expected 4 sha1 indicators (tox skipped), got {len(real_inds)}"
assert all("SHA-1" in i.pattern for i in real_inds)
print("OK  real /iocs payload -> 5 records parsed, 4 SHA-1 indicators, tox skipped")

# 9. /groups envelope tolerance (PRO wraps the list; free returns a bare list)
assert RansomwareLiveClient._extract_list(
    {"client": "x", "groups": [{"name": "a"}]}, ("groups", "data")) == [{"name": "a"}]
assert RansomwareLiveClient._extract_list([{"name": "a"}], ("groups",)) == [{"name": "a"}]
assert RansomwareLiveClient._extract_list(
    {"client": "x", "weirdkey": [{"name": "b"}]}, ("groups",)) == [{"name": "b"}]
assert RansomwareLiveClient._extract_list({"client": "x"}, ("groups",)) == []
print("OK  /groups envelope tolerance (dict-wrapped, bare list, fallback, empty)")

# 10. Real PRO /groups entries name the group with the "group" key
real_groups_payload = {"client": "x", "count": 3, "groups": [
    {"group": "0apt", "altname": None, "victims": 0},
    {"group": "8base", "altname": None, "victims": 455},
    {"group": "0day syndicate", "altname": None, "victims": 5},
]}
raw = RansomwareLiveClient._extract_list(real_groups_payload, ("groups",))
norm = RansomwareLiveClient._normalize_groups(raw)
names_out = [g["name"] for g in norm]
assert names_out == ["0apt", "8base", "0day syndicate"], names_out
# free-v2 style (name key) and bare strings still work
assert RansomwareLiveClient._normalize_groups([{"name": "akira"}, "lockbit3"]) == [
    {"name": "akira"}, {"name": "lockbit3"}]
print("OK  /groups entries -> name resolved from 'group' key (+ name/string fallbacks)")

print("\nALL SELFTESTS PASSED")
