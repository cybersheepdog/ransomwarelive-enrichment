# Ransomware.live PRO Enrichment Connector for OpenCTI
![Maintenance](https://img.shields.io/maintenance/yes/2026.svg?style=flat-square)
[![GitHub last commit](https://img.shields.io/github/last-commit/cybersheepdog/ransomwarelive-enrichment.svg?style=flat-square)](https://github.com/cybersheepdog/ransomwarelive-enrichment/commit/master)

A **companion** external-import connector that fills the gap left by the official
[`ransomwarelive`](https://github.com/OpenCTI-Platform/connectors/tree/master/external-import/ransomwarelive)
connector. The official connector ingests victims + the Intrusion Set (and, when
present, `IntrusionSet —uses→ AttackPattern` links). It does **not** ingest the
tools, CVEs, YARA rules, or IOCs that ransomware.live shows on each group page.

This connector adds exactly those, and links every object to the **same
Intrusion Set** the official connector already created — no duplicate groups.

> **Deploying into an existing OpenCTI stack?** See **`DEPLOYMENT.md`** for the
> full step-by-step (build the image, add the service, networking, verify,
> upgrade, troubleshoot). The section below is the quick reference.

| ransomware.live data | OpenCTI object created | Relationship to Intrusion Set |
| --- | --- | --- |
| Tools Used matrix | `Tool` | `intrusion-set —uses→ tool` |
| TTP matrix (MITRE techniques) | `Attack Pattern` (resolved by `x_mitre_id`) | `intrusion-set —uses→ attack-pattern` |
| CVEs / vulnerabilities | `Vulnerability` (`CVE-YYYY-NNNN`) | `intrusion-set —targets→ vulnerability` |
| YARA rule | `Indicator` (`pattern_type: yara`) | `indicator —indicates→ intrusion-set` |
| IOCs (hashes, IPs, domains, URLs, emails) | Observable + `Indicator` (`pattern_type: stix`) | `indicator —indicates→ intrusion-set` |

### Note on IOC linkage (group-level only)

IOCs are linked to the **group (Intrusion Set)**, not to individual Tools or
Malware. The ransomware.live IOC feed (`/iocs/<group>`) returns bare values
grouped by type — e.g. for `thegentlemen`: `{"iocs": {"sha1": [...], "tox": [...]}}`
— with **no attribution field tying a given hash to a specific tool or malware
family**. The "Tools Used" matrix is likewise just tool *names* with no hashes.
Because the source provides no hash→tool mapping, the connector cannot (and does
not) create `indicator —indicates→ tool` edges; a file hash and the tools are
both attached to the same Intrusion Set instead. IOC types with no STIX
observable equivalent (tox IDs, session IDs) are logged and skipped.

## Why it attaches to the same Intrusion Set

The official connector builds the intrusion set with
`pycti.IntrusionSet.generate_id(name)` (collapsing `lockbit3`/`lockbit2` to
`lockbit`). This connector reproduces that deterministic STIX ID, so OpenCTI
upserts onto the existing entity. It emits only a name-only Intrusion Set stub,
so it can never overwrite the richer description the official connector wrote.

## Prerequisites

1. The **MITRE ATT&CK connector** must have run first, so Attack Patterns exist
   to link TTPs to. Techniques that aren't found are skipped (or stubbed if you
   set `RANSOMWARELIVE_CREATE_MISSING_TTP=true`).
2. A **ransomware.live PRO API key** (`X-API-KEY`) from https://my.ransomware.live.
   IOCs and CVEs are PRO-only data.
3. Optionally, the official `ransomwarelive` connector running alongside — this
   one complements it but does not require it.

## Configuration

All parameters are environment variables (see `docker-compose.yml` and
`.env.sample`), or a `src/config.yml` (see `src/config.yml.sample`).

| Env var | Default | Description |
| --- | --- | --- |
| `OPENCTI_URL` | — | OpenCTI platform URL |
| `OPENCTI_TOKEN` | — | Connector user token |
| `CONNECTOR_ID` | — | A fresh UUIDv4 |
| `CONNECTOR_DURATION_PERIOD` | `P1D` | ISO-8601 period between runs |
| `RANSOMWARELIVE_API_KEY` | — | PRO API key |
| `RANSOMWARELIVE_BASE_URL` | `https://api-pro.ransomware.live` | PRO base URL |
| `RANSOMWARELIVE_TLP` | `TLP:CLEAR` | Marking on every object |
| `RANSOMWARELIVE_ENABLE_{TOOLS,TTPS,CVES,YARA,IOCS}` | `true` | Per-dataset toggles |
| `RANSOMWARELIVE_CREATE_MISSING_TTP` | `false` | Stub an Attack Pattern when not already in OpenCTI |
| `RANSOMWARELIVE_ONLY_GROUPS` | _(all)_ | Comma-separated allow-list of group slugs |

### Call-budget note

The PRO tier is limited (~3,000 calls/day). This connector makes about
**1 + 3×(number of groups)** calls per run (`/groups` once, then
`/groups/<name>`, `/yara/<name>`, `/iocs/<name>` per group). With ~250 groups
that's ~750 calls/run, so a **daily** (`P1D`) schedule is safe; sub-daily runs
or a very large `ONLY_GROUPS`-free run can exhaust the budget. Use
`RANSOMWARELIVE_ONLY_GROUPS` while testing.

## Run

```bash
cp .env.sample .env        # fill in tokens
# edit docker-compose.yml: set CONNECTOR_ID to a fresh uuidv4
docker compose up -d --build
docker compose logs -f
```

Run locally without Docker:

```bash
cd src
pip install -r requirements.txt
export OPENCTI_URL=... OPENCTI_TOKEN=... CONNECTOR_ID=... RANSOMWARELIVE_API_KEY=...
python connector.py
```

> **Pin `pycti` to your platform version.** `requirements.txt` pins a recent
> `pycti`; if your OpenCTI is a different version, set `pycti==<your-version>`
> to avoid API drift. Check with `GET {OPENCTI_URL}/graphql` platform info or
> the version shown in the OpenCTI UI footer.

## Verifying it worked

1. In OpenCTI open **Threats → Intrusion Sets → _thegentlemen_** (or any group).
2. **Knowledge** tab: you should now see, in addition to victims,
   - `uses` → Tools (AnyDesk, rclone, ADFind, …)
   - `uses` → Attack Patterns (the ATT&CK techniques)
   - `targets` → Vulnerabilities (CVEs), if the group has any
3. **Observables/Indicators** tab (or the linked indicators): YARA rule + IOC
   indicators, each with an `indicates` relationship back to the group.

If Tools/CVEs/YARA/IOCs are missing, check the connector logs — most commonly a
group simply has no such data, the technique wasn't in OpenCTI yet (run MITRE),
or the PRO IOC/CVE payload shape differs (see next section).

## Endpoint / field assumptions to verify against your PRO account

The PRO API isn't fully public, so two things are handled defensively and worth
a sanity check against your account's live responses:

- **IOCs** — pulled from `GET /iocs/<group>`. The confirmed PRO shape is
  `{"iocs": {"<type>": ["<value>", ...]}}` (a dict keyed by IOC type), which the
  parser handles; it also tolerates a plain list, `{type,value}` records, other
  envelope keys, and bare strings, and infers hash/IP/domain/URL/email types.
  Non-mappable types (tox IDs, session IDs) are logged and skipped. See the
  "Note on IOC linkage" above — the feed carries no per-tool attribution. If your
  payload uses different keys, adjust `_extract_ioc` / `_stix_pattern` in
  `src/converter.py` and `_as_ioc_list` in `src/api_client.py`.
- **CVEs** — there's no dedicated CVE endpoint, so they're extracted from the
  `/groups/<name>` detail: explicit `cve`/`cves`/`vulnerabilities` fields plus a
  `CVE-\d{4}-\d{4,7}` scan of the description and technique details. If your PRO
  detail exposes CVEs elsewhere, extend `convert_cves`.

The `tools`, `ttps`, and `yara` shapes are confirmed against the live
ransomware.live v2/PRO responses.
