# Deploying the Ransomware.live PRO enrichment connector

The connector runs as a service inside the **OpenCTI** compose stack on the
OpenCTI host. The compose file that actually runs lives at:

    ~/Tools/OpenCTI/docker/docker-compose.yml

The connector's service block was **copied into** that merged file, so the
standalone `docker-compose.yml` in this repo is a reference only — editing it
does *not* change what runs. Apply changes to the merged file on the host.

The connector's source (this repo: `Dockerfile` + `src/`) also lives on the
OpenCTI host. `docker build` reads from that copy, so it must be up to date
before you rebuild.

---

## One-time compose setup (merged OpenCTI file)

In `~/Tools/OpenCTI/docker/docker-compose.yml`, the connector service should
build from source and keep the image tag:

```yaml
  connector-ransomwarelive-enrichment:
    build: /absolute/path/to/ransomwarelive-enrichment   # folder with the Dockerfile
    image: opencti-ransomwarelive-enrichment:1.0
    environment:
      ...
      - RANSOMWARELIVE_CREATE_MISSING_TTP=true            # populate the ATT&CK matrix
      ...
```

Find the source path on the host:

```bash
find ~ -name Dockerfile -path '*ransomwarelive*' 2>/dev/null
```

Notes:
- `build:` + `image:` together means Compose builds from source and tags the
  result, so `--build` rebuilds in place.
- Because the service lives in the OpenCTI compose, it already shares the
  OpenCTI network — no extra `networks:` wiring needed.
- Env vars in compose override the code defaults in `src/config_loader.py`, so
  `RANSOMWARELIVE_CREATE_MISSING_TTP` must be `true` here, not just in the code.

---

## Deploy a code change

1. **Sync the source on the OpenCTI host.** Get the updated files into the
   host's copy of this repo (the one `build:` points at):

   ```bash
   git pull            # if the host copy is a git clone
   # otherwise scp/rsync the changed files, e.g.:
   #   src/api_client.py src/converter.py src/config_loader.py
   ```

2. **Mirror any compose changes** (env vars, `build:` path) into
   `~/Tools/OpenCTI/docker/docker-compose.yml` by hand.

3. **Rebuild and recreate just the connector**, from `~/Tools/OpenCTI/docker`:

   ```bash
   cd ~/Tools/OpenCTI/docker
   docker compose up -d --build connector-ransomwarelive-enrichment
   ```

   A plain `docker compose restart` reuses the old image and will **not** pick
   up code changes — you must `--build`.

4. **Verify** from the logs:

   ```bash
   docker compose logs -f --tail=100 connector-ransomwarelive-enrichment
   ```

   A healthy run shows:
   - no `[Errno 101] Network is unreachable` (IPv4 is forced by default)
   - `ttp_links` > 0 in the "Enrichment breakdown" lines
   - ransom-note artifacts created without "Missing required elements for
     Artifact creation (hashes - url)"

---

## Offline sanity check (no OpenCTI needed)

Before deploying, the converter logic can be validated on the host or any
machine with the source:

```bash
cd /path/to/ransomwarelive-enrichment
python3 tests/selftest.py
```

Expect `ALL SELFTESTS PASSED`.

---

## Relevant tunables (compose env)

| Variable | Default | Purpose |
|---|---|---|
| `RANSOMWARELIVE_CREATE_MISSING_TTP` | `true` | Create stub AttackPatterns (with tactic) so the ATT&CK matrix populates when MITRE data isn't imported. Set `false` for strict dedup against an imported MITRE dataset. |
| `RANSOMWARELIVE_FORCE_IPV4` | `true` | Force IPv4 for API calls. The API publishes an AAAA record but the container has no IPv6 route, which caused `[Errno 101] Network is unreachable`. Set `false` only on genuinely IPv6-capable hosts. |
| `RANSOMWARELIVE_REQUEST_DELAY` | `1.5` | Minimum seconds between API calls (client-side pacing). Raise it if you get rate-limited / IP-blocked; `0` disables. Spreads a run out instead of bursting into the rate limiter. |
| `RANSOMWARELIVE_MAX_GROUPS_PER_RUN` | `0` | Cap groups processed per run (`0` = all). The rest defer to the next run; the connector rotates (never-done/failed first, then oldest-success) so every group is covered over time and a blocked run resumes instead of restarting from the top. Progress is persisted in the connector's OpenCTI state. |
| `RANSOMWARELIVE_ONLY_GROUPS` | *(blank)* | Comma-separated allow-list to enrich only specific groups. Blank = all. |

## If you keep getting rate-limited / blocked

The PRO tier allows ~3000 calls/day, and each group hits several endpoints
(detail, iocs, yara, ransomnotes), so the burst rate matters as much as the
daily total. In order of effectiveness:

1. **Raise `RANSOMWARELIVE_REQUEST_DELAY`** (e.g. `3` or `5`) to space calls out.
2. **Narrow scope** with `RANSOMWARELIVE_ONLY_GROUPS=group1,group2` so a run
   touches fewer groups.
3. **Slow the schedule** with `CONNECTOR_DURATION_PERIOD` (e.g. `P2D`, `P7D`).
4. If already blocked, wait for the block to lift (a `Connection refused` /
   RST on port 443 is the block), then bring the connector back with a higher
   delay so it doesn't immediately re-trip the limiter.
