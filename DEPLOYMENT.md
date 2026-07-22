# Deploying the Ransomware.live PRO Enrichment image into an existing OpenCTI stack

This guide covers running the connector as a **prebuilt Docker image** added to
your existing OpenCTI `docker-compose.yml`. It is purely additive: you build one
image and add one service. None of your existing services (opencti, worker,
redis, elasticsearch, minio, rabbitmq, your other connectors) are modified or
restarted.

---

## 0. Prerequisites

- An existing, running OpenCTI deployment managed by `docker compose`.
- The **MITRE ATT&CK connector** already imported into that platform (the TTP
  links resolve against those Attack Patterns).
- A **ransomware.live PRO API key** (`X-API-KEY`) from https://my.ransomware.live.
- Shell access to the host that runs the OpenCTI containers (or a CI/registry
  workflow if you build elsewhere — see 3b).
- The connector source folder `ransomwarelive-enrichment/` (this repo).

Throughout, replace `opencti` / `8080` with your platform's actual compose
service name and port if they differ.

---

## 1. Get the connector source onto the build host

Put the `ransomwarelive-enrichment/` folder somewhere on the Docker host. The
common choice is next to your compose file, e.g.:

```
/opt/opencti/
├── docker-compose.yml          # your existing stack
├── .env                        # your existing env file
└── ransomwarelive-enrichment/  # <-- this connector
    ├── Dockerfile
    ├── src/
    └── ...
```

## 2. Pin pycti to your platform version (do this before building)

`pycti` must match your OpenCTI version or you risk API errors at runtime.
Find your version in the OpenCTI UI footer (or `Settings → About`), then edit
`ransomwarelive-enrichment/src/requirements.txt`:

```
pycti==<your-opencti-version>     # e.g. 6.7.9  — must equal your platform version
stix2==3.0.1
requests==2.32.3
PyYAML==6.0.2
```

## 3a. Build and tag the image (local host)

From the directory that contains the connector folder:

```bash
docker build -t opencti-ransomwarelive-enrichment:1.0 ./ransomwarelive-enrichment
```

Verify it built:

```bash
docker images | grep ransomwarelive-enrichment
```

The image name `opencti-ransomwarelive-enrichment:1.0` is what the compose
service references. Use a real version tag (`:1.0`, `:1.1`, …) rather than
`:latest` so upgrades are explicit and rollbacks are possible.

> **"legacy builder is deprecated / install the buildx component"?** Recent
> Docker removed the classic image builder — builds now go through **buildx**
> (BuildKit). Use `docker buildx build --load -t opencti-ransomwarelive-enrichment:1.0 ./ransomwarelive-enrichment`
> (the included `build.sh` does this automatically). If `docker buildx` reports
> "not a docker command", install it: update **Docker Desktop** (buildx is
> bundled), or on Debian/Ubuntu/WSL2 `sudo apt-get install docker-buildx-plugin`,
> or drop the binary from https://github.com/docker/buildx/releases into
> `~/.docker/cli-plugins/docker-buildx` and `chmod +x` it. Optionally
> `docker buildx install` makes `docker build` use buildx by default.

Or just run the helper, which prefers buildx and prints install steps if it's
missing:

```bash
./build.sh            # -> opencti-ransomwarelive-enrichment:1.0
./build.sh 1.1        # a new version tag
```

## 3b. (Only if OpenCTI runs on a different host) push to a registry

Build once, then push to a registry both hosts can reach:

```bash
docker build -t myregistry.example.com/opencti-ransomwarelive-enrichment:1.0 ./ransomwarelive-enrichment
docker push  myregistry.example.com/opencti-ransomwarelive-enrichment:1.0
```

Then use that full name in the `image:` line below, and the OpenCTI host will
pull it automatically on `docker compose up`.

## 4. Create the connector's identity (UUID + token)

**UUID:** every connector needs a unique `CONNECTOR_ID`. Generate one:

```bash
python3 -c "import uuid; print(uuid.uuid4())"
# or: uuidgen
```

**Token:** you can reuse your platform's admin token, but the cleaner practice is
a dedicated connector user:

1. In OpenCTI: `Settings → Security → Users → Create` (e.g. name
   "Ransomware.live Enrichment"), give it a role that can write data
   (the default "Connector" / "Administrator"-level import role).
2. Open that user and copy its **API token**.
3. Use that token as `OPENCTI_TOKEN` below.

## 5. Add credentials to your existing `.env`

Append to the `.env` file your compose already uses (do **not** commit it):

```
# ransomware.live enrichment connector
RANSOMWARELIVE_API_KEY=your-pro-api-key
RANSOMWARELIVE_CONNECTOR_ID=the-uuid-you-generated
RANSOMWARELIVE_CONNECTOR_TOKEN=the-connector-user-token
```

(If you prefer to reuse your existing `OPENCTI_ADMIN_TOKEN`, you can reference
that instead of `RANSOMWARELIVE_CONNECTOR_TOKEN` in the service block.)

## 6. Add the service to your existing `docker-compose.yml`

Paste this block under the top-level `services:` key, alongside your other
connector services. It references the prebuilt image — there is no `build:`.

```yaml
  connector-ransomwarelive-enrichment:
    image: opencti-ransomwarelive-enrichment:1.0    # or myregistry.example.com/...:1.0
    environment:
      # --- OpenCTI core ---
      - OPENCTI_URL=http://opencti:8080             # internal compose URL of your OpenCTI service
      - OPENCTI_TOKEN=${RANSOMWARELIVE_CONNECTOR_TOKEN}
      # --- Connector core ---
      - CONNECTOR_ID=${RANSOMWARELIVE_CONNECTOR_ID}
      - CONNECTOR_NAME=Ransomware.live PRO Enrichment
      - CONNECTOR_SCOPE=intrusion-set,tool,attack-pattern,vulnerability,indicator
      - CONNECTOR_LOG_LEVEL=info
      - CONNECTOR_DURATION_PERIOD=P1D               # run once/day (respect PRO call budget)
      # --- ransomware.live PRO ---
      - RANSOMWARELIVE_API_KEY=${RANSOMWARELIVE_API_KEY}
      - RANSOMWARELIVE_BASE_URL=https://api-pro.ransomware.live
      - RANSOMWARELIVE_TLP=TLP:CLEAR
      - RANSOMWARELIVE_ENABLE_TOOLS=true
      - RANSOMWARELIVE_ENABLE_TTPS=true
      - RANSOMWARELIVE_ENABLE_CVES=true
      - RANSOMWARELIVE_ENABLE_YARA=true
      - RANSOMWARELIVE_ENABLE_IOCS=true
      - RANSOMWARELIVE_CREATE_MISSING_TTP=false
      - RANSOMWARELIVE_ONLY_GROUPS=thegentlemen     # <-- start with ONE group; blank for all later
    restart: always
    depends_on:
      - opencti
```

### Networking

- **Single-file stack (most deployments):** all services share the compose
  project's default network and reach each other by service name, so
  `OPENCTI_URL=http://opencti:8080` works as-is. Nothing else to do.
- **Stack that defines an explicit / external network:** copy the `networks:`
  block your *other* connector services use onto this one, e.g.:

  ```yaml
    connector-ransomwarelive-enrichment:
      image: opencti-ransomwarelive-enrichment:1.0
      environment: [ ... ]
      networks:
        - opencti-net          # same network name your other connectors use
  ```

  A connector that can't resolve `opencti` almost always means it isn't on the
  same network — match an existing connector's `networks:` exactly.

## 7. Start just the new service

This creates/starts only the enrichment connector and leaves everything else
running:

```bash
docker compose up -d connector-ransomwarelive-enrichment
docker compose logs -f connector-ransomwarelive-enrichment
```

Expected log lines: `connector starting`, `Starting enrichment run`,
`Groups to enrich {count: 1}` (because of the `ONLY_GROUPS=thegentlemen` test),
then `Enriched group {group: thegentlemen, objects: N}`.

## 8. Verify in OpenCTI

1. `Settings → Connectors` (or `Data → Ingestion → Connectors`): the
   "Ransomware.live PRO Enrichment" connector should be listed and show a recent
   run under a green/active state.
2. `Threats → Intrusion Sets → thegentlemen → Knowledge` tab:
   - `uses` → Tools (AnyDesk, rclone, ADFind, …)
   - `uses` → Attack Patterns (the ATT&CK techniques)
   - `targets` → Vulnerabilities (CVEs, if any)
   - linked Indicators (YARA rule + IOCs), each `indicates` the group.

## 9. Go full-coverage

Once the single-group test looks right, remove the restriction so every group is
enriched on the daily schedule:

```yaml
      - RANSOMWARELIVE_ONLY_GROUPS=
```

then:

```bash
docker compose up -d connector-ransomwarelive-enrichment    # recreates with new env
```

> **Call-budget reminder.** The connector makes ~`1 + 3 × (number of groups)`
> PRO calls per run (`/groups` once, then `/groups/<name>`, `/yara/<name>`,
> `/iocs/<name>` per group). With ~250 groups that's ~750 calls/run — safe on a
> daily (`P1D`) schedule against the ~3,000/day PRO limit. Don't shorten the
> period below a few hours with all groups enabled.

---

## Configuration reference

| Env var | Default | Description |
| --- | --- | --- |
| `OPENCTI_URL` | — | Internal compose URL of OpenCTI (`http://opencti:8080`) |
| `OPENCTI_TOKEN` | — | Token of the connector's OpenCTI user |
| `CONNECTOR_ID` | — | Unique UUIDv4 for this connector |
| `CONNECTOR_NAME` | Ransomware.live PRO Enrichment | Display name |
| `CONNECTOR_SCOPE` | intrusion-set,tool,attack-pattern,vulnerability,indicator | Types this connector writes |
| `CONNECTOR_LOG_LEVEL` | info | debug / info / warn / error |
| `CONNECTOR_DURATION_PERIOD` | P1D | ISO-8601 period between runs |
| `RANSOMWARELIVE_API_KEY` | — | PRO API key |
| `RANSOMWARELIVE_BASE_URL` | https://api-pro.ransomware.live | PRO base URL |
| `RANSOMWARELIVE_TLP` | TLP:CLEAR | Marking on every emitted object |
| `RANSOMWARELIVE_ENABLE_TOOLS` | true | Emit Tools + `uses` |
| `RANSOMWARELIVE_ENABLE_TTPS` | true | Emit `uses` → Attack Patterns |
| `RANSOMWARELIVE_ENABLE_CVES` | true | Emit Vulnerabilities + `targets` |
| `RANSOMWARELIVE_ENABLE_YARA` | true | Emit YARA Indicators + `indicates` |
| `RANSOMWARELIVE_ENABLE_IOCS` | true | Emit IOC Indicators + `indicates` |
| `RANSOMWARELIVE_CREATE_MISSING_TTP` | false | Stub an Attack Pattern if not already in OpenCTI |
| `RANSOMWARELIVE_ONLY_GROUPS` | _(all)_ | Comma-separated allow-list of group slugs |

## Upgrading / rebuilding the image

After changing code or the pinned `pycti` version:

```bash
docker build -t opencti-ransomwarelive-enrichment:1.1 ./ransomwarelive-enrichment
# bump the image: tag in docker-compose.yml to :1.1
docker compose up -d connector-ransomwarelive-enrichment
```

Roll back by pointing `image:` at the previous tag and re-running the same
command. Because the connector is stateless (it re-reads the API each run and
upserts by deterministic IDs), rebuilds and rollbacks are safe and non-destructive.

## Troubleshooting

| Symptom | Likely cause / fix |
| --- | --- |
| `Missing required configuration: ...` at startup | An env var (`OPENCTI_URL`, `OPENCTI_TOKEN`, `CONNECTOR_ID`, `RANSOMWARELIVE_API_KEY`) is empty. Check `.env` and the service block. |
| Connector can't reach OpenCTI / connection refused | `OPENCTI_URL` wrong, or the service isn't on the same network. Match an existing connector's `OPENCTI_URL` and `networks:`. |
| `HTTP 401` / `403` from the PRO API | Bad or missing `RANSOMWARELIVE_API_KEY`. |
| `HTTP 429` in logs | PRO rate limit — the client backs off and retries; lengthen `CONNECTOR_DURATION_PERIOD` or narrow `ONLY_GROUPS`. |
| Intrusion set appears but has **no TTP links** | The MITRE ATT&CK connector hasn't imported those techniques. Run it, or set `RANSOMWARELIVE_CREATE_MISSING_TTP=true`. |
| Duplicate intrusion set created | The group slug didn't match the official connector's name. It uses `IntrusionSet.generate_id(<slug>)` with `lockbit3/2 → lockbit`; check the group's `name` in the API. |
| CVEs/IOCs missing for a group | The group genuinely has none, or the PRO payload uses field names the parser doesn't recognize — see the "endpoint/field assumptions" section in `README.md` and adjust `converter.py`. |
| pycti/GraphQL schema errors | `pycti` version doesn't match the platform. Re-pin in `requirements.txt` and rebuild. |
| `legacy builder is deprecated / install the buildx component` | Build with `docker buildx build --load ...` or run `./build.sh`. If buildx is absent, update Docker Desktop or install `docker-buildx-plugin` (see step 3a note). |
