# Deploy SONiC Smart Patch Intelligence

The primary deployment is a Python virtual environment on the management server.
The default listener is **HTTPS at `<server-ip>:8000`**. Central workers run Grype;
switches only publish inventory and bounded runtime facts. One service process owns
the durable queue. Do not run multiple Uvicorn workers against the same state directory.

## Prepare and start

For a new installation, use a fresh Smart Patch state directory and database.
For an existing Smart Patch 3.0 installation upgrading to this maintenance update,
preserve its database, tokens, TLS material and configuration; do not reset enrollment
or remove local action journals. Stop/restart the service only after checking that
no package action is active. Earlier product names still have no compatibility aliases.

Prerequisites: Linux amd64/arm64, Python 3.10+, `python3-venv`, `curl`, `openssl`,
`git`, `gpgv` for signed repository metadata, and Debian `dpkg` for version-comparison tools. The host must own the chosen
bind address. Preparation downloads Python packages and the checksum-pinned Grype
0.112.0 binary; it does not start a listener or change a switch.

```bash
./scripts/prepare-local.sh
./scripts/start-local.sh
```

The preparation helper creates `.venv`, `.tools/grype`, `.state`, and a mode-0600
`.env`. Existing configuration is preserved. For offline preparation, pre-provision
pinned Python wheels and the scanner, or use `--skip-scanner` and configure an
existing scanner binary. This flag does not create a working scanner by itself.

Optional preparation overrides:

```bash
SMART_PATCH_BIND_HOST="<server-ip>" SMART_PATCH_BIND_PORT=8000 \
  SMART_PATCH_STATE_DIR=/var/lib/sonic-smart-patch \
  SMART_PATCH_VENV_DIR=/opt/sonic-smart-patch/venv ./scripts/prepare-local.sh
```

The selected directories must already be writable by the service account. Reuse
`SMART_PATCH_VENV_DIR` when starting if it differs from the default. Run the service as
a dedicated account whose state and source-repository permissions are restricted
to its needs. It does not require root. A root-run deployment's generated private
files are consequently root-owned.

On first startup, the service generates `.state/bootstrap-token` and
`.state/settings.key`, both mode 0600. An administrator reads the bootstrap token
locally and pastes it into the UI's connection dialog. Do not put it in URLs, shell
history, source code, screenshots, or logs. Use Access tokens to issue one `agent`
credential per device, bound to its device ID. Token creation returns the raw token
once; the database stores its digest. The browser stores the administrator token
in `sessionStorage` for the current tab, never `localStorage`.

## Permanently remove a switch from the service

First stop its collector on the switch:

```bash
sudo security config smart-patch disable
# Community SONiC also exposes: sudo config security smart-patch disable
```

Take a private database backup and let outstanding analysis and package work
finish. Stop the central service before applying a purge; retain its PID file so
the tool can verify that process has stopped. From the service checkout,
review the offline tool's dry run with the actual SQLite database path, exact
device ID and service PID file:

```bash
.venv/bin/python scripts/purge-device.py \
  --database /path/to/state/smart_patch.db \
  --device-id '<device-id>' --pid-file /path/to/service.pid
```

Apply the reviewed removal by adding `--apply`; add `--compact` to compact the
SQLite database after deletion. The tool requires the service to be stopped
before applying changes. Restart the service after the purge completes.

This tool supports SQLite deployments. The purge permanently removes the switch's inventory, credentials and associated
service records. It cleans affected batches and derived analytics while
preserving other switches and shared release artifacts. Fleet views read the
remaining data directly. There is no archive/restore API or hidden device state.

Derived assessment/response caches are invalidated. The CVE discovery ledger is
rebuilt from retained findings and history, with historical coverage marked
partial. Combined fleet snapshots from before the switch's exclusion are removed
because their per-switch contributions cannot be recovered accurately. Shared
evidence snapshots stay when other records still cite them; a retained reference
to device-owned evidence blocks deletion until that dependency is resolved.
Existing backups and exported retention archives are separate from the live
database and are not erased by this tool.

This offline database operation does not uninstall software or delete collector
state on the switch. Handle switch package cleanup separately and establish the
outcome of any outstanding package action before removing its service records.
Reconnecting the switch later requires a new enrollment credential.

## Upgrade collectors and configure maintenance visibility

Install the matching `sonic-smart-patch_3.1.1-1_all.deb` on each intended switch using
your normal package deployment process. Preserve the existing Smart Patch enrollment,
state and journals. The service accepts older inventory clients, but container
maintenance and CLI-origin progress require the new capability/reporting support.
Keep `maintenance_mode=false` until an operator permits the intended container work.

Collector **3.1.1-1** fixes transfer of staged archives from runtime-mounted
container temporary directories. In 3.1.0, APT could download into a `/var/tmp`
tmpfs successfully while `docker cp` then reported the path missing through the
Docker archive view. The corrected transfer uses the running container's mount
view and retains exact container/package identity checks. A failed staging copy
has not installed the target package. Preserve existing configuration, credentials
and plan journals during upgrade, then create a fresh current plan before staging
again; no failed action is retried or approved automatically. Historical 3.1.0
validation artifacts describe their original build and are not proof for 3.1.1.

The daemon reports capability, container identity and progress through device-token
`POST /api/v1/agents/remediation`, separately from potentially long inventory/action
synchronization. Permit this HTTPS path through any proxy. A report keeps connectivity
fresh without claiming new inventory collection or scan coverage. Background jobs must
remain enabled for central reassessment and batch dispatch.

Snapshot rollback fallback needs outgoing HTTPS to `snapshot.debian.org`, normal CA
trust, and `/usr/share/keyrings/debian-archive-keyring.gpg` on the switch. It creates
private temporary APT configuration; no global source rewrite is required. Use the
Debian distribution and architecture of the target container, which may differ from
the host. Container execution has two supported paths:

- **Unified cgroup v2:** the target container needs `/usr/bin/python3`; the host needs
  a supported Docker Engine API (1.41 or newer), pidfd controls and trusted systemd
  maintenance units with the configured limits. Docker creates an exec with the
  original container security profile. A private gate must attach to the worker
  cgroup and be verified before the package command starts. Seccomp filtering is
  preserved; it is not disabled to enable maintenance.
- **Older cgroup v1:** the pinned-namespace fallback requires an unconfined,
  non-remapped compatible container. It refuses confined targets rather than
  bypassing filters that namespace entry cannot reproduce.

Both paths reject unsupported setups, user remapping, changed container identity
and missing resource guarantees. Smart Patch neither recreates the container nor
changes its security profile to satisfy these requirements. The cgroup v2 helper
uses a temporary private directory/socket in the container and cleans it up; no
persistent helper service is installed there. Validate the chosen path on the
actual platform before qualifying package maintenance.

### Reverse-proxy and SBOM file limits

The file limit is **52,428,800 bytes (50 MiB)**. The application accepts at most another
65,536 bytes for multipart overhead on `POST /api/v1/sbom-upload` and
`POST /admin/sbom-upload`; other APIs retain `MAX_REQUEST_BYTES` (16 MiB by default).
Both Content-Length and streamed byte counts are bounded. Oversized files receive
HTTP 413. `GET /api/v1/upload-limits` exposes the effective values to authorized users.

If a reverse proxy is used, allow at least **51 MiB** for these upload routes; for
example, the corresponding Nginx location can use `client_max_body_size 51m;`.
Apply that route-specific exception without raising unrelated API limits. Set
`MAX_SBOM_UPLOAD_BYTES=52428800` in the service environment and restart to change an
existing override. The deployment option is not an editable provider/UI setting.

## TLS and trust

Preparation creates a local CA and a 30-day server certificate with SANs for the
selected IP and `localhost`. Keep `ca.key` and `service.key` private. Distribute only
`ca.crt` to authorized clients and configure the collector's CA path. Install that
CA in the browser's trusted certificate store, or replace the server certificate
with one issued by your existing management-network CA. A browser certificate
warning means trust has not been configured; it does not mean the service is down.

For a prepared deployment:

```bash
curl --cacert .state/tls/ca.crt "https://<server-ip>:8000/health"
```

The start helper refuses non-TLS listening. Explicit plaintext test mode is limited
to `ALLOW_PLAINTEXT_LOCAL=true` with `HOST=127.0.0.1` or `::1`; normal deployment and
collector traffic use certificate verification. The service entry point itself
honors `TLS_CERT`/`TLS_KEY`, so always configure those when using another supervisor.
The helper does not rotate existing TLS material; schedule certificate replacement
and restart before expiry.

## Deployment configuration

Settings are read from environment variables or `.env` in the working directory.
Environment variables take precedence. Lists use JSON, for example
`SOURCE_ROOTS='["/srv/source/sonic-buildimage"]'`. Secret values are omitted from
`GET /api/v1/settings`; provider keys saved through the UI are encrypted using the
state directory's Fernet key.

| Variable | Default | Purpose |
|---|---|---|
| `HOST`, `PORT` | `<server-ip>`, `8000` | Bind address and port. |
| `STATE_DIR` | `.state` | Bootstrap token, encryption key, and runtime state directory. |
| `DATABASE_URL` | `sqlite:///./.state/smart_patch.db` | Durable records/queue. SQLite uses WAL; PostgreSQL URLs are supported by the store. |
| `TLS_CERT`, `TLS_KEY` | empty | Server certificate/key paths; preparation writes absolute paths. |
| `LOG_LEVEL` | `INFO` | Application log level. |
| `BOOTSTRAP_TOKEN` | generated private file | Optional pre-provisioned admin token. Prefer the generated file or a secret manager. |
| `SCANNER_BINARY` | `grype` | Central Grype executable. Preparation pins `.tools/grype`. Restart after changing. |
| `SCANNER_DB_DIR` | `.state/grype-db` | Central advisory database cache; requires persistent disk space. |
| `SCAN_TIMEOUT_SECONDS` | `600` | Per-scope scanner time limit (5–3600). |
| `SCANNER_MAX_OUTPUT_BYTES` | `67108864` | Bound on scanner output captured by the service. |
| `SCAN_INTERVAL_SECONDS` | `21600` | Periodic reassessment interval; the scheduler also updates advisory data daily. |
| `WORKER_COUNT` | `1` | Central worker concurrency (1–4). Measure peak memory before increasing. |
| `JOBS_ENABLED` | `true` | Start scheduler/workers. Set false for isolated API tests; jobs remain queued. |
| `SOURCE_ROOTS` | `[]` | Read-only repository roots available to bounded source tools. |
| `SOURCE_REVISION` | empty | Exact source commit for investigation context. Source tool calls require a full commit hash. |
| `BUILD_EVIDENCE_POLICY` | `required` | `required` keeps unverified exact matches under investigation; `optional` allows eligible inventory/advisory matches to be affected while build provenance remains unverified. |
| `AI_ENABLED` | `false` | Enable provider-backed investigation. Deterministic matching still works when disabled. |
| `AI_PROVIDER` | `openai` | Configured provider adapter; see supported provider names in the service. |
| `AI_API_URL`, `AI_API_KEY`, `AI_MODEL` | empty | Provider endpoint, secret, and exact model identifier. |
| `AI_MAX_CALLS` | `4` | Maximum provider calls per investigation. |
| `AI_MAX_FINDINGS` | `10` | Maximum CVEs per provider batch (0 pauses provider batches; maximum 100). Remaining eligible cases continue from saved evidence. |
| `AI_MAX_TOOL_CALLS` | `6` | Maximum evidence-tool calls per investigation. |
| `AI_MAX_INPUT_CHARS` | `24000` | Bound on assembled investigation context. |
| `AI_MAX_OUTPUT_TOKENS` | `1200` | Maximum response tokens per provider request. |
| `AI_TIMEOUT_SECONDS` | `30` | Provider request timeout (1–120). |
| `CACHE_TTL_HOURS` | `24` | Declared cache configuration; inspect implementation-specific reuse rules before changing. |
| `MAX_REQUEST_BYTES` | `16777216` | Default request-body budget, including inventory and JSON APIs; unchanged by the SBOM upload budget. |
| `MAX_SBOM_UPLOAD_BYTES` | `52428800` | Maximum SBOM file bytes: 50 MiB. Only the two SBOM upload routes receive an additional bounded 64 KiB multipart allowance. |
| `ONLINE_THRESHOLD_SECONDS` | `300` | Last-seen age used to label devices online/stale. |
| `RETENTION_DAYS` | `365` | Archive-before-delete cleanup of expired, unreferenced operational records; current trust and replay identities remain retained. |
| `ALERTS_ENABLED` | `true` | Evaluate measured service alert rules and retain alert/audit records. |
| `ALERT_MIN_SAMPLES` | `20` | Minimum samples before rate/latency rules evaluate. |
| `ALERT_LATENCY_P95_SECONDS` | `2` | API p95 latency threshold over the bounded recent observation window. |
| `ALERT_CACHE_HIT_RATE_PERCENT` | `70` | Minimum measured cache reuse percentage. |
| `ALERT_ERROR_RATE_PERCENT` | `5` | Maximum measured API error percentage. |
| `ALERT_QUEUE_DEPTH` | `100` | Queue-depth alert threshold. |
| `SONIC_RELEASES`, `SBOM_SOURCE` | `[]`, empty | Compatibility configuration; register actual releases through the API/UI. |

The UI can update the subset accepted by `PUT /api/v1/settings`: provider fields,
source roots/revision, scan interval, build-evidence applicability policy, AI investigation limits, and operational alert thresholds. Bind addresses,
paths, worker count and other deployment knobs require environment changes and a
restart. Source repositories should be mounted read-only and pinned to exact commits.
Do not configure an entire home directory as a source root.

After enabling or changing the provider, explicitly start a device Scan or
Investigate action, or Sync the relevant release. Configuration changes do not
automatically launch a fleet-wide analysis. Existing investigations retain their
original input identity and cannot be relabeled under the new configuration.

**Optional build evidence:** after deploying this source change, choose **Settings & providers → Build evidence for applicability → Optional for inventory advisory matches**, or initialize `BUILD_EVIDENCE_POLICY=optional`. Saving marks existing assessments stale and schedules reassessment when workers are enabled; queue a fresh Scan for each device to request it explicitly. The default remains `required`; switch back and rescan to restore that assessment rule. Current views remain under investigation until reassessed, and historical records preserve the original policy. Changing the policy does not create build signatures or retroactively verify an image. Optional mode keeps known custom/patch-bearing and Debian cross-release candidates unresolved, does not automatically create fixed/not-affected verdicts, and requires a scoped operator review before approving inventory-only remediation. No SONiC ConfigDB change is needed. This source change has not been deployed by the documentation update.

Periodic deadlines and their current operation IDs are stored in the database.
Service restarts preserve rescan, daily advisory/release, hourly observation and
retention schedules. Failed periodic jobs retry after 60 seconds; successful jobs
advance their deadline from their recorded completion time. Primary release
refreshes are enqueued first. `JOBS_ENABLED=false` keeps scheduler and workers off.

Assessment responses record `assessment_duration_ms` from the trusted server
request entry through audit preparation. `queue_wait_ms` includes authentication,
body handling and worker wait before assessment begins; `processing_duration_ms`
covers assessment work. These fields exclude the subsequent audit write and
response serialization. HTTP middleware measurements include those steps up to
response headers, but are not client-observed network latency. Every response
states its `duration_basis`; direct helper calls without a server timestamp measure
worker time only. Client-provided timestamps never control these measurements.

Per-CVE processing is recorded separately from applicability. The authenticated
`GET /api/v1/analysis-lifecycle?target_kind=device&target_id=DEVICE_ID` endpoint
shows bounded transition histories and the input identity for each attempt; an
optional `finding_id` narrows the query. `target_kind=release` selects release
processing. Pending, analyzing, analyzed and retry-needed states do not by
themselves establish whether a CVE affects the switch. Saved-evidence continuations
use bounded batches, preserve attempt counts across restarts and avoid another
Grype scan. A successful AI response that still says unknown is not retried forever.

Release findings and immutable revision histories are available under
`/api/v1/releases/RELEASE_ID/findings/FINDING_ID` and its `/history` subpath.
History entries cite exact content-addressed `/api/v1/evidence-snapshots/DIGEST`
records. Subset AI updates preserve the last actual scan time and scan revision;
old occurrences retained after a partial scan cannot supply an authoritative
artifact verdict for the new scan. Legacy confidence and source-repository fields
remain null when their supporting evidence is unavailable.

Retention writes gzip JSONL archives under the private state directory before
deleting eligible records. Deletion rechecks record identity and live references.
Archives are not automatically expired; include them in backup and disk-capacity
planning. Current findings, trust, active work and inventory replay identities
are preserved. Historical assessment and evidence APIs cover retained database
records; archive recovery is an operator procedure.

## Supervisor example

A deployment owner may install a systemd unit using absolute installation paths:

```ini
[Unit]
Description=SONiC Smart Patch Intelligence
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=smart-patch
Group=smart-patch
WorkingDirectory=/opt/sonic-smart-patch
ExecStart=/opt/sonic-smart-patch/scripts/start-local.sh
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/sonic-smart-patch
# Point STATE_DIR, DATABASE_URL, SCANNER_DB_DIR and TLS paths at the writable state
# directory in .env; source repositories and installed binaries stay read-only.

[Install]
WantedBy=multi-user.target
```

Set memory/CPU limits from measured central scan requirements. Switch collector
limits do not size Grype workers. The helper neither installs nor activates a unit.

## Switch maintenance resource policy

The switch owns resource policy for package staging and installation. With the
updated native Smart Patch package installed, configure it through ConfigDB/CLI:

```bash
sudo config security setting maintenance_checks_enabled false
sudo config security setting maintenance_min_free_mib 500
sudo config security setting maintenance_cpu_quota_percent 0
```

`maintenance_checks_enabled` accepts exactly `true` or `false` and defaults to
`false`. Set it to `true` to require local preflight and pre/post health checks.
The free-space minimum defaults to 500 MiB and accepts 1–65536 MiB. With checks
enabled, it applies on the staging filesystem before staging and forward installation. The CPU value
defaults to 0 (disabled); 1–100 limits each maintenance command to that percentage
of one CPU. These are switch settings, not inputs on the service webpage. Use the
normal SONiC configuration-save process for persistent running ConfigDB changes.

On native SONiC/systemd, maintenance commands run in separate transient services:
512 MiB hard memory, 128 tasks and the command deadline, with no default CPU
quota. The collector retains its MemoryHigh=80M, MemoryMax=128M, CPUQuota=10% and
TasksMax=32 settings. Inspect the installed package and service behavior when
qualifying an existing deployment; source changes alone do not establish that an
older installed collector has these limits.

Automatic package maintenance is limited to eligible host packages. Container and
image changes require manual maintenance. Authentication, operating mode, exact
authorized device/package/target, explicit approval/expiry and supported execution
boundaries remain enforced. With checks disabled, local currentness, free-space,
dependency-policy, hash and health gates are skipped; package-manager operations
must still succeed, and APT's configured trust remains unchanged. Smart Patch attempts
rollback package downloads but permits a missing previous version, records
`rollback_available=false` and does not attempt partial automatic recovery.
Without complete recovery artifacts, installation failure requires manual recovery.
Skipped health validation is never reported as a pass. Command resource ceilings
apply regardless of this option.

With checks enabled, the complete rollback set and local preflight/health checks
are required. Default whole-switch health thresholds are CPU≤80%, memory≤90% and
disk≤85% used, independent of the maintenance quota/free-byte minimum.
`show security status --json` exposes the current policy (standalone:
`security show status --json`). Changing settings does not retry a denied request,
grant approval or install a package.

## Optional Docker deployment

`docker-compose.yml` contains one non-root service with a persistent state volume,
no embedded database password, and only the chosen management-IP port published.
Prepare TLS first, then provide a directory containing `service.crt`, `service.key`,
and `ca.crt` readable by container UID/GID 10001. Mount only those files; do not give
the container the CA private key. For example, have the deployment administrator
copy the files into a separate `docker-tls` directory, set its owner to 10001:10001,
set the directory mode 0700 and key mode 0600, then set `SMART_PATCH_TLS_DIR` to it.

```bash
SMART_PATCH_TLS_DIR=/secure/docker-tls docker compose build
SMART_PATCH_TLS_DIR=/secure/docker-tls docker compose up -d
```

The Docker image pins Python 3.11.16 by its official multi-platform image digest and the complete runtime package resolution
in `requirements.lock`. Debian package indexes and downloaded platform artifacts
can still change; record an image digest and hashed wheel archive for a release
that requires byte-for-byte reproducibility. Source tools
need additional read-only repository mounts and corresponding `SOURCE_ROOTS` paths.
A custom CA must include a `localhost` SAN for the included healthcheck, or adjust
its checked hostname. TLS/state files are excluded from the build context.

## Verification and UI testing

The authenticated readiness endpoint separates scanner/AI readiness from database
health. `/health` only confirms service/database availability. `/metrics` requires
an operator/admin token. No token value is logged by the deployment helpers.

```bash
python -m pip install -r requirements-dev.txt
python -m pytest tests/unit tests/integration -q
python -m playwright install chromium
python tests/browser/workspace_smoke.py --mock --output /tmp/smart-patch-ui-test
```

Mock browser tests explicitly use synthetic fixtures and test all views, token
creation, settings save, source-tool calls, safe rendering of malicious strings,
plan creation, and mobile layout. They bind no port and do not contact a switch.
For an authorized live deployment, the same browser script supports a read-only
smoke test using `--base-url`, `--token-file`, and `--output`. The optional
`--allow-untrusted-test-tls` bypass is limited to that browser test and does not
change collector or application TLS settings. Configure CA trust for normal use.

Back up the database with SQLite's online backup mechanism (or stop the service),
together with `settings.key`; encrypted provider settings cannot be recovered
without that key. Protect backups like credentials. Retain the Grype database
revision, source commits, and build identities when reproducing an assessment.

## Verify a signed release baseline

The community build emits an embedded manifest before sealing the image and an
external `<image>.smart-patch.json` index after the image/SBOM exist. A builder signs
the exact external index bytes. For an RSA signing key held by the build system:

```bash
openssl dgst -sha256 -sign /secure/build-signing.key \
  -out sonic-image.bin.smart-patch.json.sig sonic-image.bin.smart-patch.json
openssl pkey -in /secure/build-signing.key -pubout -out community-builder-2026.pem
```

Provision only the public key on the service host under
`STATE_DIR/trusted-build-keys/community-builder-2026.pem`. The trusted directory
and PEM file must not be writable by group or others; symlink keys/directories
are rejected. A typical public-key directory is mode 0755 and the PEM is mode
0644, owned by the deployment administrator. Its parent state directory remains
private. No signing private key is sent to the service or browser.

Upload the exact original SBOM bytes to register the artifact. In **Builds &
releases → Verify binding**, select the original embedded manifest, external index,
and detached binary signature, then enter the approved public-key ID. The API is
`POST /api/v1/artifacts/verify` with `release_id`, `manifest_text`,
`release_index_text`, `signature_base64`, and `key_id`. Manifest/index documents
are limited to 1 MiB each; signatures are limited to 1024 decoded bytes. Supported
signatures are RSA PKCS#1 v1.5/SHA-256 (2048–8192-bit keys) and Ed25519.

Verification requires matching canonical build identity, exact raw manifest digest,
and the registered original SBOM digest, plus signed image and SBOM records.
Changing whitespace in signed documents changes their digests/signature. Old
imports without an original-byte `source_sha256` must be reuploaded; a digest of
reserialized JSON cannot replace it.

A verified signature records a **signed release baseline**. Matching a switch's
reported build ID and raw manifest digest to it is an inventory association, not
TPM or runtime attestation. Package drift and runtime exposure still require their
own scoped observations and assessment. Existing switches without a build-time
manifest remain unverified.
