# Smart Patch 3.0 operational UI

The workspace at `/ui/` presents recorded inventory, evidence, decisions, and next
actions. It uses FastAPI/Jinja, plain JavaScript, local CSS, and SVG charts. There
is no charting CDN or synthetic production dataset.

## Access and assets

The shell is public; operational API calls require a Bearer token. The connection
dialog validates access against the service. Administrator tokens remain in the
browser tab's `sessionStorage`, and Disconnect removes them. Provider secrets are
entered through settings and never returned by the settings API. Generated access
tokens appear once at creation.

An administrator, operator, and enrolled agent have different backend permissions.
The UI reports permission failures; presenting a control never bypasses API
validation. Configure trust for the deployment CA before normal use. Authentication
credentials must not be included in URLs, screenshots, or source files.

The shell has a Content Security Policy. API strings are inserted as text, and
links are restricted to appropriate HTTP(S) sources. CSS/JavaScript URLs include a
content fingerprint so deployment restarts invalidate stale browser bundles.

## Views

| Route | What it shows |
|---|---|
| `/ui/` | Registered/online devices, all finding counts, unresolved evidence gaps, declared inventory scan coverage, and signed-baseline associations. The review queue switches between affected findings and candidates needing evidence; it defaults to candidates when affected verdicts are absent. |
| `/ui/fleet` | Switch identity, last seen, inventory/scopes, collection resources, findings and runtime facts. Device details can queue a central scan, request allowlisted observations, and export scoped VEX. |
| `/ui/findings` | Server-filtered findings with 50-row pagination. Applicability and exposure are distinct. Component/version/container identity, rationale, evidence, and freshness are inspectable. |
| `/ui/coverage` | Reported metadata scan coverage, signed-baseline match counts, missing/stale inventory, and applicability distribution. Package-scope coverage is not whole-device coverage. |
| `/ui/changes` | Recorded inventory, analysis, configuration, and operational events with expandable details. |
| `/ui/plans` | Scoped targets and repository evidence, explicit approval → staging → execution, collector results, and reassessment state. |
| `/ui/jobs` | Central scan, investigation, release, and target-check jobs with workflow phase, scope/package/finding counts, logs, errors and results. Completed processing and accepted current results remain distinct. |
| `/ui/tools` | Approved source/evidence tools, their input schemas, bounded JSON arguments, and actual results. |
| `/ui/remediation-status` | Per-CVE current operation state and retained CLI/service history; switch/CVE/scope/state filters and read-only progress details. |
| `/ui/releases` | Release registration with pinned source revision and explicit signed APT repository configuration, original SBOM upload, artifact details, and release-binding verification. |
| `/ui/packages-trends` | Unattended hourly observations, current package families, and recorded version-update rankings. Up to 7 days stays hourly; longer windows use the last actual observation per UTC day with sample counts and observed affected peaks. Missing days stay missing. |
| `/ui/cve-trends` | Observed applicability trends and current package/severity distributions. Distinct CVEs and scoped finding occurrences are separate counts. |
| `/ui/request-status` | Assessment API request states, average/p95 durations, observed cache reuse, and up to 500 matching request records. Request IDs open recorded details and errors. Background jobs are tracked separately. |
| `/ui/settings` | Provider endpoint/model/secret, source roots and pinned revision, scan interval, and effective non-secret configuration. Operational alert thresholds are editable; alerts are recorded as service/audit data. Some deployment-only fields are read-only. |
| `/ui/tokens` | Administrator/operator/agent credential creation, device binding, last-used metadata, and revocation. Raw existing tokens are never listed. |

Legacy `/ui/setup` and `/ui/smart-patch-integration` links redirect to their current
views. Operational views refresh every 30 seconds when visible and idle. Detail
dialogs are not silently replaced; use their refresh controls to inspect current
worker/collector results.

## Finding investigation and review

Open a finding to inspect its exact component occurrence and evidence. Investigation
queues central work. A scoped administrator review requires a justification and
selected existing evidence IDs. Fixed/not-affected outcomes require HTTPS supporting
evidence; a not-affected outcome also needs a valid OpenVEX justification.

The review identifies the device, component, inventory, and runtime context. The
service enforces freshness and expiry. A review does not suppress every occurrence
of the CVE, and AI output is not substituted for the required evidence.

## Staged maintenance workflow

1. Select findings from one package version, scope, and switch. Create a review plan.
2. Inspect target options and their status: **Candidate only**, **Recheck required**,
   or **Recheck passed**. Inspect signed repository evidence and required agent
   preflight. Candidate status is not operational compatibility.
3. **Recheck selected target** queues a central target scan and clears existing
   approval. Refresh the plan after the job completes, then review the result.
4. **Approve review** records authorization for the exact plan. Approval alone
   does not enable execution.
5. **Stage packages** asks the collector to prepare exact target/rollback artifacts
   and check inventory, dependencies, policy, free disk space and artifact hashes.
   Configured APT trust governs downloads; full resource/SONiC health baseline
   checks occur during apply immediately before installation. While
   staging is queued, failed, or unknown, execution remains unavailable.
6. **Review execution** is enabled only for a current approved plan with recorded
   successful staging and explicit server eligibility. The confirmation names the
   package, versions, scope, and device; type the exact device ID to request apply.
7. Refresh for collector results. **Pending reassessment** means the resulting
   inventory and central vulnerability assessment still need to establish the
   security outcome. A package-action acknowledgement is not a fixed verdict.

Expired plans, changed inventory/build identity, protected-package policy, missing
repository evidence, or failed preflight can block actions. The UI displays the
service result and preserves the full plan record for inspection.

## Remediate selected switches

Select finding rows across switches and choose **Remediate selected switches**.
The draft shows a separate package target, eligibility reason and evidence for
each switch. Missing reviews/fixes, stale/offline devices and manual image changes
are visible but excluded. Configure 1–10 switches at a time (default 1) and whether
new dispatch pauses after a failure (default enabled). Save target choices before
approving the eligible rows with **Approve and stage selected switches**.

Staging does not install packages. When selected rows are successfully staged,
**Review execution for selected switches** lists the exact devices/targets and
their retained staging checks, including skipped checks and unavailable rollback.
Type the displayed `EXECUTE N SWITCHES` phrase to authorize only those rows.
Later-staged rows are not silently included. Installation completion requires
fresh inventory and complete scoped reassessment for each switch.

**Maintenance plans** includes persistent batches with per-switch progress.
The open batch polls read-only status every five seconds. Pause/stop affect new
dispatch only; queued work can still finish. Resume does not retry failed work.
One eligible host or supported container package occurrence per switch may be included, with multiple
CVEs for that occurrence. Additional packages need a fresh batch after reassessment.
Draft preparation requires operator access; staging/execution/dispatch controls
require administrator access. Container eligibility additionally requires the updated collector maintenance-mode, capability and identity report.

## Container maintenance and CVE lifecycle

**Remediation status** separates the collector phase from applicability and central resolution. Filter by switch, CVE ID/prefix, exact host/container scope and state; open **Inspect status** for the selected attempt. Active visible rows poll read-only every five seconds, and detail polling follows the record even after its state leaves the table filter. Navigation, terminal status and errors stop polling. No status request dispatches work.

CLI-origin attempts are labelled **Switch CLI** and remain read-only here. They show local plan identity, target/observed version, progress, checks skipped, container restart and rollback archive evidence. Service-origin rows link to their independent central plan. `resolved` requires accepted complete scoped reassessment; `no_longer_reported` merely describes disappearance without verified maintenance closure. A later rollback or returning CVE must not display the earlier resolution as a current result.

**Switch fleet → Inspect** exposes reported maintenance mode, capability, freshness and eligibility reason. Operators enable container permission on the switch using `config security smart-patch maintenance-mode enable`; the UI does not enable it remotely. Eligible container plans explain that only the captured container restarts and that a writable-layer update can disappear when it is recreated. Protected core packages and unsupported execution setups remain manual. Eligible seccomp-filtered containers use the cgroup v2 Docker exec/gate path; cgroup v1 requires the compatible unconfined fallback. The UI never asks operators to disable a container security profile.

The **Builds & releases** upload form shows the effective maximum from `/api/v1/upload-limits` and checks file size before sending it. The default SBOM file budget is **50 MiB (52,428,800 bytes)**; normal inventory/JSON limits remain unchanged. A proxy must separately allow the multipart request. See [deployment limits](docs/DEPLOYMENT.md#reverse-proxy-and-sbom-file-limits).

Synthetic browser examples: [CVE history](docs/user-guide/images/16-remediation-status.png) and [CLI container reassessment](docs/user-guide/images/17-container-maintenance.png). These examples do not claim actual package installation or real vulnerability findings.

## Signed release binding

After uploading the original SBOM, select **Verify binding** on the release row.
Provide the original build-time manifest, exact signed external index, detached
binary signature, and an approved public-key ID. The UI sends the original text
and base64-encoded signature; it never accepts a signing private key.

The service checks approved-key trust, signature, build identity, and raw artifact
digests. A matching reported switch manifest identifies a signed release baseline.
The UI labels this separately from runtime/TPM attestation. Existing switches
without a matching build-time manifest stay unverified. See the signing workflow
in [deployment documentation](docs/DEPLOYMENT.md).

## External agent review with an existing sign-in

A finding’s **External agent review** action creates a bounded investigation case.
The dialog displays its exact snapshot identity, component/scope, expiry, tool and
context limits, and recorded evidence. Download or copy the JSON case bundle for
your authorized coding agent that is already signed in. Creating a case does not
invoke a model automatically and does not change the finding.

The agent uses the session’s allowlisted tools. Import its JSON result file or
paste its JSON into **Return an agent proposal**, then submit it. The UI supplies
case identity fields from the session when omitted; supplied identities still
undergo server validation. The agent can also submit directly to
`/api/v1/agent-sessions/{id}/analysis`. The finding then displays **External agent
proposal**, its source, rationale and evidence IDs separately from current
applicability. Agent names are self-reported; the workflow tag does not verify a
provider identity or prove an SSO session. Administrator review remains explicit. Expired or changed snapshots
must be investigated again rather than silently reusing an old proposal.

This lane does not need an AI-provider API key configured in Smart Patch. The coding
agent’s existing sign-in is separate from the service token used to access Smart Patch.
There is no simulated SSO button and no web-provider login implemented by this UI.

## Source tools and API-provider AI

Source tools expose bounded operations on configured repositories at exact commits,
plus named build/runtime facts and deterministic Debian version comparison. Tool
results include scope/provenance and unknowns; they are evidence, not automatic
proof that vulnerable code is unreachable.

The central API-provider lane is optional and requires configured provider credentials/model. An unavailable
provider is displayed honestly, with no generated substitute response. Settings
and deployment controls limit input size, output tokens, provider/tool calls, and
timeouts. Expanded investigation data remains inspectable as recorded evidence.

**CVEs per provider batch** limits each continuation; zero pauses provider batches.
Pending cases continue from saved evidence with durable attempt counts and bounded
retries. Finding details distinguish processing state from applicability. An AI
response can finish successfully while the verdict remains under investigation.
After enabling or changing the provider, start Scan/Investigate for a device or
Sync for a release to assess under the new configuration.

The CVE trends view separates **first observed CVEs** from the number of current
findings. Discovery counts each CVE once across the device fleet, including
unresolved candidates, and preserves its first observation after disappearance
or reappearance. Release-only candidates and CVE publication dates are excluded.
Migrated discovery history is labelled partial; empty intervals are not evidence
of successful scanning or absence of risk.

SBOM upload errors include a JSON path and the original line/column. Missing
properties point to the containing object; nested component paths retain their
actual hierarchy. Original source positions are unavailable for in-memory
dictionary imports that have no source text.

## Browser verification

```bash
python -m pip install -r requirements-dev.txt
python -m playwright install chromium
python tests/browser/workspace_smoke.py --mock --output /tmp/smart-patch-ui-test
```

Mock screenshots and findings are explicitly synthetic. The harness exercises all
14 views under production CSP, safe rendering, pagination, token/settings actions,
original-file binding submission, scoped review, staged maintenance gating, and
mobile layout. It binds no port and changes no real switch.

For an authorized live service, the harness also supports read-only navigation
using `--base-url`, a protected `--token-file`, and an output directory. The optional
`--allow-untrusted-test-tls` flag applies only to the browser test; normal clients
must verify their configured CA. Screenshots and run summaries distinguish mock
from live mode. Hardware mutation/rollback acceptance is a separate opt-in workflow
in the [community SONiC harness guide](../sonic-buildimage/src/sonic-smart-patch/tests/integration/README.md);
this UI document does not assert that those gates passed.
