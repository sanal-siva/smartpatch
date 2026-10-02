# Smart Patch Intelligence 3.0 implementation status

See the [consolidated detailed design](docs/DETAILED_DESIGN.md) for module contracts,
interaction diagrams, rationale, failure behavior and known implementation limits.

The original scaffold's task-completion checkboxes are superseded by the modules
and verification boundaries below. File presence is not an acceptance result. The
service is implemented for the hackathon; broad production/platform acceptance is
not asserted.

## Maintenance update

- Supported running Debian SONiC containers can install ordinary exact-version package targets and restart the captured container under explicit local maintenance mode. Cgroup v2 preserves Docker security profiles through a verified Python resource gate; cgroup v1 uses the unconfined namespace fallback. Protected core packages and unsupported setups remain manual; writable-layer changes do not survive recreation.
- Native `show security remediation` / `show security cves` and the UI **Remediation status** page include local CLI and service-origin attempts, download/install/restart phases and independent central resolution. Reports do not create approvals. A later rollback or repeated match invalidates the current resolved display while retaining history.
- Missing previous Debian packages can use exact-version official snapshot discovery and isolated signature-verified APT downloads. Scope distribution/architecture and artifact provenance remain explicit; custom packages may remain unavailable.
- SBOM file uploads accept 50 MiB with a bounded 64 KiB multipart allowance on upload routes; unrelated requests retain their 16 MiB budget.

Synthetic unit/API/browser tests cover these contracts, including an actual 50 MiB test file and negative container-identity/reassessment cases. They do not establish successful maintenance on every physical platform.

## Execution architecture

`app.main.create_app` constructs the authenticated API and public UI shell. Its
lifespan creates a durable `Runtime`; startup and shutdown own its database,
workers, scheduler, and secret storage. Heavy scanning runs in central workers.
Switches synchronize scoped metadata and evidence through the versioned agent API.

| Module | Responsibility |
|---|---|
| `app/api/models.py` | Validated inventory, token, release, assessment, and plan contracts. |
| `app/db/store.py` | SQL-backed device inventory, sequence/replay checks, tokens, queued operations, evidence, findings, and audit records. |
| `app/runtime.py` | Worker/scheduler lifecycle, advisory updates, inventory reconstruction, baseline association, cached assessments, and result delivery. |
| `app/services/scanner.py`, `process.py` | Central Grype execution and bounded process output/time handling. |
| `app/services/sbom_parser.py` | CycloneDX/SPDX parsing, bundled schema validation, scoped components, and original-source hashing. |
| `app/services/provenance.py` | Approved-key signature verification over exact release-index bytes and binding to the original manifest/SBOM/image identities. |
| `app/services/baseline.py` | Conservative association of observed components with signed baseline identities and patch pedigree. |
| `app/services/assessment.py` | Deterministic applicability decisions and explicit unresolved states. |
| `app/services/applicability_context.py` | Shared evidence selection; action receipts do not invalidate their own assessment, while relevant inventory/runtime changes do. |
| `app/services/request_assessment.py`, `request_lifecycle.py` | Registered, scoped assessment queries; revision-bound cache reuse; bounded asynchronous investigations and durable request outcomes. |
| `app/services/analysis_lifecycle.py` | Durable per-CVE processing transitions, attempt reservations and fair continuation of saved-evidence investigations. |
| `app/services/release_history.py`, `package_metadata.py` | Atomic release assessment revisions and exact evidence history; explicit evidence and unknowns for legacy package fields. |
| `app/services/json_source.py` | Bounded-path source location lookup for JSON/schema diagnostics, including nested components and missing properties. |
| `app/services/external_agent.py` | Snapshot-bound cases, scoped tools, and cited proposals from an already signed-in coding agent; no provider API key is required in Smart Patch for this lane. |
| `app/services/source_tools.py` | Approved, exact-revision source and patch tools, runtime/build facts, and Debian version comparison. |
| `app/services/ai_client.py`, `pipeline.py` | Optional provider-backed investigations, bounded tool/context budgets, evidence citations, and deterministic decision checks. |
| `app/services/release_service.py`, `github_sync.py` | Release ingestion, pinned source preparation, release findings, and durable analysis retry handling. |
| `app/services/repository_catalog.py` | Configured signed APT repository metadata, package/checksum availability evidence, and coverage errors. |
| `app/services/maintenance_capability.py`, `remediation_status.py` | Fresh container permission/identity gates, device-authenticated monotonic progress reports, CLI-origin history and scoped lifecycle projection. |
| `app/services/maintenance_policy.py`, `maintenance_jobs.py` | Scoped target resolution and central rechecks. Version ordering alone does not establish operational compatibility. |
| `app/analytics.py` | Scheduled hourly observations; adaptive hourly/daily history with last-observed values, counts and peaks; severity/package distributions and assessment-request measurements. |
| `app/observability/state.py` | Bounded latency/cache/error observations, actual provider availability and locally recorded alert transitions. |
| `app/services/retention.py` | Bounded archive-before-delete retention with current-reference checks and durable progress cursors. |
| `app/ui/` | Local-asset operational workspace, evidence and maintenance actions, and administration. |

Older compatibility modules remain in the tree. They should not be confused with
the application's current entry point or with independently running schedulers.

## Trust and state boundaries

- Device-supplied `artifact_verified` is a claim, never proof. A signed build
  association requires the registered original SBOM bytes, approved builder key,
  exact raw manifest digest, build ID, and matching manifest content.
- Signing proves a release-baseline statement. It does not provide remote runtime
  attestation. Existing images without build-time manifests remain unverified.
- Revoking or invalidating a binding removes current trust and requires
  reassessment. Scan commit/finding freshness includes build, inventory, context,
  and relevant binding identity so an older result cannot silently become current.
- Reviewed decisions expire with their supporting facts. Review, assessment and
  ruleset revisions also bind maintenance plans and queued collector actions;
  superseded work requires revalidation before delivery.
- Immutable assessment history and content-addressed evidence snapshots retain
  earlier evidence even when a later assessment reaches the same verdict.
- Fleet CVE discovery uses a durable earliest-observation ledger, separate from
  vulnerability stock. Reappearing CVEs are not new discoveries. Migrated history
  remains explicitly partial; publication dates and release-only candidates are
  not fleet observations.
- Applicability, exposure, collection completeness, and processing status remain
  separate. Missing evidence or a failed scan is not converted to zero risk.
- Scoped operator reviews require existing evidence IDs and justification; fixed
  or not-affected decisions require supporting HTTPS references. Exemptions do not
  transfer to another component occurrence, build, device, or runtime context.
- AI explanations are proposals supported by bounded evidence. The model does not
  obtain arbitrary shell access or independently grant suppression/remediation.
  No configured API provider means unavailable provider analysis, not a simulated
  response. An already signed-in external coding agent can use a bounded session
  and submit cited proposals through authenticated service APIs. This is separate
  from web SSO, which is not supplied by the Smart Patch UI. Agent names are
  self-reported metadata, not verified provider identities.

## Maintenance behavior

A plan identifies one switch, scope, binary package/version, candidate target, and
inventory/build state. Targets preserve advisory/source-version distinctions and
repository evidence. Where needed, a central Grype recheck evaluates the exact
candidate and current advisory database before staging can become eligible.

The API exposes separate review approval, staging, and execution transitions.
Approval does not install anything. Staging checks current inventory/package
identity, free space, dependency simulation, and retained forward/rollback
artifact identities and hashes. Downloads use configured APT trust; this is not
independent detached-signature verification of each `.deb`. When `maintenance_checks_enabled=true`, resource and SONiC health baseline checks run during apply, immediately before installation. Optional checks default to disabled, and missing rollback packages are reported without blocking staging; authentication, approval and actual package-manager errors remain enforced.
Execution requires recorded successful staging,
server eligibility, current plan identity/expiry, permitted agent policy, and an
explicit device confirmation. Completion must be followed by current inventory
and central reassessment before a vulnerability outcome is established.

The current UI uses only service-returned eligibility; it does not infer safety
from a higher version number, a repository listing, or an AI confidence score.

Multi-switch remediation adds a durable batch around independent child plans.
An operator selects findings, reviews per-switch eligibility and exact targets,
and an administrator separately approves staging and confirms the staged subset
for installation. Default concurrency is one switch, held through reassessment;
failures pause further dispatch by default. Batches survive restart without
requeuing an existing action. Pause/stop do not cancel already queued work, and
resume does not retry failed installations. The first workflow supports one
eligible host or supported container package occurrence per switch, with manual/blocked rows retained.
Single-plan and batch actions share device-busy and authorization guards.

## Verification evidence and limits

The repository includes executable unit tests, real-app API integration tests with
isolated state, and a headless-browser harness. Coverage includes authenticated
lifecycle and revocation, scoped inventory/replay, parser validation, scanner/cache
contracts, approved source tools, original-byte provenance, stale identity guards,
release jobs, repository evidence, maintenance target rules, and operational UI
interactions. Test counts change as regressions are added; use the actual run
output rather than a static completion count.

Browser mock results are explicitly synthetic. They exercise CSP, safe rendering,
all views, pagination, signatures, scoped review, target validation, approval,
staging, failed/unknown-stage gating, explicit execution confirmation, and mobile
layout. They do not establish a real vulnerability or platform maintenance safety.

Real two-DUT SSH and genuine SpyTest entry points are documented in the companion
[community SONiC acceptance guide](../sonic-buildimage/src/sonic-smart-patch/tests/integration/README.md).
Those tests are opt-in and produce separate measurements and cleanup results.
No hardware acceptance pass is claimed by this document. Similarly, live-provider
AI acceptance is not claimed without configured provider credentials and a recorded
run. Firmware/proprietary internals and manually copied binaries require their own
coverage; reported package metadata alone does not establish their security state.

## Packaging and operation

The distribution includes the Jinja workspace, local CSS/JavaScript, and offline
SBOM schemas. `requirements.lock` pins the runtime resolution; the optional Docker
base image is pinned by digest. The primary deployment uses a local virtual
environment, TLS, persistent private state, and a checksum-pinned central scanner.
Docker packaging exists, but image-build/runtime acceptance must be recorded
separately. See [deployment instructions](docs/DEPLOYMENT.md).
