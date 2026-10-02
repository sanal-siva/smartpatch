/* SONiC Smart Patch workspace. API data is rendered with textContent, never HTML. */
(() => {
  'use strict';
  const API = '/api/v1';
  const TOKEN_KEY = 'smart_patch_admin_token';
  let fieldSequence = 0;
  let analyticsWindow = 30;
  const page = document.body.dataset.page || 'overview';
  const state = { token: sessionStorage.getItem(TOKEN_KEY) || '', data: {}, selectedFindings: new Set(), selectedRecords: new Map(), loading: false, refreshId: null, toolList: [] };
  const pendingPlans = new Set();
  let planWatch = null;
  let batchWatch = null;
  const pendingBatches = new Set();
  let batchDraftAttempt = null;
  let remediationViewCleanup = null;
  let remediationWatch = null;
  let jobWatch = null;
  let jobRequestRevision = 0;
  const icons = {
    overview: ['M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z'],
    fleet: ['M3 4h18v6H3zM3 14h18v6H3zM6 7h.01M6 17h.01M16 7h2M16 17h2'],
    shield: ['M12 3 20 7v6c0 4.5-8 8-8 8s-8-3.5-8-8V7l8-4Z', 'm8.5 12 2.5 2.5 4.5-5'],
    coverage: ['M9 3H3v6M15 3h6v6M3 15v6h6M21 15v6h-6', 'm8 12 3 3 5-6'],
    activity: ['M2 12h4l3-8 6 16 3-8h4'],
    plan: ['M8 4H4v17h16V4h-4M8 2h8v5H8zM8 12h8M8 16h5'],
    jobs: ['M12 8v4l3 2', 'M21 12a9 9 0 1 1-3-6.7M21 3v6h-6'],
    code: ['m8 6-6 6 6 6M16 6l6 6-6 6M14 3l-4 18'],
    box: ['m12 3 9 5v9l-9 5-9-5V8l9-5ZM3 8l9 5 9-5M12 13v9M7 5l10 5'],
    settings: ['M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8Z', 'm9 3 1-1h4l1 3 3 1 3 1v4l-2 1-1 3 1 3-3 3-3-1-3 1-1 1H6l-1-3-3-1v-4l2-2 1-3-1-2 3-3 2 1Z'],
    key: ['M14 5a5 5 0 1 1-3 9l-7 7H1v-4l7-7a5 5 0 0 1 6-5ZM17 8h.01'],
    refresh: ['M20 7A9 9 0 0 0 5 5L2 8M2 2v6h6M4 17a9 9 0 0 0 15 2l3-3M22 22v-6h-6'],
    arrow: ['M4 12h16m-6-6 6 6-6 6'], moon: ['M20 15.5A9 9 0 0 1 8.5 4 9 9 0 1 0 20 15.5Z'],
    sun: ['M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8ZM12 2v2M12 20v2M2 12h2M20 12h2M5 5l1 1M18 18l1 1M5 19l1-1M18 6l1-1'],
    menu: ['M3 6h18M3 12h18M3 18h18'], search: ['M10 3a7 7 0 1 0 0 14 7 7 0 0 0 0-14ZM15 15l6 6'],
    warning: ['m12 3 10 18H2L12 3ZM12 9v5M12 17h.01'], check: ['m5 12 4 4L19 6'],
    clock: ['M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18ZM12 7v5l4 2'], upload: ['M12 16V3m-5 5 5-5 5 5M4 15v6h16v-6'],
    link: ['m10 13 4-4M8 16l-2 2a4 4 0 0 1-6-6l5-5a4 4 0 0 1 6 0M13 17a4 4 0 0 0 6 0l5-5a4 4 0 0 0-6-6l-2 2'],
    memory: ['M6 6h12v12H6zM9 9h6v6H9zM9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4']
  };
  const pages = {
    overview: ['Security overview', 'Know what is running, what is affected, and what to do next.', 'SECURITY OPERATIONS'],
    fleet: ['Switch fleet', 'Inventory, resource use, and security state for every connected switch.', 'COMMUNITY SONiC'],
    findings: ['Vulnerability findings', 'Review applicability, exposure, and the evidence behind every decision.', 'EVIDENCE & ACTION'],
    coverage: ['Coverage & freshness', 'Find missing inventories and stale evidence before trusting an assessment.', 'INVENTORY ASSURANCE'],
    changes: ['Security activity', 'Follow inventory changes, assessments, and operational events.', 'AUDIT TRAIL'],
    plans: ['Remediation plans', 'Review affected components, proposed fixes, and operational prerequisites.', 'CONTROLLED CHANGE'],
    'remediation-status': ['Remediation status', 'Follow each CVE from preparation to installation and verified reassessment, including switch CLI changes.', 'CVE LIFECYCLE'],
    jobs: ['Analysis jobs', 'Track central scans and investigations through completion.', 'INTELLIGENCE OPERATIONS'],
    tools: ['Evidence tools', 'Inspect exact source revisions and collect bounded evidence for an investigation.', 'SOURCE & PATCH ANALYSIS'],
    releases: ['Builds & releases', 'Connect deployed builds with their software inventory and provenance.', 'ARTIFACT INTELLIGENCE'],
    settings: ['Settings & providers', 'Configure analysis, source evidence, and central scanning.', 'ADMINISTRATION'],
    'packages-trends': ['Package trends', 'Follow observed inventory growth and package distribution across the fleet.', 'RECORDED INVENTORY'],
    'cve-trends': ['CVE trends', 'Follow first observations, applicability changes, and packages with concentrated findings.', 'SECURITY ANALYTICS'],
    'request-status': ['Request performance', 'Inspect assessment API status, latency, and measured cache reuse.', 'SERVICE ANALYTICS'],
    tokens: ['Access tokens', 'Manage administrator and device access without sharing credentials.', 'ADMINISTRATION']
  };
  const $ = (selector, parent = document) => parent.querySelector(selector);
  const array = (value) => Array.isArray(value) ? value : [];
  const text = (value, fallback = '—') => value === null || value === undefined || value === '' ? fallback : String(value);
  const number = (value) => value === null || value === undefined ? '—' : Number.isFinite(Number(value)) ? Number(value).toLocaleString() : '—';
  const pretty = (value) => text(value).replaceAll('_', ' ').replace(/\b\w/g, (c) => c.toUpperCase());
  const date = (value) => value && !Number.isNaN(new Date(value).getTime()) ? new Date(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : 'Not recorded';
  const relative = (value) => {
    if (!value || Number.isNaN(new Date(value).getTime())) return 'Not recorded';
    const seconds = Math.max(0, (Date.now() - new Date(value).getTime()) / 1000);
    if (seconds < 60) return 'Just now';
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    return `${Math.floor(seconds / 86400)}d ago`;
  };
  function el(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
      if (value === null || value === undefined || value === false) continue;
      if (key === 'class') node.className = value;
      else if (key === 'text') node.textContent = text(value, '');
      else if (key.startsWith('on') && typeof value === 'function') node.addEventListener(key.slice(2), value);
      else if (key === 'checked' || key === 'disabled' || key === 'hidden') node[key] = Boolean(value);
      else if (key === 'value') node.value = value;
      else node.setAttribute(key, value === true ? '' : String(value));
    }
    for (const child of children.flat()) if (child !== null && child !== undefined) node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    return node;
  }
  function icon(name) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    for (const [key, value] of Object.entries({ viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': '1.6', 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true' })) svg.setAttribute(key, value);
    for (const data of icons[name] || icons.shield) { const path = document.createElementNS(svg.namespaceURI, 'path'); path.setAttribute('d', data); svg.append(path); }
    return svg;
  }
  function button(label, action, variant = 'secondary', iconName = null) { return el('button', { type: 'button', class: `button button-${variant}`, onclick: action }, iconName ? icon(iconName) : null, label); }
  function link(label, href, variant = 'quiet') { return el('a', { href, class: `button button-${variant}` }, label, icon('arrow')); }
  function tone(value) {
    const v = String(value || '').toLowerCase();
    if (['critical', 'high', 'affected', 'exposed', 'reachable', 'failed', 'denied', 'error', 'revoked', 'staging_failed', 'stage_failed', 'validation_failed', 'target_validation_failed', 'execution_failed', 'rollback_failed', 'reopened'].includes(v)) return 'danger';
    if (['medium', 'unknown', 'under_investigation', 'stale', 'partial', 'pending', 'queued', 'needs_review', 'draft', 'candidate_only', 'recheck_required', 'staging_unknown', 'not_ready', 'pending_reassessment', 'maintenance_required'].includes(v)) return 'warning';
    if (['fixed', 'resolved', 'not_affected', 'online', 'healthy', 'completed', 'approved', 'active', 'success', 'succeeded', 'signature_verified', 'staged', 'recheck_passed'].includes(v)) return 'success';
    if (['running', 'analyzing', 'low', 'info', 'informational', 'validating_target', 'staging_queued', 'executing', 'verified_index', 'eligible', 'staging', 'downloading', 'downloaded', 'installing', 'installed', 'restarting'].includes(v)) return 'info';
    return '';
  }
  function badge(value) { return el('span', { class: `badge ${tone(value)}` }, pretty(value || 'unknown')); }
  function inventoryOnlyAssessment(finding) { return finding.applicability === 'affected' && finding.decision_basis === 'inventory_advisory_match'; }
  function findingApplicability(finding) { return el('div', {}, badge(finding.applicability), inventoryOnlyAssessment(finding) ? el('span', { class: 'cell-secondary' }, 'Inventory advisory match · build unverified') : null); }
  function cell(primary, secondary = null, monospaced = false) { return el('div', {}, el('span', { class: `cell-primary${monospaced ? ' mono' : ''}` }, text(primary)), secondary !== null ? el('span', { class: 'cell-secondary', title: text(secondary) }, text(secondary)) : null); }
  function card(title, subtitle, body, action = null) { return el('section', { class: 'card' }, el('div', { class: 'card-header' }, el('div', {}, el('h2', { class: 'card-title' }, title), subtitle ? el('p', { class: 'card-subtitle' }, subtitle) : null), action), body); }
  function empty(message) { return el('div', { class: 'empty-inline' }, message); }
  function table(headers, rows, emptyMessage = 'No records available.') {
    const body = el('tbody');
    if (!rows.length) body.append(el('tr', {}, el('td', { colspan: headers.length, class: 'table-empty' }, emptyMessage)));
    for (const row of rows) body.append(el('tr', {}, row.map((content) => el('td', {}, content))));
    return el('div', { class: 'table-wrap' }, el('table', {}, el('thead', {}, el('tr', {}, headers.map((label) => el('th', { scope: 'col' }, label)))), body));
  }
  function stat(label, value, note, iconName, variant = '') { return el('div', { class: `stat-card ${variant}` }, el('div', { class: 'stat-heading' }, el('span', { class: 'stat-label' }, label), el('span', { class: 'stat-icon' }, icon(iconName))), el('div', { class: 'stat-value' }, value), el('div', { class: 'stat-note' }, note)); }
  function field(label, value) { return el('div', { class: 'detail-field' }, el('span', { class: 'detail-label' }, label), el('div', { class: 'detail-value' }, value instanceof Node ? value : text(value))); }
  function notice(message, variant = '') { return el('div', { class: `notice ${variant}` }, message); }
  function jsonBlock(data, dark = false) { return el('pre', { class: dark ? 'code-output' : '' }, JSON.stringify(data ?? {}, null, 2)); }
  function toast(message, kind = '') {
    const item = el('div', { class: `toast ${kind}`, role: kind === 'error' ? 'alert' : 'status' }, el('span', {}, message));
    item.append(el('button', { type: 'button', class: 'icon-button', 'aria-label': 'Dismiss notification', onclick: () => item.remove() }, '×'));
    // Native modal dialogs occupy the browser's top layer. A body toast, whatever
    // its z-index, is obscured and inert while a modal is open.
    const dialog = [...document.querySelectorAll('dialog[open]')].pop();
    if (dialog) {
      let region = $('.dialog-feedback', dialog);
      if (!region) { region = el('div', { class: 'dialog-feedback', 'aria-live': 'polite' }); dialog.prepend(region); }
      region.replaceChildren(item);
      item.scrollIntoView({ block: 'nearest' });
    } else $('#toast-region').append(item);
    if (!dialog || kind !== 'error') setTimeout(() => item.remove(), 7500);
  }
  async function api(endpoint, options = {}) {
    if (!endpoint.startsWith('/') || endpoint.startsWith('//') || endpoint.includes('://')) throw new Error('Invalid API endpoint.');
    const headers = new Headers(options.headers || {});
    if (state.token) headers.set('Authorization', `Bearer ${state.token}`);
    if (options.body && !(options.body instanceof FormData)) { headers.set('Content-Type', 'application/json'); options.body = JSON.stringify(options.body); }
    const response = await fetch(API + endpoint, { ...options, headers, credentials: 'same-origin', redirect: 'error', cache: 'no-store' });
    const payload = response.status === 204 ? {} : await response.json().catch(() => ({}));
    if (!response.ok) {
      if (response.status === 401) setConnection(false, 'Access expired');
      const detail = payload.detail || payload.message || payload.error;
      const message = typeof detail === 'string' ? detail : Array.isArray(detail) ? detail.map((item) => item.msg || 'Invalid request').join('; ') : `Request failed (${response.status})`;
      throw new Error(message);
    }
    return payload;
  }
  async function action(task, success) {
    try { const result = await task(); if (success) toast(success, 'success'); return result; }
    catch (error) { toast(error.message, 'error'); return null; }
  }
  function setConnection(connected, label = null) {
    const node = $('#connection-state'); node.classList.toggle('connected', connected); $('span', node).textContent = label || (connected ? 'Service connected' : 'Not connected');
    $('#auth-button').replaceChildren(icon('key'), connected ? 'Connected' : 'Connect');
  }
  function showAuth() { $('#auth-error').hidden = true; $('#auth-dialog').showModal(); setTimeout(() => $('#auth-token').focus(), 0); }
  function openDetail(kind, title, content) { stopPlanWatch(); stopBatchWatch(); stopRemediationWatch(); stopJobWatch(); $('#detail-dialog').classList.toggle('batch-modal', ['MULTI-SWITCH REMEDIATION', 'AUTHORIZE STAGED SWITCH CHANGES'].includes(kind)); $('.dialog-feedback', $('#detail-dialog'))?.remove(); $('#detail-kind').textContent = kind; $('#detail-content').replaceChildren(el('h2', { id: 'detail-title' }, title), content); if (!$('#detail-dialog').open) $('#detail-dialog').showModal(); }
  function recordId(row) { return row.id ?? row.operation_id ?? row.finding_id ?? row.device_id; }
  function safeUrl(value) { try { const url = new URL(value); return ['https:', 'http:'].includes(url.protocol) ? url.href : null; } catch { return null; } }
  function advisorySource(finding) {
    const source = finding.source || finding.advisory_namespace;
    if (source) return typeof source === 'string' ? source : JSON.stringify(source);
    return array(finding.advisory_sources).map((item) => typeof item === 'string' ? item : item.namespace || item.url || item.data_source || item.dataSource || item.name || item.id || JSON.stringify(item)).join(', ') || 'Not recorded';
  }
  function evidenceItems(evidence) {
    const items = Array.isArray(evidence) ? evidence : evidence && typeof evidence === 'object' ? Object.entries(evidence).map(([key, value]) => ({ type: key, value })) : [];
    if (!items.length) return notice('No supporting evidence has been recorded. Treat this assessment as unverified.', 'warning');
    return el('div', {}, items.map((item) => {
      if (typeof item === 'string') return el('div', { class: 'evidence-item' }, el('p', {}, item));
      const url = safeUrl(item.url || item.source_url || item.reference);
      return el('div', { class: 'evidence-item' }, el('h4', {}, text(item.title || item.type || item.kind || item.id, 'Evidence')), el('p', {}, text(item.description || item.summary || item.message || item.rationale || (typeof item.value === 'string' ? item.value : null), '')), item.value && typeof item.value === 'object' ? jsonBlock(item.value) : null, item.data && typeof item.data === 'object' ? jsonBlock(item.data) : null, el('div', { class: 'evidence-meta' }, item.id ? el('span', { class: 'mono' }, item.id) : null, item.source ? el('span', {}, text(item.source)) : null, item.collected_at || item.timestamp ? el('span', {}, date(item.collected_at || item.timestamp)) : null, url ? el('a', { href: url, target: '_blank', rel: 'noopener noreferrer' }, 'Open source ↗') : null), el('details', { class: 'timeline-details' }, el('summary', {}, 'Full evidence record'), jsonBlock(item)));
    }));
  }
  function timeline(events, limit = 8, expanded = false) {
    const items = array(events).slice(0, limit);
    if (!items.length) return empty('No activity has been recorded yet.');
    return el('div', { class: 'timeline' }, items.map((event) => el('article', { class: `timeline-item ${tone(event.severity || event.type)}` }, el('p', { class: 'timeline-title' }, text(event.message || event.type, 'Event')), el('div', { class: 'timeline-time' }, `${relative(event.created_at)}${event.device_id ? ` · ${event.device_id}` : ''}`), expanded ? el('details', { class: 'timeline-details' }, el('summary', {}, 'Inspect event'), jsonBlock(event)) : null)));
  }
  function findingRows(findings, compact = false, selectable = false) {
    return array(findings).map((finding) => {
      const row = [];
      if (selectable) row.push(el('input', { type: 'checkbox', class: 'row-select', 'aria-label': `Select ${finding.cve_id} in ${finding.scope}`, checked: state.selectedFindings.has(String(recordId(finding))), onchange: (event) => { const id = String(recordId(finding)); if (event.target.checked) { state.selectedFindings.add(id); state.selectedRecords.set(id, finding); } else { state.selectedFindings.delete(id); state.selectedRecords.delete(id); } updateSelection(); } }));
      row.push(el('button', { class: 'button-link', onclick: () => showFinding(recordId(finding)) }, cell(finding.cve_id, finding.package_name, true)), badge(finding.severity), cell(finding.hostname || finding.device_id, finding.scope), findingApplicability(finding));
      if (!compact) row.push(badge(finding.exposure), cell(array(finding.fixed_versions).join(', ') || 'No fix recorded', finding.affected_version ? `Installed ${finding.affected_version}` : null), el('span', { class: 'muted' }, relative(finding.assessed_at)));
      row.push(el('button', { class: 'button-link', onclick: () => showFinding(recordId(finding)), 'aria-label': `Inspect ${finding.cve_id}` }, icon('arrow')));
      return row;
    });
  }
  async function renderOverview() {
    const [overview, deviceData] = await Promise.all([api('/overview'), api('/devices')]);
    const s = overview.summary || {}; const devices = array(deviceData.devices); const verifiedBuilds = devices.filter((device) => device.artifact_verified === true).length;
    const totalFindings = s.findings_total ?? (overview.applicability_counts ? Object.values(overview.applicability_counts).reduce((sum, value) => sum + Number(value || 0), 0) : null);
    const count = $('#nav-findings-count'); count.textContent = number(totalFindings); count.hidden = totalFindings == null;
    let queueMode = state.overviewQueuePreference || (Number(s.findings_affected) > 0 ? 'affected' : 'under_investigation');
    let queueSequence = 0; const queueBody = el('div'); const queueTabs = el('div', { class: 'queue-tabs', role: 'group', 'aria-label': 'Review queue applicability' });
    async function updateQueue(mode) {
      queueMode = mode; const sequence = ++queueSequence;
      queueTabs.querySelectorAll('button').forEach((tab) => { const active = tab.dataset.mode === mode; tab.classList.toggle('active', active); tab.setAttribute('aria-pressed', String(active)); });
      queueBody.setAttribute('aria-busy', 'true');
      try { const response = await api(`/findings?limit=6&applicability=${mode}&sort=cvss`); if (sequence !== queueSequence) return;
        queueBody.replaceChildren(el('div', { class: 'queue-explanation' }, mode === 'affected' ? 'Highest-priority affected components.' : 'Highest-priority candidates needing build, patch, or runtime evidence.'), table(['FINDING / COMPONENT', 'SEVERITY', 'SWITCH / SCOPE', 'APPLICABILITY', ''], findingRows(response.findings, true), mode === 'affected' ? 'No affected verdicts are recorded. Review candidates that still need evidence.' : 'No unresolved candidates are currently recorded. Check inventory coverage and build verification.'));
      } catch (error) { if (sequence === queueSequence) queueBody.replaceChildren(notice(error.message, 'danger')); }
      finally { if (sequence === queueSequence) queueBody.setAttribute('aria-busy', 'false'); }
    }
    for (const [mode, label] of [['affected', `Affected (${number(s.findings_affected)})`], ['under_investigation', `Needs evidence (${number(s.findings_unknown)})`]]) queueTabs.append(el('button', { type: 'button', class: 'tab', 'data-mode': mode, onclick: () => { state.overviewQueuePreference = mode; updateQueue(mode); } }, label));
    await updateQueue(queueMode);
    const stats = el('div', { class: 'stat-grid' }, stat('Registered switches', number(s.devices_total), `${number(s.devices_online)} reporting online`, 'fleet'), stat('Affected findings', number(s.findings_affected), `${number(s.findings_exposed)} with reported exposure`, 'shield', 'danger'), stat('Under investigation', number(s.findings_unknown), 'Evidence needed for a verdict', 'search', 'warning'), stat('Reported inventory scanned', s.coverage_pct == null ? '—' : `${Number(s.coverage_pct).toFixed(0)}%`, 'Declared host/container metadata scopes', 'coverage', 'success'));
    const needsEvidence = Number(s.findings_unknown) > 0;
    const buildIndicator = el('span', { class: `badge ${verifiedBuilds < devices.length ? 'warning' : ''}` }, `Signed baseline matches: ${number(verifiedBuilds)} / ${number(devices.length)} switches`);
    const hero = el('section', { class: 'hero-panel' }, el('div', { class: 'hero-symbol' }, icon(needsEvidence ? 'search' : 'shield')), el('div', {}, el('p', { class: 'eyebrow' }, 'BUILD → SWITCH → EVIDENCE'), el('h2', {}, needsEvidence ? `${number(s.findings_unknown)} candidates need applicability evidence.` : s.devices_total > 0 ? 'Connect scanner results to verified build evidence.' : 'Bring your first switch into view.'), el('p', {}, needsEvidence ? 'Verify the deployed build, patch status, and relevant runtime conditions for these scanner matches. Unresolved candidates remain visible until evidence supports a verdict.' : s.devices_total > 0 ? 'Scanning declared package scopes does not cover unknown software, firmware, or unverified build provenance.' : 'Connect a Smart Patch collector to publish its scoped inventory. Central workers perform vulnerability matching away from the switch.'), el('div', { class: 'hero-evidence' }, buildIndicator)), el('div', { class: 'hero-actions' }, link(needsEvidence ? 'Review evidence gaps' : s.devices_total > 0 ? 'Explore fleet' : 'Manage access', needsEvidence ? '/ui/findings?applicability=under_investigation' : s.devices_total > 0 ? '/ui/fleet' : '/ui/tokens', 'primary'), devices.length ? link('Register build evidence', '/ui/releases', 'secondary') : null));
    const pipeline = card('Analysis pipeline', 'Heavy analysis stays in the intelligence service.', el('div', { class: 'pipeline' }, [['01 · INVENTORY', number(s.devices_total), 'registered switches'], ['02 · MATCHING', number(s.scans_running), 'active scans'], ['03 · INVESTIGATION', number(s.queue_depth), 'queued jobs']].map(([index, value, label]) => el('div', { class: 'pipeline-stage' }, el('div', { class: 'pipeline-index' }, index), el('div', { class: 'pipeline-number' }, value), el('div', { class: 'pipeline-label' }, label)))));
    const queue = card('Review queue', 'Review affected components and unresolved candidates separately.', el('div', {}, queueTabs, queueBody), link('All findings', '/ui/findings'));
    const scanner = overview.scanner || {}; const ai = overview.ai || {};
    const signals = card('Intelligence readiness', 'Source freshness and service state.', el('div', { class: 'card-body signal-list' }, signal('box', 'Central scanner', `${text(scanner.status, 'Unknown')}${scanner.version ? ` · ${scanner.version}` : ''}`), signal('clock', 'Advisory database', scanner.db_revision ? `Revision ${scanner.db_revision}` : 'No revision reported'), signal('box', 'Signed release binding', `${number(verifiedBuilds)} of ${number(devices.length)} reported manifests match signed release baselines.`), signal('code', 'API-provider investigations', ai.enabled ? `${text(ai.provider)} · ${text(ai.model)}` : 'Disabled · deterministic assessment remains available'), signal('code', 'Signed-in agent review', 'Create a bounded investigation case from a finding. This lane uses your coding agent’s existing sign-in.'), signal('activity', 'API-provider usage', `${number(ai.requests)} requests · ${number(ai.tokens)} tokens`), signal('coverage', 'Verdict discipline', 'Unknown and stale evidence remain visible. Exposure is separate from applicability.')));
    return el('div', {}, stats, hero, el('div', { class: 'overview-grid' }, el('div', { class: 'content-stack' }, queue, pipeline), el('div', { class: 'content-stack' }, signals, card('Recent activity', 'Latest recorded events.', timeline(overview.recent_events, 5), link('View all', '/ui/changes')))));
  }
  function signal(iconName, title, description) { return el('div', { class: 'signal' }, el('span', { class: 'signal-icon' }, icon(iconName)), el('div', {}, el('p', { class: 'signal-title' }, title), el('p', { class: 'signal-description' }, description))); }
  function maintenanceModeSummary(device) {
    const maintenance = device.maintenance || {};
    const enabled = maintenance.maintenance_mode === true;
    const capable = Boolean(maintenance.capabilities?.container_package_update);
    const ready = device.container_maintenance_eligible === true;
    return el('section', { class: 'detail-section container-maintenance-summary' }, el('h3', {}, 'Container package maintenance'), el('div', { class: 'detail-grid' }, field('Switch maintenance mode', typeof maintenance.maintenance_mode === 'boolean' ? enabled ? 'Enabled on switch' : 'Disabled on switch' : 'Not reported'), field('Container update capability', capable ? 'Reported by collector' : 'Not reported'), field('Current eligibility', ready ? badge('eligible') : 'Not currently eligible'), field('Mode reported', date(maintenance.reported_at))), notice(text(device.maintenance_reason, ready ? 'The collector reported maintenance mode and container package support. The plan still needs exact target review, staging and execution approval.' : 'Enable maintenance mode locally and synchronize an updated collector before preparing a container package plan.'), ready ? 'info' : 'warning'), el('p', { class: 'form-help' }, 'Enter maintenance mode after arranging any required traffic drain. This setting does not drain traffic automatically.'), el('pre', { class: 'code-output' }, 'sudo config security smart-patch maintenance-mode enable\n# After maintenance:\nsudo config security smart-patch maintenance-mode disable'), el('p', { class: 'form-help' }, 'Standalone CLI: replace “config security” with “security config”. A container package change restarts the target container and updates its writable layer. Recreating it or changing the SONiC image can discard the patch; include the fix in a maintained image for persistence.'));
  }
  async function renderFleet() {
    const { devices = [] } = await api('/devices'); state.data.devices = devices;
    const filters = searchToolbar('Search hostname, address, build, or platform', (query) => update(query));
    const container = el('div');
    function update(query = '') {
      const filtered = devices.filter((item) => JSON.stringify([item.hostname, item.ip_address, item.sonic_version, item.build_id, item.platform]).toLowerCase().includes(query.toLowerCase()));
      container.replaceChildren(card('Switch inventory', `${filtered.length} of ${devices.length} registered switches`, table(['SWITCH', 'SONiC BUILD', 'INVENTORY', 'FINDINGS', 'LAST SEEN', 'STATE', ''], filtered.map((device) => [el('button', { class: 'button-link', onclick: () => showDevice(device.id) }, cell(device.hostname || device.id, device.ip_address)), cell(device.sonic_version, device.build_id), cell(`${number(device.components_count)} components`, `${number(device.scopes_count)} scopes`), cell(`${number(device.findings_counts?.affected)} affected`, `${number(device.findings_counts?.under_investigation ?? device.findings_counts?.unknown)} unknown`), el('span', { title: date(device.last_seen) }, relative(device.last_seen)), badge(device.status), el('button', { class: 'button-link', onclick: () => showDevice(device.id) }, 'Inspect', icon('arrow'))]), 'No switches match. Register a device token and connect a collector to add a switch.')));
    }
    update(); return el('div', {}, filters, container);
  }
  function searchToolbar(placeholder, onInput) { return el('div', { class: 'toolbar' }, el('div', { class: 'search-field' }, el('span', {}, icon('search')), el('input', { type: 'search', placeholder, 'aria-label': placeholder, oninput: (event) => onInput(event.target.value) }))); }
  async function showDevice(id) {
    await action(async () => {
      const payload = await api(`/devices/${encodeURIComponent(id)}?include_findings=false`); const device = payload.device || payload;
      const resources = device.resources || {};
      const content = el('div', {}, el('div', { class: 'detail-badges' }, badge(device.status), badge(device.scan_status)), el('div', { class: 'detail-grid' }, field('Management address', device.ip_address), field('Platform', device.platform), field('Build provenance', badge(device.artifact_verified ? 'signature_verified' : 'unverified')), field('SONiC version', device.sonic_version), field('Build identity', el('span', { class: 'mono' }, text(device.build_id))), field('Inventory digest', el('span', { class: 'mono' }, text(device.inventory_digest))), field('Last heartbeat', date(device.last_seen)), field('Inventory observed', date(device.inventory_collected_at)), field('Inventory freshness', pretty(device.inventory_freshness || 'unknown')), field('Collector resources', Object.keys(resources).length ? jsonBlock(resources) : 'Not reported'), field('Coverage', device.coverage && typeof device.coverage === 'object' ? jsonBlock(device.coverage) : text(device.coverage))));
      content.append(el('section', { class: 'detail-section' }, el('h3', {}, 'Component inventory'), el('p', { class: 'form-help' }, `Showing ${number(Math.min(200, array(device.components).length))} of ${number(array(device.components).length)} component records.`), table(['PACKAGE', 'VERSION', 'SCOPE', 'ARCHITECTURE'], array(device.components).slice(0, 200).map((component) => [cell(component.name || component.package_name, component.source_package), el('span', { class: 'mono' }, text(component.version)), text(component.scope), text(component.architecture || component.arch)]), 'Component details are not available.')), el('section', { class: 'detail-section' }, el('h3', {}, 'Runtime facts'), evidenceItems(device.facts)), el('section', { class: 'detail-section' }, el('h3', {}, 'Recent device activity'), timeline(device.events, 10)), el('div', { class: 'detail-actions' }, button('Queue central scan', () => queueDeviceScan(id), 'primary', 'refresh'), link('View findings', `/ui/findings?device_id=${encodeURIComponent(id)}`)));
      const collector = el('select', { 'aria-label': 'Runtime evidence collector' }, ['services', 'listeners', 'features', 'interfaces', 'routing', 'resources', 'inventory'].map((name) => el('option', { value: name }, pretty(name))));
      const evidenceScope = el('input', { value: 'host', placeholder: 'host or container scope', 'aria-label': 'Runtime evidence scope' });
      content.append(el('section', { class: 'detail-section' }, el('h3', {}, 'Request runtime evidence'), el('p', { class: 'form-help' }, 'Ask the enrolled collector for a named observation. The request is queued and returned on a subsequent sync.'), el('div', { class: 'toolbar' }, collector, evidenceScope, button('Request observation', () => action(async () => { const result = await api(`/devices/${encodeURIComponent(id)}/evidence`, { method: 'POST', body: { collector: collector.value, scope: evidenceScope.value, args: {} } }); toast(`Observation ${text(result.request_id)} ${text(result.status, 'queued')}.`, 'success'); }), 'secondary', 'search'))), el('div', { class: 'detail-actions' }, button('Export scoped VEX', () => action(async () => { const result = await api(`/devices/${encodeURIComponent(id)}/vex`); const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' }); const url = URL.createObjectURL(blob); const anchor = el('a', { href: url, download: `smart-patch-${String(id).replace(/[^A-Za-z0-9_.-]/g, '_')}.vex.json` }); anchor.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); }), 'secondary', 'shield')));
      content.append(maintenanceModeSummary(device), el('div', { class: 'detail-actions' }, link('View remediation status', remediationHref({ device_id: id }))));
      openDetail('SWITCH DETAIL', device.hostname || device.id, content);
    });
  }
  async function queueDeviceScan(id) {
    await action(async () => { const job = await api(`/devices/${encodeURIComponent(id)}/scan`, { method: 'POST', body: {} }); toast(`Central scan ${text(job.operation_id)} ${text(job.status, 'queued')}.`, 'success'); }, null);
  }
  async function renderFindings() {
    const original = new URLSearchParams(location.search);
    const filters = { query: original.get('search') || '', applicability: original.get('applicability') || '', severity: original.get('severity') || '', fix_available: original.get('fix_available') === 'false' ? 'false' : original.get('fix_available') === 'all' ? '' : 'true' };
    const container = el('div', { 'aria-live': 'polite' }); let offset = 0, requestSerial = 0, searchTimer; const limit = 50;
    const toolbar = searchToolbar('Search CVE, package, switch, or scope', (value) => { filters.query = value; offset = 0; clearTimeout(searchTimer); searchTimer = setTimeout(refreshResults, 250); });
    $('input', toolbar).value = filters.query;
    for (const [name, label, values] of [['applicability', 'All applicability', ['affected', 'under_investigation', 'fixed', 'not_affected']], ['severity', 'All severities', ['critical', 'high', 'medium', 'low', 'unknown']]]) {
      const select = el('select', { 'aria-label': label, onchange: (event) => { filters[name] = event.target.value; offset = 0; refreshResults(); } }, el('option', { value: '' }, label), values.map((value) => el('option', { value }, pretty(value))));
      select.value = filters[name]; toolbar.append(select);
    }
    const fixFilter = el('select', { 'aria-label': 'Fix availability', onchange: (event) => { filters.fix_available = event.target.value; offset = 0; refreshResults(); } }, [['true', 'Fix recorded'], ['false', 'No fix recorded'], ['', 'All findings']].map(([value, label]) => el('option', { value }, label)));
    fixFilter.value = filters.fix_available; toolbar.append(fixFilter);
    toolbar.append(button(`Create plan (${state.selectedFindings.size})`, createSelectedPlan, 'primary', 'plan')); toolbar.lastChild.id = 'create-plan-button'; toolbar.lastChild.disabled = !state.selectedFindings.size;
    toolbar.append(button('Remediate selected switches', createSelectedBatch, 'secondary', 'fleet')); toolbar.lastChild.id = 'create-batch-button'; toolbar.lastChild.disabled = !state.selectedFindings.size;
    async function refreshResults() {
      const serial = ++requestSerial; const query = new URLSearchParams();
      if (original.get('device_id')) query.set('device_id', original.get('device_id'));
      if (filters.query) query.set('search', filters.query);
      if (filters.applicability) query.set('applicability', filters.applicability);
      if (filters.severity) query.set('severity', filters.severity);
      if (filters.fix_available) query.set('fix_available', filters.fix_available);
      query.set('offset', String(offset)); query.set('limit', String(limit)); query.set('sort', 'cvss');
      container.setAttribute('aria-busy', 'true');
      try {
        const response = await api(`/findings?${query}`); if (serial !== requestSerial) return;
        const findings = array(response.findings); const total = Number.isFinite(Number(response.total)) ? Number(response.total) : findings.length; state.data.findings = findings;
        for (const finding of findings) if (state.selectedFindings.has(String(recordId(finding)))) state.selectedRecords.set(String(recordId(finding)), finding);
        const panel = card('Component findings', `${number(total)} matching records · ${limit} per page · a CVE can affect multiple components`, table(['', 'FINDING / COMPONENT', 'SEVERITY', 'SWITCH / SCOPE', 'APPLICABILITY', 'EXPOSURE', 'FIX / INSTALLED', 'ASSESSED', ''], findingRows(findings, false, true), 'No findings match these filters. Review inventory coverage and scan completion.'));
        const previous = button('Previous', () => { offset = Math.max(0, offset - limit); refreshResults(); }, 'secondary'); previous.disabled = offset === 0;
        const next = button('Next', () => { offset += limit; refreshResults(); }, 'secondary'); next.disabled = offset + limit >= total;
        panel.append(el('div', { class: 'card-footer' }, el('span', {}, total ? `Showing ${number(offset + 1)}–${number(Math.min(offset + findings.length, total))} of ${number(total)}` : '0 records'), el('div', { class: 'cell-actions' }, previous, next)));
        container.replaceChildren(panel);
      } catch (error) { if (serial === requestSerial) container.replaceChildren(notice(error.message, 'danger')); }
      finally { if (serial === requestSerial) container.setAttribute('aria-busy', 'false'); }
    }
    await refreshResults();
    return el('div', {}, toolbar, notice('By default, this view shows findings with a recorded fix version. Use Fix availability to include findings with no fix recorded. A recorded version still requires target validation before remediation. Applicability describes whether a component is affected; exposure describes deployment conditions.'), container);
  }
  function updateSelection() { const buttonNode = $('#create-plan-button'); if (buttonNode) { buttonNode.replaceChildren(icon('plan'), `Create plan (${state.selectedFindings.size})`); buttonNode.disabled = state.selectedFindings.size === 0; } const batchButton = $('#create-batch-button'); if (batchButton) batchButton.disabled = state.selectedFindings.size === 0; }
  async function createSelectedPlan() {
    const selected = [...state.selectedRecords.values()];
    const devices = new Set(selected.map((finding) => finding.device_id));
    if (devices.size !== 1 || new Set(selected.map((finding) => JSON.stringify([finding.scope, finding.package_name, finding.affected_version]))).size !== 1) { toast('Select one package version and scope on one switch to create a remediation plan.', 'error'); return; }
    await action(async () => { const plan = await api('/plans', { method: 'POST', body: { device_id: selected[0].device_id, finding_ids: selected.map(recordId) } }); state.selectedFindings.clear(); state.selectedRecords.clear(); document.querySelectorAll('.row-select').forEach((input) => { input.checked = false; }); updateSelection(); showPlanData(plan.plan || plan); }, 'Plan created for review.');
  }
  async function showFinding(id) {
    await action(async () => {
      const payload = await api(`/findings/${encodeURIComponent(id)}`); const finding = payload.finding || payload;
      const content = el('div', {}, el('div', { class: 'detail-badges' }, badge(finding.severity), badge(finding.applicability), badge(finding.exposure)), el('div', { class: 'detail-grid' }, field('Component', finding.package_name), field('Installed version', finding.affected_version), field('Switch', finding.hostname || finding.device_id), field('Container / scope', finding.scope), field('Reported CVSS', finding.cvss_score), field('Fixed versions', array(finding.fixed_versions).join(', ') || 'No fix recorded'), field('Advisory source', advisorySource(finding)), field('Last assessed', date(finding.assessed_at)), field('Assessment basis', finding.decision_basis ? pretty(finding.decision_basis) : 'Not recorded'), field('Build provenance', finding.artifact_binding ? badge(finding.artifact_binding) : 'Not recorded'), field('Build evidence policy', finding.build_evidence_policy ? pretty(finding.build_evidence_policy) : 'Not recorded'), field('Analysis processing', finding.assessment_state || 'Not recorded'), field('Provider attempts', number(finding.analysis_attempts)), field('Next provider retry', date(finding.analysis_next_attempt_at))), el('section', { class: 'detail-section' }, el('h3', {}, 'Assessment rationale'), el('p', {}, text(finding.rationale, 'No rationale was recorded.'))), el('section', { class: 'detail-section' }, el('h3', {}, 'Supporting evidence'), evidenceItems(finding.evidence)), el('details', { class: 'detail-section' }, el('summary', {}, 'Inspect full assessment record'), jsonBlock(finding)), el('div', { class: 'detail-actions' }, button('Investigate with evidence', () => investigateFinding(id), 'primary', 'search'), button('External agent review', () => createExternalSession(finding), 'secondary', 'code'), button('Record reviewed verdict', () => reviewFinding(finding), 'secondary', 'check'), button('Create review plan', () => action(async () => { const result = await api('/plans', { method: 'POST', body: { device_id: finding.device_id, finding_ids: [recordId(finding)] } }); showPlanData(result.plan || result); }, 'Plan created for review.'), 'secondary', 'plan')));
      if (inventoryOnlyAssessment(finding)) $('.detail-grid', content).after(notice('Affected based on reported package inventory and an exact distribution advisory match. The installed build is unverified. Record a scoped operator review before approving remediation; this assessment does not authorize automatic installation.', 'warning'));
      if (finding.latest_external_analysis) $('.detail-grid', content).after(externalProposal(finding));
      content.append(el('div', { class: 'detail-actions' }, link('View CVE remediation status', remediationHref(finding))));
      openDetail('FINDING EVIDENCE', finding.cve_id || String(id), content);
    });
  }
  function externalProposal(finding) {
    const proposal = finding.latest_external_analysis;
    return el('section', { class: 'detail-section external-proposal' }, el('h3', {}, 'External agent proposal'), proposal.stale === true ? notice('This proposal belongs to an older or expired case. Create a new agent session for current inventory and evidence before using it in a review.', 'warning') : null, notice(`This is a submitted agent proposal, separate from the reviewed verdict. The current recorded applicability is ${pretty(finding.applicability)}.`), el('div', { class: 'detail-grid' }, field('Proposed applicability', el('span', { class: 'badge purple' }, pretty(proposal.proposed_applicability))), field('Submission workflow', pretty(proposal.source || 'external_agent')), field('Agent attribution', text(proposal.agent_name, 'External agent')), field('Agent identity verification', proposal.agent_identity_verified === true ? 'Verified by service' : 'Self-reported; not provider-verified'), field('Submitted', date(proposal.submitted_at)), field('Investigation session', el('span', { class: 'mono' }, text(proposal.session_id)))), el('p', { class: 'agent-rationale' }, text(proposal.rationale, 'No rationale was recorded.')), el('div', { class: 'pill-row' }, array(proposal.evidence_ids).map((id) => el('span', { class: 'badge mono' }, id))), array(proposal.unknowns).length ? el('div', { class: 'detail-section' }, el('h3', {}, 'Unresolved evidence'), el('ul', { class: 'preflight-list' }, proposal.unknowns.map((unknown) => el('li', {}, text(unknown))))) : null, el('div', { class: 'detail-actions' }, button('Open reviewed-verdict form', () => reviewFinding(finding), 'secondary', 'check')));
  }
  async function createExternalSession(finding) {
    await action(async () => {
      const session = await api(`/findings/${encodeURIComponent(recordId(finding))}/agent-session`, { method: 'POST', body: {} });
      if (!session.session_id) throw new Error('The service did not return an investigation session.');
      showExternalSession(session, finding);
    });
  }
  function showExternalSession(session, finding) {
    const snapshot = session.snapshot || {}; const limits = session.limits || {};
    const bundleText = JSON.stringify(session, null, 2);
    const copyBundle = async () => { try { await navigator.clipboard.writeText(bundleText); toast('Bounded case bundle copied.', 'success'); } catch { toast('Clipboard access is unavailable. Download the case bundle instead.', 'error'); } };
    const downloadBundle = () => { const url = URL.createObjectURL(new Blob([bundleText], { type: 'application/json' })); const anchor = el('a', { href: url, download: `smart-patch-agent-${String(session.session_id).replace(/[^A-Za-z0-9_.-]/g, '_')}.json` }); anchor.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); };
    const content = el('div', {}, el('div', { class: 'detail-badges' }, badge(session.status || 'open'), el('span', { class: 'badge purple' }, pretty(session.source || 'external_agent'))), notice('Give this bounded case to your coding agent that is already signed in. Its cited analysis is recorded as a proposal for separate administrator review; creating a session does not run a model or change the finding.'), el('div', { class: 'detail-grid' }, field('Session ID', el('span', { class: 'mono' }, session.session_id)), field('Expires', date(session.expires_at)), field('Finding / component', `${text(session.finding?.cve_id || finding.cve_id)} / ${text(session.finding?.package_name || finding.package_name)}`), field('Device / scope', `${text(snapshot.device_id)} / ${text(session.finding?.scope_id || session.finding?.scope || finding.scope)}`), field('Build / source revision', el('span', { class: 'mono' }, `${text(snapshot.build_id)} / ${text(snapshot.source_revision)}`)), field('Snapshot binding', el('span', { class: 'mono' }, text(session.snapshot_hash)))), el('div', { class: 'agent-session-limits' }, signal('code', 'Bounded tools', `${number(limits.max_tool_calls)} tool calls · ${number(array(session.tools).length)} available tools`), signal('box', 'Context budget', `${number(limits.max_context_chars)} context characters · ${number(limits.max_response_chars)} response characters`), signal('shield', 'Evidence references', `${number(array(session.evidence).length)} recorded evidence items; submissions must cite approved session evidence.`)), el('section', { class: 'detail-section' }, el('h3', {}, 'Use with your signed-in agent'), el('ol', { class: 'preflight-list' }, el('li', {}, 'Provide the case bundle through the configured external-agent workflow.'), el('li', {}, 'Let the agent request bounded session tools and identify supporting evidence or missing facts.'), el('li', {}, 'Submit the cited proposal through the authenticated session API, then refresh the finding.'), el('li', {}, 'Review the proposal and evidence separately before changing applicability.'))), el('details', { class: 'detail-section' }, el('summary', {}, 'Inspect case bundle and submission schema'), jsonBlock(session)), el('div', { class: 'detail-actions' }, button('Download case bundle', downloadBundle, 'primary', 'box'), button('Copy case bundle', copyBundle, 'secondary'), button('Refresh finding', () => showFinding(recordId(finding)), 'secondary', 'refresh')));
    const proposalForm = el('form');
    const proposalInput = el('textarea', { id: 'external-agent-json', rows: 9, class: 'mono', required: true, maxlength: limits.max_response_chars || 48000, placeholder: 'Paste the agent’s JSON proposal. Case identity is supplied from this session when omitted.' });
    const proposalFile = el('input', { id: 'external-agent-file', type: 'file', accept: '.json,application/json' });
    proposalFile.addEventListener('change', () => action(async () => { const file = proposalFile.files[0]; if (!file) return; const limit = Number(limits.max_response_chars) || 48000; if (file.size > limit * 4) throw new Error('The result file exceeds this session’s response budget.'); const raw = await file.text(); if (raw.length > limit) throw new Error('The result exceeds this session’s response character limit.'); proposalInput.value = raw; }));
    proposalForm.append(el('p', { class: 'muted' }, 'Import or paste the signed-in agent’s result. Submission records its cited proposal; the administrator-reviewed verdict remains separate.'), el('label', { for: 'external-agent-file' }, 'Agent result JSON file · optional'), proposalFile, el('div', { class: 'detail-section' }, el('label', { for: 'external-agent-json' }, 'Agent proposal JSON'), proposalInput), el('div', { class: 'detail-actions' }, el('button', { type: 'submit', class: 'button button-primary' }, icon('code'), 'Submit agent proposal')));
    proposalForm.addEventListener('submit', async (event) => { event.preventDefault(); await action(async () => { let proposal; try { proposal = JSON.parse(proposalInput.value); } catch { throw new Error('The agent proposal must be valid JSON.'); } if (!proposal || Array.isArray(proposal) || typeof proposal !== 'object') throw new Error('The proposal must be a JSON object.'); const payload = { snapshot_hash: session.snapshot_hash, cve_id: session.finding?.cve_id || finding.cve_id, component_id: session.finding?.component_id || finding.component_id, scope_id: session.finding?.scope_id || session.finding?.scope || finding.scope, ...proposal }; const submit = $('button[type=submit]', proposalForm); submit.disabled = true; try { await api(`/agent-sessions/${encodeURIComponent(session.session_id)}/analysis`, { method: 'POST', body: payload }); await showFinding(recordId(finding)); if (page === 'findings') await loadPage(false); } finally { submit.disabled = false; } }, 'Agent proposal recorded for separate administrator review.'); });
    content.append(el('section', { class: 'detail-section' }, el('h3', {}, 'Return an agent proposal'), proposalForm));
    openDetail('EXTERNAL AGENT INVESTIGATION', 'Use your signed-in agent', content);
  }
  function reviewFinding(finding) {
    const evidence = array(finding.evidence);
    const ids = [...new Set([...array(finding.evidence_ids), ...evidence.filter((item) => item && typeof item === 'object').map((item) => item.id)].filter(Boolean))];
    const form = el('form');
    const applicability = el('select', { name: 'applicability', id: 'review-applicability' }, ['under_investigation', 'affected', 'fixed', 'not_affected'].map((value) => el('option', { value }, pretty(value))));
    applicability.value = finding.applicability || 'under_investigation';
    const rationale = el('textarea', { name: 'justification', id: 'review-rationale', rows: 5, minlength: 20, maxlength: 4000, required: true, placeholder: 'Explain the component-specific evidence and how it supports this verdict.' });
    const reference = el('input', { name: 'review_reference', id: 'review-reference', type: 'url', placeholder: 'https://… supporting build or patch evidence' });
    const justification = el('select', { name: 'vex_justification', id: 'review-vex' }, el('option', { value: '' }, 'Choose a justification'), ['component_not_present', 'vulnerable_code_not_present', 'vulnerable_code_not_in_execute_path', 'vulnerable_code_cannot_be_controlled_by_adversary', 'inline_mitigations_already_exist'].map((value) => el('option', { value }, pretty(value))));
    const vexField = el('div', { class: 'form-field full-width' }, el('label', { for: 'review-vex' }, 'OpenVEX justification'), justification);
    const referenceHelp = el('p', { class: 'form-help' });
    function updateRequirements() { const suppressing = ['fixed', 'not_affected'].includes(applicability.value); reference.required = suppressing; referenceHelp.textContent = suppressing ? 'An HTTPS reference to the supporting build or patch evidence is required.' : 'Optional supporting reference.'; vexField.hidden = applicability.value !== 'not_affected'; justification.required = !vexField.hidden; }
    applicability.addEventListener('change', updateRequirements); updateRequirements();
    form.append(notice('This review applies to this device, component, inventory, and runtime context. It expires after 30 days and does not suppress other occurrences of the CVE.'), el('div', { class: 'detail-grid' }, field('CVE', finding.cve_id), field('Switch / scope', `${text(finding.hostname || finding.device_id)} / ${text(finding.scope)}`), field('Component / version', `${text(finding.package_name)} ${text(finding.affected_version)}`), field('Inventory identity', el('span', { class: 'mono' }, text(finding.inventory_digest)))), el('div', { class: 'form-grid detail-section' }, el('div', { class: 'form-field full-width' }, el('label', { for: 'review-applicability' }, 'Reviewed applicability'), applicability), el('div', { class: 'form-field full-width' }, el('label', { for: 'review-rationale' }, 'Evidence-based justification'), rationale), el('div', { class: 'form-field full-width' }, el('label', { for: 'review-reference' }, 'Supporting reference'), reference, referenceHelp), vexField), el('section', { class: 'detail-section' }, el('h3', {}, 'Cite the evidence used in this review'), ids.length ? el('div', { class: 'signal-list' }, ids.map((id) => { const item = evidence.find((record) => record && record.id === id); return el('label', { class: 'checkbox-label' }, el('input', { type: 'checkbox', name: 'evidence_id', value: id }), el('span', {}, el('span', { class: 'mono' }, id), el('span', { class: 'cell-secondary' }, text(item?.title || item?.type || item?.source, 'Recorded evidence')))); })) : notice('No existing evidence IDs are available. Investigate this finding before recording a reviewed verdict.', 'warning')), el('div', { class: 'detail-actions' }, button('Back to evidence', () => showFinding(recordId(finding)), 'secondary'), el('button', { type: 'submit', class: 'button button-primary', disabled: !ids.length }, icon('check'), 'Save scoped review')));
    form.addEventListener('submit', async (event) => { event.preventDefault(); await action(async () => { const selected = [...form.querySelectorAll('input[name=evidence_id]:checked')].map((input) => input.value); if (!selected.length) throw new Error('Select at least one existing evidence record.'); if (reference.required && !reference.value.startsWith('https://')) throw new Error('A supporting HTTPS evidence reference is required.'); const payload = { applicability: applicability.value, justification: rationale.value.trim(), evidence_ids: selected, review_reference: reference.value.trim() }; if (applicability.value === 'not_affected') payload.vex_justification = justification.value; await api(`/findings/${encodeURIComponent(recordId(finding))}/review`, { method: 'POST', body: payload }); await showFinding(recordId(finding)); await loadPage(false); }, 'Scoped applicability review recorded.'); });
    openDetail('ADMINISTRATOR EVIDENCE REVIEW', `Review ${text(finding.cve_id)}`, form);
  }
  async function investigateFinding(id) { await action(async () => { const result = await api(`/findings/${encodeURIComponent(id)}/investigate`, { method: 'POST', body: {} }); toast(`Investigation ${text(result.operation_id)} ${text(result.status, 'queued')}.`, 'success'); }); }
  async function renderCoverage() {
    const [overview, { devices = [] }] = await Promise.all([api('/overview'), api('/devices')]); const summary = overview.summary || {};
    const counts = overview.applicability_counts || {};
    const stats = el('div', { class: 'stat-grid' }, stat('Reported inventory scanned', summary.coverage_pct == null ? '—' : `${Number(summary.coverage_pct).toFixed(0)}%`, 'Declared host/container metadata scopes', 'coverage'), stat('Signed baseline matches', `${number(devices.filter((device) => device.artifact_verified === true).length)} / ${number(devices.length)}`, 'Reported manifest hashes; no runtime attestation', 'box', 'warning'), stat('Unresolved findings', number(summary.findings_unknown), 'Missing or inconclusive evidence', 'search', 'warning'), stat('Fixed findings', number(summary.findings_fixed), 'Retained with supporting evidence', 'check'));
    const distribution = Object.entries(counts); const max = Math.max(1, ...distribution.map(([, value]) => Number(value) || 0));
    return el('div', {}, stats, notice('Coverage is limited to the reported inventory. Firmware, proprietary internals, manually copied binaries, and runtime conditions require their own evidence; absent coverage is not a clean verdict.', 'warning'), card('Inventory freshness', 'Inspect each scope before relying on the finding count.', table(['SWITCH', 'COMPONENTS / SCOPES', 'LAST REPORT', 'INVENTORY', 'COVERAGE'], devices.map((device) => [el('button', { class: 'button-link', onclick: () => showDevice(device.id) }, cell(device.hostname || device.id, device.ip_address)), cell(number(device.components_count), `${number(device.scopes_count)} scopes`), cell(relative(device.last_seen), date(device.last_seen)), cell(device.inventory_digest ? String(device.inventory_digest).slice(0, 16) : 'No digest', device.scan_status), typeof device.coverage === 'object' ? el('span', { class: 'mono' }, JSON.stringify(device.coverage)) : text(device.coverage)]), 'No device inventory has been received.')), el('div', { class: 'full-width-card' }, card('Applicability distribution', 'Separate affected components from fixed, non-applicable, and unresolved findings.', distribution.length ? el('div', { class: 'card-body' }, distribution.map(([name, count]) => el('div', { class: 'distribution-row' }, el('span', { class: 'distribution-name' }, pretty(name)), progress(count / max * 100), el('span', { class: 'distribution-count' }, number(count))))) : empty('No assessment distribution is available.'))));
  }
  function progress(percent) { const bar = el('div', { class: 'progress-fill' }); bar.style.width = `${Math.max(0, Math.min(100, Number(percent) || 0))}%`; return el('div', { class: 'progress-track', role: 'progressbar', 'aria-valuenow': Math.max(0, Math.min(100, Number(percent) || 0)), 'aria-valuemin': 0, 'aria-valuemax': 100 }, bar); }
  function jobProgress(job) {
    const data = job.progress_data || {}; const superseded = data.phase === 'superseded' || job.result?.accepted === false;
    const labels = { preparing: 'Preparing inventory', matching: 'Matching packages', assessing: 'Assessing findings', reviewing_evidence: 'Checking evidence', cached: 'Using current assessment cache', saving: 'Saving assessment', complete: 'Processing complete', superseded: 'Superseded · inventory changed', failed: 'Processing failed' };
    const phase = superseded ? 'superseded' : job.status === 'failed' ? 'failed' : data.phase;
    const label = labels[phase] || (job.status === 'queued' ? 'Waiting for worker' : 'Progress details unavailable');
    const work = [];
    if (phase === 'matching' && data.scope_id) work.push(`Current scope: ${data.scope_id}`);
    if (data.scopes_total != null) work.push(`${number(data.scopes_completed)} / ${number(data.scopes_total)} scopes processed`);
    if (data.packages_matched != null && data.packages_reused != null) work.push(`Packages checked now: ${number(data.packages_matched)} · Package results reused: ${number(data.packages_reused)}`);
    if (data.packages_removed) work.push(`${number(data.packages_removed)} removed packages excluded`);
    if (data.scan_mode === 'assessment_cached') work.push('Complete assessment reused; no new package matching.');
    if (data.findings_total != null) work.push(`${number(data.findings_completed)} / ${number(data.findings_total)} findings assessed`);
    if (phase === 'reviewing_evidence' && data.evidence_completed != null) work.push(`${number(data.evidence_completed)} / ${number(data.findings_total)} evidence checks`);
    const detail = superseded ? 'Finished processing an older inventory; this result is not current.' : phase === 'failed' && data.stopped_phase ? `Stopped during ${labels[data.stopped_phase] || pretty(data.stopped_phase)}` : data.detail;
    return el('div', { class: 'job-progress' }, el('div', { class: 'cell-primary' }, label), progress(job.progress_percentage), el('div', { class: 'progress-text' }, job.progress_percentage == null ? 'Progress not reported' : `${number(job.progress_percentage)}%${data.progress_kind === 'workflow' ? ' workflow progress' : ' reported progress'}`), work.map((line) => el('div', { class: 'job-work' }, line)), detail ? el('div', { class: 'job-work muted' }, detail) : null);
  }
  async function renderChanges() { const response = await api('/changes'); const changes = array(response.changes || response.events); return card('Recorded changes', `${changes.length} events · timestamps use your browser’s local timezone`, timeline(changes, 250, true)); }
  async function renderJobs() {
    const { operations = [] } = await api('/operations');
    return card('Central work queue', 'Workflow progress follows matching, assessment and saving. It is not elapsed time or a package-completion percentage. Work counters show new matching and reuse.', table(['OPERATION', 'TYPE', 'STATUS', 'PROGRESS', 'CREATED', ''], operations.map((job) => [cell(String(recordId(job)).slice(0, 16), job.device_id), pretty(job.operation_type || job.type), badge(job.progress_data?.phase === 'superseded' || job.result?.accepted === false ? 'superseded' : job.status), jobProgress(job), cell(relative(job.created_at), date(job.created_at)), el('button', { class: 'button-link', onclick: () => showJob(recordId(job)) }, 'Inspect')]), 'No analysis jobs have been recorded. Queue a scan from a switch or investigate a finding.'));
  }
  function stopJobWatch() { jobRequestRevision += 1; if (jobWatch) { jobWatch.stopped = true; clearTimeout(jobWatch.timer); jobWatch.controller?.abort(); jobWatch = null; } }
  function jobDetail(job, logs) {
    return el('div', {}, el('div', { class: 'detail-badges' }, badge(job.result?.accepted === false ? 'superseded' : job.status)), jobProgress(job), el('p', { class: 'form-help' }, 'Workflow progress is weighted by stage, not elapsed time. Reused packages have current cached matching evidence; they were not newly sent to the scanner.'), el('div', { class: 'detail-grid' }, field('Operation ID', el('span', { class: 'mono' }, text(recordId(job)))), field('Created', date(job.created_at)), field('Started', date(job.started_at)), field('Completed', date(job.completed_at))), job.error_message ? el('div', { class: 'detail-section' }, notice(job.error_message, 'danger')) : null, el('section', { class: 'detail-section' }, el('h3', {}, 'Worker log'), jsonBlock(logs, true)), el('section', { class: 'detail-section' }, el('h3', {}, 'Result'), jsonBlock(job.result)));
  }
  async function showJob(id) {
    stopJobWatch(); const requestRevision = jobRequestRevision;
    await action(async () => {
      const endpoint = `/operations/${encodeURIComponent(id)}`;
      const [response, logResponse] = await Promise.all([api(endpoint), api(`${endpoint}/logs`)]);
      if (requestRevision !== jobRequestRevision) return;
      let job = response.operation || response;
      const content = el('div', {}, jobDetail(job, logResponse.logs)); const feedback = el('p', { class: 'form-help', role: 'status' });
      const refreshButton = button('Refresh progress', () => refresh(), 'secondary', 'refresh');
      openDetail('ANALYSIS JOB', pretty(job.operation_type || job.type || 'Operation'), el('div', {}, el('div', { class: 'detail-actions' }, refreshButton), feedback, content));
      const watch = { stopped: false, busy: false, timer: null, controller: null }; jobWatch = watch;
      const active = () => ['queued', 'in_progress', 'running'].includes(job.status);
      const schedule = () => { if (jobWatch === watch && !watch.stopped && active()) watch.timer = setTimeout(refresh, 5000); };
      async function refresh() {
        if (jobWatch !== watch || watch.stopped || !$('#detail-dialog').open || watch.busy) return;
        clearTimeout(watch.timer);
        if (document.hidden) { schedule(); return; }
        watch.busy = true; refreshButton.disabled = true; watch.controller = new AbortController();
        try {
          const [next, logs] = await Promise.all([api(endpoint, { signal: watch.controller.signal }), api(`${endpoint}/logs`, { signal: watch.controller.signal })]);
          if (jobWatch !== watch || watch.stopped || !$('#detail-dialog').open) return;
          job = next.operation || next;
          const dialog = $('#detail-dialog'); const scroll = dialog.scrollTop;
          content.replaceChildren(jobDetail(job, logs.logs)); dialog.scrollTop = scroll;
          feedback.textContent = active() ? 'Progress refreshes every 5 seconds while this view is visible.' : 'Operation finished. Latest recorded result shown.';
        } catch (error) { if (jobWatch === watch && !watch.stopped && error.name !== 'AbortError') feedback.textContent = `Progress refresh unavailable: ${error.message}`; }
        finally { watch.busy = false; refreshButton.disabled = false; schedule(); }
      }
      feedback.textContent = active() ? 'Progress refreshes every 5 seconds while this view is visible.' : 'Latest recorded result shown.';
      schedule();
    });
  }
  function remediationHref(row = {}) {
    const query = new URLSearchParams();
    for (const key of ['device_id', 'cve_id', 'scope']) if (row[key]) query.set(key, row[key]);
    return `/ui/remediation-status${query.size ? `?${query}` : ''}`;
  }
  function remediationOrigin(row) { return row.origin === 'cli' ? 'Switch CLI' : row.origin === 'service' ? 'Intelligence service' : 'Inventory finding'; }
  function remediationActive(row) { return ['planned', 'draft', 'approved', 'staging_queued', 'staging', 'downloading', 'downloaded', 'staged', 'queued', 'executing', 'installing', 'installed', 'restarting', 'pending_reassessment'].includes(row.state); }
  function centralResolutionSummary(row) {
    const result = row.central_resolution || {};
    const verified = row.state === 'resolved' && result.status === 'completed' && row.current_matching_finding === false;
    if (row.state === 'reopened') return el('div', {}, badge('reopened'), el('span', { class: 'cell-secondary' }, 'This CVE is reported again for the package occurrence. Earlier resolution does not clear the current finding.'));
    if (!verified && ['completed', 'resolved'].includes(result.status)) return el('div', {}, badge('pending_reassessment'), el('span', { class: 'cell-secondary' }, 'A recorded scan outcome does not establish resolution for the current operation state. Refresh the record for current central evidence.'));
    return el('div', {}, badge(verified ? 'resolved' : result.status || 'not_assessed'), el('span', { class: 'cell-secondary' }, text(result.reason, verified ? 'Selected CVE absent from the accepted scan for this package and scope.' : 'Installation alone does not establish resolution.')));
  }
  async function renderRemediationStatus() {
    remediationViewCleanup?.();
    const original = new URLSearchParams(location.search);
    const filters = state.remediationFilters || { device_id: original.get('device_id') || '', cve_id: original.get('cve_id') || '', scope: original.get('scope') || '', status: original.get('status') || '', offset: 0 };
    state.remediationFilters = filters;
    const root = el('div', { class: 'remediation-status-view' }); const results = el('div', { 'aria-live': 'polite' });
    const feedback = el('p', { class: 'form-help', role: 'status' }); const toolbar = el('div', { class: 'toolbar remediation-filters' });
    const { devices = [] } = await api('/devices');
    let timer = null, debounce = null, request = null, serial = 0, disposed = false, rows = [];
    const limit = 50;
    const cleanup = () => { disposed = true; clearTimeout(timer); clearTimeout(debounce); request?.abort(); };
    remediationViewCleanup = cleanup;
    const changed = () => { filters.offset = 0; clearTimeout(debounce); debounce = setTimeout(() => refresh(), 250); };
    const deviceSelect = el('select', { 'aria-label': 'Remediation switch', onchange: (event) => { filters.device_id = event.target.value; changed(); } }, el('option', { value: '' }, 'All switches'), devices.map((device) => el('option', { value: device.id }, device.hostname || device.id)));
    if (filters.device_id && !devices.some((device) => device.id === filters.device_id)) deviceSelect.append(el('option', { value: filters.device_id }, filters.device_id));
    deviceSelect.value = filters.device_id;
    const cveInput = el('input', { type: 'search', 'aria-label': 'Remediation CVE', placeholder: 'CVE ID or prefix', value: filters.cve_id, oninput: (event) => { filters.cve_id = event.target.value.trim(); changed(); } });
    const scopeInput = el('input', { type: 'search', 'aria-label': 'Remediation scope', placeholder: 'Scope: host or container:pmon', value: filters.scope, oninput: (event) => { filters.scope = event.target.value.trim(); changed(); } });
    const statuses = ['no_plan', 'planned', 'approved', 'staging_queued', 'staging', 'downloading', 'downloaded', 'staged', 'queued', 'installing', 'installed', 'restarting', 'pending_reassessment', 'resolved', 'failed', 'denied', 'unknown', 'requires_revalidation', 'superseded', 'reopened', 'no_longer_reported', 'cancelled', 'expired', 'rolled_back', 'rollback_failed', 'rollback_unknown', 'staging_failed'];
    const stateSelect = el('select', { 'aria-label': 'Remediation state', onchange: (event) => { filters.status = event.target.value; changed(); } }, el('option', { value: '' }, 'All states'), statuses.map((status) => el('option', { value: status }, pretty(status))));
    if (filters.status && !statuses.includes(filters.status)) stateSelect.append(el('option', { value: filters.status }, pretty(filters.status)));
    stateSelect.value = filters.status;
    toolbar.append(deviceSelect, cveInput, scopeInput, stateSelect, button('Refresh status', () => refresh(), 'secondary', 'refresh'));
    root.append(notice('Package operations and vulnerability outcomes are tracked separately. Resolved means a fresh accepted central scan no longer reports the selected CVE for that package and scope. Historical attempts remain visible even after a finding leaves the active findings list.'), toolbar, feedback, results);
    function schedule() {
      clearTimeout(timer);
      if (!disposed && rows.some(remediationActive)) timer = setTimeout(async () => {
        if (disposed || !root.isConnected) return;
        if (document.hidden || document.querySelector('dialog[open]') || !state.token) { schedule(); return; }
        await refresh(true);
      }, 5000);
    }
    async function refresh(automatic = false) {
      clearTimeout(timer); request?.abort(); const sequence = ++serial; request = new AbortController();
      const query = new URLSearchParams({ limit: String(limit), offset: String(filters.offset) });
      for (const key of ['device_id', 'cve_id', 'scope', 'status']) if (filters[key]) query.set(key, filters[key]);
      results.setAttribute('aria-busy', 'true');
      try {
        const response = await api(`/remediation-status?${query}`, { signal: request.signal });
        if (disposed || sequence !== serial) return;
        rows = array(response.items); const total = Number(response.total || 0);
        feedback.textContent = `${number(total)} matching CVE records. ${rows.some(remediationActive) ? 'Active records refresh every 5 seconds while this page is visible.' : 'Showing the last recorded state. Use Refresh status to check for new activity.'}`;
        const tableRows = rows.map((row) => [cell(row.cve_id, row.package_name, true), cell(row.hostname || row.device_id, row.scope), el('div', {}, badge(row.state), el('span', { class: 'cell-secondary' }, row.collector_state ? `Collector: ${pretty(row.collector_state)}` : 'No collector operation recorded')), cell(row.target_version || 'No target', row.observed_version ? `Observed ${row.observed_version}` : row.from_version ? `Before ${row.from_version}` : null), centralResolutionSummary(row), cell(remediationOrigin(row), relative(row.updated_at)), button('Inspect status', () => showRemediationStatus(row), 'quiet')]);
        const previous = button('Previous', () => { filters.offset = Math.max(0, filters.offset - limit); refresh(); }, 'quiet'); previous.disabled = filters.offset === 0;
        const next = button('Next', () => { filters.offset += limit; refresh(); }, 'quiet'); next.disabled = filters.offset + limit >= total;
        results.replaceChildren(card('CVE remediation records', 'One record per selected CVE and package occurrence. Multiple attempts have separate histories.', table(['CVE / PACKAGE', 'SWITCH / SCOPE', 'CURRENT STATE', 'TARGET / OBSERVED', 'CENTRAL REASSESSMENT', 'ORIGIN / UPDATED', ''], tableRows, 'No remediation records match these filters. Clear a filter or collect fresh inventory.')), el('div', { class: 'pagination' }, previous, el('span', {}, total ? `${filters.offset + 1}–${Math.min(filters.offset + limit, total)} of ${number(total)}` : '0 records'), next));
        schedule();
      } catch (error) {
        if (disposed || sequence !== serial || error.name === 'AbortError') return;
        feedback.textContent = `${automatic ? 'Automatic refresh stopped' : 'Status could not be loaded'}: ${error.message}. The last recorded data is still shown. Use Refresh status to retry.`;
        if (!rows.length) results.replaceChildren(empty('Remediation status is unavailable.'));
      } finally { if (!disposed && sequence === serial) results.removeAttribute('aria-busy'); }
    }
    await refresh(); return root;
  }
  function stopRemediationWatch() { if (remediationWatch) { clearTimeout(remediationWatch.timer); remediationWatch.controller?.abort(); remediationWatch = null; } }
  async function refreshRemediationRecord(row, watch = null) {
    const query = new URLSearchParams({ record_id: row.id, device_id: row.device_id, cve_id: row.cve_id, scope: row.scope, limit: '1' });
    const response = await api(`/remediation-status?${query}`, watch ? { signal: watch.controller.signal } : {});
    const updated = array(response.items).find((item) => item.id === row.id);
    if (!updated) throw new Error('This attempt was not returned. Refresh the status list to locate its recorded history.');
    return updated;
  }
  function watchRemediationRecord(row) {
    if (!remediationActive(row)) return;
    const watch = { timer: null, controller: null, snapshot: JSON.stringify(row) }; remediationWatch = watch;
    const schedule = () => { if (remediationWatch === watch) watch.timer = setTimeout(poll, 5000); };
    async function poll() {
      if (remediationWatch !== watch || !$('#detail-dialog').open) return;
      if (document.hidden || $('#auth-dialog').open || !state.token) { schedule(); return; }
      watch.controller = new AbortController();
      try {
        const updated = await refreshRemediationRecord(row, watch);
        if (remediationWatch !== watch || !$('#detail-dialog').open) return;
        if (JSON.stringify(updated) !== watch.snapshot) { showRemediationStatus(updated, true); return; }
      } catch (error) {
        if (remediationWatch !== watch || error.name === 'AbortError') return;
        $('#detail-content').append(notice(`Automatic status refresh stopped: ${error.message} The last recorded evidence is still shown.`, 'warning'));
        stopRemediationWatch(); return;
      }
      schedule();
    }
    schedule();
  }
  function showRemediationStatus(row, preserveView = false) {
    const dialog = $('#detail-dialog'); const scroll = dialog.scrollTop;
    const opened = preserveView ? [...dialog.querySelectorAll('details')].map((node) => node.open) : [];
    const result = row.central_resolution || {};
    const content = el('div', {}, el('div', { class: 'detail-badges' }, badge(row.state), el('span', { class: 'badge' }, remediationOrigin(row))), el('div', { class: 'detail-grid' }, field('Switch / scope', `${text(row.hostname || row.device_id)} / ${text(row.scope)}`), field('Package', row.package_name), field('Before → target version', `${text(row.from_version)} → ${text(row.target_version)}`), field('Observed version', row.observed_version), field('Collector state', row.collector_state ? pretty(row.collector_state) : 'No operation reported'), field('Updated', date(row.updated_at)), field('Recorded finding applicability', row.applicability ? badge(row.applicability) : 'No recorded verdict'), field('Plan ID', row.plan_id || row.local_plan_id || 'No plan'), field('Current matching finding', row.current_matching_finding === true ? 'Still reported' : row.current_matching_finding === false ? 'Not currently reported; see reassessment evidence' : 'Not established')));
    if (row.origin === 'cli') content.append(notice('This is a switch CLI operation reported by the authenticated collector. Its local approval and package receipts are read-only here; the intelligence service separately verifies the CVE outcome.'));
    content.append(el('section', { class: 'detail-section' }, el('h3', {}, 'Central vulnerability reassessment'), centralResolutionSummary(row), el('div', { class: 'detail-grid' }, field('Scan completed', date(result.scan_completed_at)), field('Reassessment checked', date(result.checked_at)), field('Assessment revision', result.assessment_revision), field('Scanner database revision', result.scanner_db_revision)), el('p', { class: 'form-help' }, 'A fixed applicability verdict or successful package command is separate from verified resolution of this recorded attempt. An earlier resolved attempt does not clear a newer finding.')));
    const progress = row.progress || {};
    const events = array(progress.events || progress.steps || row.steps).filter((event) => event && typeof event === 'object' && !Array.isArray(event));
    if (Object.keys(progress).length || events.length) content.append(el('section', { class: 'detail-section' }, el('h3', {}, 'Collector progress'), progress.phase ? badge(progress.phase) : null, events.length ? table(['STEP', 'REPORTED AT', 'DETAILS'], events.map((event) => [pretty(event.phase || event.state || event.status), date(event.at || event.updated_at || event.timestamp), text(event.message || event.reason)])) : el('p', { class: 'form-help' }, 'Only the latest reported phase is available.'), el('details', {}, el('summary', {}, 'Inspect progress record'), jsonBlock(progress))));
    for (const [label, report] of [['Staging receipt', row.staging_result], ['Installation receipt', row.execution_result]]) if (report) content.append(maintenanceCheckSummary(report), containerRestartSummary(report), el('details', { class: 'detail-section' }, el('summary', {}, label), jsonBlock(report)));
    if (row.rollback) content.append(el('details', { class: 'detail-section' }, el('summary', {}, 'Rollback source and verification'), jsonBlock(row.rollback)));
    content.append(el('details', { class: 'detail-section' }, el('summary', {}, 'Full remediation status record'), jsonBlock(row)), el('div', { class: 'detail-actions' }, row.origin === 'service' && row.plan_id ? button('Review service plan', () => showPlan(row.plan_id), 'secondary', 'plan') : null, row.finding_id && row.current_matching_finding !== false ? button('Inspect current finding', () => showFinding(row.finding_id), 'secondary', 'search') : null, button('Inspect switch', () => showDevice(row.device_id), 'quiet', 'fleet'), button('Refresh this record', () => action(async () => showRemediationStatus(await refreshRemediationRecord(row), true)), 'secondary', 'refresh')));
    openDetail('CVE REMEDIATION STATUS', text(row.cve_id), content);
    if (preserveView) { [...dialog.querySelectorAll('details')].forEach((node, index) => { node.open = Boolean(opened[index]); }); dialog.scrollTop = scroll; }
    watchRemediationRecord(row);
  }
  async function renderPlans() {
    const [{ plans = [] }, { batches = [] }] = await Promise.all([api('/plans'), api('/remediation-batches')]);
    return el('div', {}, notice('Eligible host packages and supported container packages in switch maintenance mode can be staged and installed with explicit approval. Container installation restarts the target container. Image and protected component changes require a manual runbook. All package changes need fresh inventory and central reassessment before resolution.'), el('div', { class: 'detail-actions' }, link('View CVE remediation status', '/ui/remediation-status')), card('Switch remediation batches', 'Approve preparation together, then separately authorize the staged switches. Progress is retained across browser and service restarts.', table(['BATCH', 'SWITCHES', 'PROGRESS', 'STATUS', 'CREATED', ''], batches.map((batch) => [cell(batch.name || String(batch.id).slice(0, 12), `${batch.max_concurrent_switches} at a time`), number(new Set(array(batch.entries).map((entry) => entry.device_id)).size), batchProgress(batch), badge(batch.status), relative(batch.created_at), button('Review batch', () => showBatch(batch.id), 'quiet')]), 'No batches yet. Select findings across switches, then choose Remediate selected switches.'), link('Select findings', '/ui/findings')), el('div', { class: 'full-width-card' }, card('Maintenance plans', 'Inspect the workflow type, recorded review and collector results.', table(['PLAN / PACKAGE', 'SWITCH / SCOPE', 'TARGET', 'STAGING', 'STATUS', 'CREATED', ''], plans.map((plan) => [cell(plan.title || String(recordId(plan)).slice(0, 16), plan.package_name), cell(plan.hostname || plan.device_id, plan.scope), cell(plan.target_version, [plan.reassessment?.observed_version ? `Observed ${plan.reassessment.observed_version}` : '', plan.from_version ? `Before ${plan.from_version}` : ''].filter(Boolean).join(' · ') || null), badge(stagingLabel(plan)), badge(plan.status), relative(plan.created_at), el('button', { class: 'button-link', onclick: () => showPlan(recordId(plan)) }, 'Review')]), 'No plans yet. Select findings from one package and scope to prepare a review.'))));
  }
  function batchProgress(batch) {
    const entries = array(batch.entries); const completed = entries.filter((entry) => entry.status === 'completed').length;
    return cell(`${completed} / ${entries.length} completed`, `${entries.filter((entry) => ['failed', 'denied', 'unknown', 'execution_failed', 'rollback_failed', 'staging_failed'].includes(entry.status)).length} failed · ${entries.filter((entry) => ['blocked', 'excluded', 'skipped'].includes(entry.status)).length} skipped or blocked`);
  }
  function batchTerminal(batch) { return ['stopped', 'completed', 'completed_with_failures'].includes(batch.status); }
  function batchEntryPlan(entry) { return entry.plan || {}; }
  function batchSelectable(entry, draft) { return Boolean(entry.plan_id) && (draft ? entry.eligibility === 'eligible' : entry.status === 'staged' && batchEntryPlan(entry).execution_eligible === true); }
  function batchEntryReason(entry) {
    const plan = batchEntryPlan(entry); const report = plan.execution_result || plan.staging_result || plan.stage_result;
    const details = report?.value?.details || report?.details; const error = typeof details === 'string' ? details : details?.error || details?.rollback_error;
    return text(error || entry.error || entry.reason, entry.eligibility === 'eligible' ? 'Eligible package'  : pretty(entry.eligibility || entry.status));
  }
  function batchComponentCell(entry) { return el('div', {}, cell(entry.package_name, entry.scope), array(entry.cve_ids).length ? el('span', { class: 'cell-secondary' }, entry.cve_ids.join(', ')) : null); }
  async function createSelectedBatch() {
    const trigger = $('#create-batch-button'); if (trigger?.disabled) return;
    if (trigger) trigger.disabled = true;
    const findingIds = [...state.selectedFindings].sort(); const selectionKey = JSON.stringify(findingIds);
    if (batchDraftAttempt?.selectionKey !== selectionKey) batchDraftAttempt = { selectionKey, id: crypto.randomUUID() };
    try { await action(async () => { const batch = await api('/remediation-batches', { method: 'POST', body: { finding_ids: findingIds, max_concurrent_switches: 1, pause_on_failure: true, idempotency_key: batchDraftAttempt.id } }); batchDraftAttempt = null; showBatchData(batch.batch || batch); }, 'Batch prepared for review. No switch action has been requested.'); }
    finally { if (trigger?.isConnected) trigger.disabled = !state.selectedFindings.size; }
  }
  async function showBatch(id) { stopBatchWatch(); stopPlanWatch(); await action(async () => { const result = await api(`/remediation-batches/${encodeURIComponent(id)}`); showBatchData(result.batch || result); }); }
  async function batchAction(batch, endpoint, payload = {}, message = null, method = 'POST') {
    const id = String(batch.id); if (pendingBatches.has(id)) return null;
    pendingBatches.add(id); stopBatchWatch();
    const content = $('#detail-content'); const controls = [...content.querySelectorAll('button,input,select')].map((node) => [node, node.disabled]);
    controls.forEach(([node]) => { node.disabled = true; }); content.setAttribute('aria-busy', 'true');
    let updated = null;
    try { await action(async () => { const response = await api(`/remediation-batches/${encodeURIComponent(id)}${endpoint ? `/${endpoint}` : ''}`, { method, body: { expected_revision: batch.revision, ...payload } }); updated = response.batch || response; showBatchData(updated); if (page === 'plans') await loadPage(false); }, message); }
    finally { pendingBatches.delete(id); content.removeAttribute('aria-busy'); controls.forEach(([node, disabled]) => { if (node.isConnected) node.disabled = disabled; }); }
    return updated;
  }
  function batchEntryEvidence(entry) {
    return el('div', { class: 'cell-actions' }, entry.plan_id ? button('View plan', () => showPlan(entry.plan_id), 'quiet') : null, array(entry.finding_ids).map((id, index) => button(array(entry.finding_ids).length === 1 ? 'Finding evidence' : `Finding ${index + 1}`, () => showFinding(id), 'quiet')));
  }
  function showBatchData(batch, selectedBefore = null, preserveView = false) {
    const dialog = $('#detail-dialog'); const scroll = dialog.scrollTop;
    const focused = document.activeElement; const focusId = focused?.id;
    const draft = batch.status === 'draft'; const entries = array(batch.entries);
    const selected = new Set(selectedBefore === null ? entries.filter((entry) => batchSelectable(entry, draft)).map((entry) => entry.plan_id) : [...selectedBefore].filter((id) => entries.some((entry) => entry.plan_id === id && batchSelectable(entry, draft))));
    const content = el('div', { class: 'batch-detail' }, el('div', { class: 'detail-badges' }, badge(batch.status)), el('div', { class: 'detail-grid' }, field('Batch ID', el('span', { class: 'mono' }, batch.id)), field('Switches at a time', batch.max_concurrent_switches), field('Pause after a failure', batch.pause_on_failure ? 'Enabled' : 'Disabled'), field('Progress', batchProgress(batch))));
    if (draft) content.append(notice('Review one package occurrence per switch. Several CVEs affecting that occurrence can share its plan. Excluded or blocked rows stay in the batch record. Approve and stage only prepares packages; installation requires a separate confirmation.'));
    else content.append(notice('Each switch retains its own plan and result. A successful package installation remains pending until fresh inventory and a central scan reassess the selected CVEs.'));
    if (['paused', 'stopping', 'stopped'].includes(batch.status)) content.append(notice(batch.reason || batch.pause_reason || 'New dispatch is stopped. Work already queued on a switch may finish. Inspect every switch result before continuing.', 'warning'));
    if (batch.error) content.append(notice(text(batch.error), 'danger'));
    const settings = el('form', { class: 'form-grid detail-section batch-settings' }, formField('Batch name', 'name', { value: batch.name || '', required: true, maxlength: 160 }), formField('Switches at a time', 'max_concurrent_switches', { type: 'number', min: 1, max: 10, required: true, value: batch.max_concurrent_switches || 1 }), el('label', { class: 'checkbox-label full-width' }, el('input', { name: 'pause_on_failure', type: 'checkbox', checked: batch.pause_on_failure !== false }), 'Pause new dispatch after a failure'), el('div', { class: 'detail-actions full-width' }, el('button', { class: 'button button-secondary', type: 'submit' }, 'Save batch settings')));
    settings.addEventListener('submit', async (event) => { event.preventDefault(); await batchAction(batch, '', { name: $('input[name=name]', settings).value.trim(), max_concurrent_switches: Number($('input[name=max_concurrent_switches]', settings).value), pause_on_failure: $('input[name=pause_on_failure]', settings).checked }, 'Batch settings saved.', 'PATCH'); });
    if (draft) content.append(settings);
    const rowInputs = []; const targetInputs = [];
    const rows = entries.map((entry) => {
      const input = el('input', { id: `batch-entry-${entry.id}`, type: 'checkbox', checked: selected.has(entry.plan_id), disabled: !batchSelectable(entry, draft), 'aria-label': `Select ${text(entry.hostname || entry.device_id)} ${text(entry.package_name)} for ${draft ? 'staging' : 'execution'}`, onchange: () => { if (input.checked) selected.add(entry.plan_id); else selected.delete(entry.plan_id); updateControls(); } }); rowInputs.push(input);
      const options = array(entry.target_options || entry.plan?.target_resolution?.target_options); const versions = [...new Set([entry.target_version, ...options.map((option) => typeof option === 'string' ? option : option.version)].filter(Boolean))];
      let target = cell(entry.target_version || 'No target', entry.from_version ? `Installed ${entry.from_version}` : null);
      if (draft && entry.plan_id && versions.length > 1) {
        const select = el('select', { 'aria-label': `Target version for ${text(entry.hostname || entry.device_id)} ${text(entry.package_name)}`, 'data-entry-id': entry.id }, versions.map((version) => el('option', { value: version }, version))); select.value = entry.target_version || ''; targetInputs.push(select);
        select.addEventListener('change', updateControls); target = el('div', {}, select, el('span', { class: 'cell-secondary' }, `Installed ${text(entry.from_version)}`));
      }
      const plan = batchEntryPlan(entry); const report = plan.execution_result || plan.staging_result || plan.stage_result; const details = report?.value?.details || report?.details || {};
      const evidence = el('details', { class: 'batch-entry-details' }, el('summary', {}, 'Evidence & recorded checks'), batchEntryEvidence(entry), options.length ? table(['TARGET', 'CENTRAL CHECK', 'REPOSITORY'], options.map((option) => [typeof option === 'string' ? option : option.version, typeof option === 'string' ? 'Not recorded' : pretty(option.status || 'not_recorded'), typeof option === 'string' ? 'Not recorded' : pretty(option.repository_availability || 'unknown')])) : null, maintenanceCheckSummary(report), plan.reassessment ? reassessmentSummary(plan) : null);
      const outcome = el('div', {}, badge(entry.status), el('span', { class: 'cell-secondary' }, batchEntryReason(entry)), details.maintenance_checks_enabled === false ? el('span', { class: 'cell-secondary' }, 'Optional checks skipped') : null, details.rollback_available === false ? el('span', { class: 'cell-secondary danger-text' }, 'Automatic rollback unavailable') : null);
      return [input, cell(entry.hostname || entry.device_id, entry.device_id), batchComponentCell(entry), target, outcome, evidence];
    });
    content.append(el('section', { class: 'detail-section' }, el('h3', {}, 'Switch targets and outcomes'), table(['SELECT', 'SWITCH', 'PACKAGE / SCOPE', 'INSTALLED → TARGET', 'OUTCOME / ELIGIBILITY', 'DETAILS'], rows, 'No selected findings could be resolved.')));
    const selectionSummary = el('p', { class: 'form-help batch-selection-summary', role: 'status' }); const controls = el('div', { class: 'maintenance-controls batch-controls' });
    const saveTargets = button('Save target selections', () => batchAction(batch, '', { target_versions: Object.fromEntries(targetInputs.map((input) => [input.dataset.entryId, input.value])) }, 'Targets refreshed. Review the updated eligibility before staging.', 'PATCH'), 'secondary');
    const approve = button('Approve and stage selected switches', () => batchAction(batch, 'approve-and-stage', { confirmed_plan_ids: [...selected] }, 'Review recorded. Selected switches will prepare packages; no installation is authorized.'), 'primary', 'check');
    const execute = button('Review execution for selected switches', () => confirmBatchExecution(batch, entries.filter((entry) => selected.has(entry.plan_id))), 'primary', 'shield');
    function updateControls() {
      const changedTargets = targetInputs.some((input) => input.value !== entries.find((entry) => entry.id === input.dataset.entryId)?.target_version);
      const chosen = entries.filter((entry) => selected.has(entry.plan_id)); const unique = new Set(chosen.map((entry) => entry.device_id)).size === chosen.length;
      selectionSummary.textContent = changedTargets ? 'Save target selections, then review refreshed eligibility before approving.' : `${selected.size} switch${selected.size === 1 ? '' : 'es'} selected${unique ? '.' : '. Select only one package occurrence per switch.'}`;
      approve.disabled = !draft || !selected.size || !unique || changedTargets; saveTargets.disabled = !changedTargets;
      execute.disabled = draft || !selected.size || !unique || batchTerminal(batch) || ['paused', 'stopping'].includes(batch.status);
    }
    if (draft) { if (targetInputs.length) controls.append(saveTargets); controls.append(approve, button('Refresh eligibility', () => batchAction(batch, 'refresh', {}, 'Eligibility refreshed. Review the new plans before approval.'), 'secondary', 'refresh')); }
    else if (!batchTerminal(batch)) controls.append(execute);
    if (!draft && !batchTerminal(batch) && batch.status !== 'stopping') {
      if (batch.status === 'paused') controls.append(button('Resume new dispatch', () => confirmBatchControl(batch, 'resume'), 'secondary'));
      else controls.append(button('Pause new dispatch', () => confirmBatchControl(batch, 'pause'), 'secondary'));
    }
    if (!batchTerminal(batch) && batch.status !== 'stopping') controls.append(button('Stop remaining dispatch', () => confirmBatchControl(batch, 'stop'), 'secondary'));
    controls.append(button('Refresh batch', () => showBatch(batch.id), 'secondary', 'refresh'));
    updateControls(); content.append(selectionSummary, controls, el('p', { class: 'form-help' }, 'Pause and stop affect new dispatch only. Already queued work may finish. Failed execution is never retried automatically; inspect the result and current inventory before creating another plan.'));
    openDetail('MULTI-SWITCH REMEDIATION', batch.name || 'Remediate selected switches', content);
    if (preserveView) { if (focusId) document.getElementById(focusId)?.focus({ preventScroll: true }); dialog.scrollTop = scroll; }
    watchBatch(batch, selected);
  }
  function confirmBatchExecution(batch, entries) {
    if (!entries.length || entries.some((entry) => !batchSelectable(entry, false))) { toast('Select successfully staged switches before requesting execution.', 'error'); return; }
    const phrase = `EXECUTE ${entries.length} SWITCHES`; const form = el('form');
    form.append(notice(`This authorizes installation only on the ${entries.length} staged switches below, up to ${batch.max_concurrent_switches} at a time. Later-staged switches require a separate confirmation.`, 'warning'), table(['SWITCH', 'PACKAGE / SCOPE', 'INSTALLED → TARGET'], entries.map((entry) => [cell(entry.hostname || entry.device_id, entry.device_id), batchComponentCell(entry), `${text(entry.from_version)} → ${text(entry.target_version)}`])));
    if (entries.some((entry) => String(entry.scope || '').startsWith('container:'))) form.append(notice('Each selected container package change automatically restarts its target container. Switch maintenance mode must remain enabled. The patch is in the writable layer and can be lost when the container is recreated; traffic drain is an operator responsibility.', 'warning'));
    for (const entry of entries) { const plan = batchEntryPlan(entry); form.append(el('section', { class: 'detail-section' }, el('h3', {}, text(entry.hostname || entry.device_id)), maintenanceCheckSummary(plan.execution_result || plan.staging_result || plan.stage_result) || notice('Detailed optional-check and rollback results were not reported. Inspect the switch plan before proceeding.', 'warning'), el('details', {}, el('summary', {}, 'Recorded staging receipt'), jsonBlock(plan.staging_result || plan.stage_result || plan.execution_result)))); }
    const confirmation = el('input', { id: 'batch-execution-confirmation', 'aria-label': 'Confirm selected switch execution', required: true, autocomplete: 'off', placeholder: phrase });
    form.append(el('div', { class: 'detail-section' }, el('label', { for: confirmation.id }, `Type ${phrase} to confirm`), confirmation), el('div', { class: 'detail-actions' }, button('Back to batch', () => showBatch(batch.id), 'secondary'), el('button', { type: 'submit', class: 'button button-danger' }, 'Request execution on selected switches')));
    form.addEventListener('submit', async (event) => { event.preventDefault(); if (confirmation.value.trim() !== phrase) { toast(`Type ${phrase} exactly to confirm these switches.`, 'error'); return; } await batchAction(batch, 'execute', { confirmed_plan_ids: entries.map((entry) => entry.plan_id), confirmed_device_ids: entries.map((entry) => entry.device_id) }, 'Execution authorized for the reviewed switches. Follow each recorded outcome and reassessment.'); });
    openDetail('AUTHORIZE STAGED SWITCH CHANGES', 'Confirm batch execution', form);
  }
  function confirmBatchControl(batch, operation) {
    const labels = { pause: 'Pause new dispatch', resume: 'Resume new dispatch', stop: 'Stop remaining dispatch' };
    const explanation = operation === 'resume' ? 'Resume dispatch for work already authorized in this batch. Failed or denied execution will not be retried. Already queued work may still be running.' : operation === 'stop' ? 'Stop dispatching remaining work in this batch. This cannot cancel actions already queued on a switch, and those actions may finish. Stopped entries require a new plan to proceed.' : 'Pause new dispatch. Actions already queued on switches may finish; this does not interrupt an installation or roll it back.';
    openDetail('BATCH DISPATCH CONTROL', labels[operation], el('div', {}, notice(explanation, 'warning'), el('div', { class: 'detail-actions' }, button('Back to batch', () => showBatch(batch.id), 'secondary'), button(`Confirm ${operation}`, () => batchAction(batch, operation, {}, `${labels[operation]} requested. Inspect in-flight switch outcomes.`), operation === 'stop' ? 'danger' : 'primary'))));
  }
  function stopBatchWatch() { if (!batchWatch) return; clearTimeout(batchWatch.timer); batchWatch.controller?.abort(); batchWatch = null; }
  function watchBatch(batch, selected) {
    if (batch.status === 'draft' || batchTerminal(batch)) return;
    const watch = { id: String(batch.id), snapshot: JSON.stringify(batch), timer: null, controller: null }; batchWatch = watch;
    const schedule = () => { if (batchWatch === watch) watch.timer = setTimeout(poll, 5000); };
    async function poll() {
      const dialog = $('#detail-dialog'); if (batchWatch !== watch || !dialog.open) return;
      if (document.hidden || $('#auth-dialog').open || pendingBatches.has(watch.id)) { schedule(); return; }
      watch.controller = new AbortController();
      try { const response = await api(`/remediation-batches/${encodeURIComponent(watch.id)}`, { signal: watch.controller.signal }); if (batchWatch !== watch || !dialog.open) return; const updated = response.batch || response; if (JSON.stringify(updated) !== watch.snapshot) { showBatchData(updated, selected, true); return; } }
      catch (error) { if (batchWatch !== watch || !dialog.open || error.name === 'AbortError') return; $('.batch-controls', dialog)?.after(el('p', { class: 'form-help batch-refresh-error', role: 'status' }, `Automatic status refresh failed: ${error.message} The last recorded batch is still shown. Use Refresh batch to retry.`)); stopBatchWatch(); return; }
      watch.controller = null; schedule();
    }
    schedule();
  }
  function stagingLabel(plan) {
    if (plan.maintenance_required) return 'manual_runbook';
    if (plan.status === 'staging_queued') return 'queued';
    if (plan.status === 'staged') return 'staged';
    if (['queued', 'executing', 'pending_reassessment', 'completed', 'remediated', 'verified'].includes(plan.status)) {
      const stage = plan.staging_result || plan.stage_result;
      return (stage?.value?.status || stage?.status) === 'staged' ? 'staged' : 'not_applicable';
    }
    return plan.staging_eligible === true ? 'eligible' : 'not_ready';
  }
  async function showPlan(id) { stopPlanWatch(); stopBatchWatch(); await action(async () => { const result = await api(`/plans/${encodeURIComponent(id)}`); showPlanData(result.plan || result); }); }
  function stopPlanWatch() {
    if (!planWatch) return;
    clearTimeout(planWatch.timer);
    planWatch.controller?.abort();
    planWatch = null;
  }
  function watchPlan(plan) {
    // Read only, and only while this exact active plan remains open. A recursive
    // timeout waits for each GET to finish before scheduling the next one.
    if (!['validating_target', 'staging_queued', 'queued', 'executing', 'pending_reassessment'].includes(plan.status) || !maintenanceState(plan).valid) return;
    const watch = { id: String(recordId(plan)), snapshot: JSON.stringify(plan), controller: null, timer: null };
    planWatch = watch;
    const schedule = () => { if (planWatch === watch) watch.timer = setTimeout(poll, 5000); };
    async function poll() {
      const dialog = $('#detail-dialog');
      if (planWatch !== watch || !dialog.open) return;
      if (document.hidden || $('#auth-dialog').open || pendingPlans.has(watch.id)) { schedule(); return; }
      watch.controller = new AbortController();
      try {
        const response = await api(`/plans/${encodeURIComponent(watch.id)}`, { signal: watch.controller.signal });
        if (planWatch !== watch || !dialog.open) return;
        const updated = response.plan || response;
        $('.plan-refresh-error', dialog)?.remove();
        if (JSON.stringify(updated) !== watch.snapshot || !maintenanceState(updated).valid) {
          showPlanData(updated, true);
          return;
        }
      } catch (error) {
        if (planWatch !== watch || !dialog.open || error.name === 'AbortError') return;
        let feedback = $('.plan-refresh-error', dialog);
        if (!feedback) { feedback = el('p', { class: 'form-help plan-refresh-error', role: 'status' }); $('.maintenance-controls', dialog).after(feedback); }
        feedback.textContent = `Automatic status refresh failed: ${error.message} The last recorded plan is still shown. Use Refresh plan to retry.`;
        stopPlanWatch();
        return;
      }
      watch.controller = null;
      schedule();
    }
    schedule();
  }
  function maintenanceState(plan) {
    const status = String(plan.status || 'unknown');
    const valid = !plan.expires_at || Date.parse(plan.expires_at) > Date.now();
    // The service updates execution_result for every action receipt; staging_result
    // remains the earlier stage receipt after a later execution denial or failure.
    const report = plan.execution_result || plan.staging_result || plan.stage_result;
    const reportStatus = report?.value?.status || report?.status;
    const reviewRequired = plan.target_resolution?.applicability_review_required === true || plan.finding?.decision_basis === 'inventory_advisory_match' || plan.finding?.remediation_eligible === false;
    const manual = Boolean(plan.maintenance_required);
    return { status, valid, report, reviewRequired, manual, completed: ['completed', 'remediated', 'verified'].includes(status), approved: plan.approved === true,
      canApprove: valid && status === 'draft' && Boolean(plan.target_version) && !reviewRequired,
      canStage: !manual && valid && status === 'approved' && plan.approved === true && plan.staging_eligible === true,
      canExecute: !manual && valid && status === 'staged' && plan.approved === true && plan.execution_eligible === true && (!reportStatus || reportStatus === 'staged'),
      canValidate: valid && ['draft', 'approved', 'validation_failed', 'target_validation_failed'].includes(status) };
  }
  function maintenanceCheckSummary(report) {
    const details = report?.value?.details || report?.details;
    if (!details || typeof details !== 'object' || Array.isArray(details)) return null;
    const checksKnown = typeof details.maintenance_checks_enabled === 'boolean';
    const rollbackKnown = typeof details.rollback_available === 'boolean';
    const skipped = array(details.checks_skipped);
    const healthSkipped = String(details.post_validation?.status || '').toUpperCase() === 'SKIPPED';
    const rollbackSources = (array(details.rollback_sources).length ? details.rollback_sources : array(details.artifacts?.rollback)).filter((item) => item && typeof item === 'object' && !Array.isArray(item));
    if (!checksKnown && !rollbackKnown && !skipped.length && !healthSkipped && !rollbackSources.length) return null;
    const section = el('section', { class: 'detail-section maintenance-check-summary', role: 'status' }, el('h3', {}, 'Recorded checks and rollback'));
    if (checksKnown) section.append(notice(details.maintenance_checks_enabled ? 'Maintenance checks enabled for this request. Inspect the recorded results for their outcomes.' : 'Maintenance checks disabled for this request. Successful staging does not mean the optional checks passed.', details.maintenance_checks_enabled ? 'info' : 'warning'));
    if (rollbackKnown) section.append(notice(details.rollback_available ? 'Rollback packages staged for an attempted recovery.' : 'Automatic rollback unavailable. The previous package could not be staged; installation failure may require manual recovery.', details.rollback_available ? 'info' : 'danger'));
    const missing = array(details.rollback_missing).filter((item) => item !== null && item !== undefined);
    if (missing.length) section.append(el('ul', { class: 'preflight-list rollback-missing' }, missing.map((item) => el('li', {}, typeof item === 'string' ? item : `${text(item.package)} ${text(item.version)}: ${text(item.reason, 'Not available')}`))));
    if (rollbackSources.length) section.append(el('h4', {}, 'Rollback package sources'), table(['PACKAGE / VERSION', 'REPORTED SOURCE', 'REPORTED VERIFICATION', 'ARCHIVE'], rollbackSources.map((item) => {
      const source = item.source || item; const url = safeUrl(source.url);
      const debianSnapshot = source.type === 'debian_snapshot' && url && new URL(url).hostname === 'snapshot.debian.org' && new URL(url).protocol === 'https:';
      return [cell(item.package || item.name, item.version), cell(debianSnapshot ? 'Debian snapshot (collector reported)' : source.type === 'debian_snapshot' ? 'Snapshot source not established' : pretty(source.type || 'configured_apt'), [source.archive, source.suite, source.snapshot].filter(Boolean).join(' · ') || null), cell(source.verification === 'apt_signed_repository' ? 'APT signed repository (collector reported)' : pretty(source.verification || 'not_recorded'), item.sha256 ? `SHA-256 ${item.sha256}` : 'Artifact hash not reported'), url ? el('a', { href: url, target: '_blank', rel: 'noopener noreferrer' }, 'Open recorded archive ↗') : 'No valid HTTP(S) archive URL recorded'];
    })), el('p', { class: 'form-help' }, 'Source, availability, hashes and signature checks above are reported by the collector; the service has not independently reverified these package signatures. These receipts do not imply that all dependency packages needed for recovery were available.'));
    if (skipped.length) section.append(el('p', { class: 'form-help' }, 'Skipped checks reported by the collector:'), el('ul', { class: 'preflight-list checks-skipped' }, skipped.map((item) => el('li', {}, typeof item === 'string' ? pretty(item) : JSON.stringify(item)))));
    if (healthSkipped) section.append(notice('Post-installation health checks skipped. Vulnerability reassessment does not provide a health-check result.', 'warning'));
    return section;
  }
  function containerRestartSummary(report) {
    const details = report?.value?.details || report?.details || {};
    const restart = details.container_restart;
    if (!restart && !details.writable_layer_warning) return null;
    return el('section', { class: 'detail-section container-restart-summary' }, el('h3', {}, 'Target container restart'), restart ? el('div', {}, notice(restart.status === 'complete' ? 'The collector reported that the target container restart completed. This is separate from central CVE resolution.' : `Container restart ${pretty(restart.status || 'unknown')}. Inspect the collector result and current container state.`, restart.status === 'complete' ? 'info' : 'warning'), el('div', { class: 'detail-grid' }, field('Container identity', restart.container_id || details.container_identity?.id), field('Started', date(restart.started_at)), field('Completed', date(restart.completed_at))), restart.error ? notice(text(restart.error), 'danger') : null) : null, details.writable_layer_warning ? notice(text(details.writable_layer_warning), 'warning') : null);
  }
  function reassessmentSummary(plan) {
    const result = plan.reassessment;
    if (!result || typeof result !== 'object' || Array.isArray(result)) return null;
    const completed = plan.status === 'completed' && result.status === 'completed';
    const selected = array(result.selected_cves);
    const remaining = array(result.remaining_cves);
    return el('section', { class: 'detail-section reassessment-summary', role: 'status' }, el('h3', {}, completed ? 'Selected CVEs no longer reported' : 'Waiting for reassessment'), notice(text(result.reason, completed ? 'The accepted scan no longer reports the selected CVEs for this package and scope.' : 'Waiting for fresh inventory and an accepted central scan for this package and scope.'), completed ? 'success' : 'warning'), el('div', { class: 'detail-grid' }, field('Package / scope', `${text(result.package_name || plan.package_name)} / ${text(result.scope || plan.scope)}`), field('Observed version', text(result.observed_version, 'Not yet reported')), field('Selected CVEs', selected.join(', ') || 'Not recorded'), field('Remaining selected CVEs', remaining.join(', ') || (completed ? 'None in the accepted scan' : 'Not yet established')), field('Scan completed', date(result.scan_completed_at)), field('Reassessment checked', date(result.checked_at)), field('Assessment revision', text(result.assessment_revision, 'Not yet recorded')), field('Scanner database revision', text(result.scanner_db_revision, 'Not yet recorded')), field('Assessed inventory identity', el('span', { class: 'mono' }, text(result.inventory_digest, 'Not yet recorded')))), el('p', { class: 'form-help' }, 'This outcome covers the selected CVEs for this package occurrence. Other findings remain separate; SONiC health follows the recorded collector checks.'), el('details', {}, el('summary', {}, 'Inspect reassessment evidence'), jsonBlock(result)));
  }
  function maintenanceFlow(plan, readiness) {
    if (readiness.manual) {
      // Only review approval is recorded here; no operator deployment state exists.
      const reviewed = readiness.status === 'approved' && readiness.approved;
      return el('ol', { class: 'maintenance-flow manual-maintenance-flow', 'aria-label': 'Manual maintenance workflow' }, ['Review target', 'Approve review', 'Operator maintenance', 'Collect & reassess'].map((label, index) => {
        const done = reviewed && index < 2;
        const current = !reviewed && readiness.valid && ['draft', 'validating_target'].includes(readiness.status) && index === 0;
        return el('li', { class: `maintenance-step ${done ? 'done' : current ? 'current' : ''}`, 'aria-current': current ? 'step' : null }, el('span', { class: 'maintenance-step-number' }, done ? icon('check') : String(index + 1)), el('span', {}, label), index > 1 ? el('span', {}, 'Operator step · not tracked here') : null);
      }));
    }
    const phase = readiness.completed ? 5 : readiness.status === 'draft' || readiness.status === 'validating_target' ? 0 : readiness.status === 'approved' ? 2 : ['staging_queued', 'staging_failed', 'stage_failed', 'staging_unknown'].includes(readiness.status) ? 2 : ['staged', 'queued', 'executing', 'execution_failed', 'rollback_failed'].includes(readiness.status) ? 3 : readiness.status === 'pending_reassessment' ? 4 : 2;
    const stageLabel = readiness.status === 'approved' ? readiness.canStage ? 'Ready to stage' : 'Staging blocked' : 'Stage & check';
    const active = readiness.valid && !['denied', 'failed', 'unknown', 'staging_failed', 'stage_failed', 'staging_unknown', 'execution_failed', 'rollback_failed', 'requires_revalidation', 'superseded'].includes(readiness.status) && !(readiness.status === 'approved' && !readiness.canStage);
    return el('ol', { class: 'maintenance-flow', 'aria-label': 'Maintenance workflow' }, ['Review target', 'Approve', stageLabel, 'Execute', 'Reassess'].map((label, index) => el('li', { class: `maintenance-step ${index < phase ? 'done' : index === phase && active ? 'current' : ''}`, 'aria-current': index === phase && active ? 'step' : null }, el('span', { class: 'maintenance-step-number' }, index < phase ? icon('check') : String(index + 1)), el('span', {}, label))));
  }
  async function planAction(plan, endpoint, payload, message) {
    const id = String(recordId(plan));
    if (pendingPlans.has(id)) return;
    stopPlanWatch();
    pendingPlans.add(id);
    const controls = $('#detail-content');
    const buttons = [...controls.querySelectorAll('button')].map((node) => [node, node.disabled]);
    for (const [node] of buttons) node.disabled = true;
    controls.setAttribute('aria-busy', 'true');
    const progress = el('p', { class: 'form-help plan-request-status', role: 'status' }, endpoint === 'approve' ? 'Submitting review approval…' : 'Submitting plan request…');
    ($('.maintenance-controls', controls) || controls).append(progress);
    try { await action(async () => {
      const response = await api(`/plans/${encodeURIComponent(recordId(plan))}/${endpoint}`, { method: 'POST', body: payload });
      const updated = response.plan || (String(recordId(response)) === String(recordId(plan)) ? { ...plan, ...response } : await api(`/plans/${encodeURIComponent(recordId(plan))}`));
      showPlanData(updated.plan || updated);
      if (page === 'plans') await loadPage(false);
      return response;
    }, message); } finally {
      pendingPlans.delete(id);
      controls.removeAttribute('aria-busy');
      progress.remove();
      for (const [node, disabled] of buttons) if (node.isConnected) node.disabled = disabled;
    }
  }
  function showPlanData(plan, preserveView = false) {
    const dialog = $('#detail-dialog');
    const scrollTop = dialog.scrollTop;
    const focused = preserveView && dialog.contains(document.activeElement) ? document.activeElement : null;
    const focusKey = focused ? [focused.tagName, focused.id, focused.getAttribute('aria-label'), focused.textContent] : null;
    const opened = preserveView ? [...dialog.querySelectorAll('details')].map((node) => node.open) : [];
    const readiness = maintenanceState(plan);
    const resolution = plan.target_resolution || {};
    const options = array(resolution.target_options).length ? resolution.target_options : array(plan.candidate_versions).map((version) => ({ version, status: 'candidate_only', repository_availability: 'unknown' }));
    const prerequisites = array(resolution.required_agent_preflight).length ? resolution.required_agent_preflight : array(plan.preflight_requirements);
    const content = el('div', {}, el('div', { class: 'detail-badges' }, badge(readiness.status), plan.maintenance_required ? badge('maintenance_required') : null), maintenanceFlow(plan, readiness), el('div', { class: 'detail-grid' }, field('Switch / scope', `${text(plan.hostname || plan.device_id)} / ${text(plan.scope)}`), field('Package', plan.package_name), field('Before → target version', `${text(plan.from_version)} → ${text(plan.target_version, 'Select a target')}`), field('Plan expires', date(plan.expires_at)), field('Plan ID', el('span', { class: 'mono' }, text(recordId(plan)))), field('Inventory identity', el('span', { class: 'mono' }, text(plan.inventory_digest)))));
    if (String(plan.scope || '').startsWith('container:')) content.append(el('section', { class: 'detail-section container-plan-help' }, notice(plan.container_maintenance === true ? 'Container maintenance is enabled for this plan. Installation runs inside the selected container and automatically restarts that container. Keep switch maintenance mode enabled through staging and execution.' : 'Automatic container maintenance requires a supported collector and maintenance mode enabled locally on the switch. Protected components can still require image maintenance. Refresh the switch inventory, then create a new plan after changing eligibility.', 'warning'), el('pre', { class: 'code-output' }, 'sudo config security smart-patch maintenance-mode enable'), el('p', { class: 'form-help' }, 'Maintenance mode does not drain traffic. Package changes affect the container writable layer and may be lost when the container is recreated or the SONiC image changes. Build the fix into a maintained image for persistence.'), button('Inspect switch maintenance mode', () => showDevice(plan.device_id), 'quiet')));
    if (plan.container_identity) content.append(el('div', { class: 'detail-grid detail-section' }, field('Target container identity', el('span', { class: 'mono' }, text(plan.container_identity.id))), field('Container image identity', el('span', { class: 'mono' }, text(plan.container_identity.image)))));
    if (plan.batch_id) content.append(notice('This switch plan belongs to a remediation batch. Use Back to batch to approve, stage, or authorize execution together with its other switches.'));
    if (!readiness.valid && !readiness.completed) content.append(el('div', { class: 'detail-section' }, notice('This plan has expired. Create a new plan from the current findings.', 'warning')));
    else if (readiness.status === 'validating_target') content.append(el('div', { class: 'detail-section' }, notice(readiness.manual ? 'A central worker is checking the selected target against the vulnerability database. This checks package metadata; it does not validate or deploy a SONiC image. Refresh the plan for its result.' : 'A central worker is checking the selected target against the vulnerability database. Approval and staging remain unavailable until the recorded result is ready. Refresh the plan for its result.', 'warning')));
    else if (readiness.manual) content.append(el('section', { class: 'detail-section manual-maintenance-status' }, el('h3', {}, readiness.status === 'approved' && readiness.approved ? 'Review approved — manual maintenance required' : 'Manual image or container maintenance required'), notice('This plan does not support automatic package staging or execution. Approval records the review; it does not queue a download or installation on the switch. Follow the manual maintenance runbook below. Waiting or rechecking a target will not start deployment.', 'warning')));
    else if (readiness.status === 'staging_queued') content.append(el('div', { class: 'detail-section' }, notice('Staging is queued for the collector. It prepares target packages using the switch’s configured maintenance check policy and records rollback availability. This dialog refreshes automatically. Execution remains unavailable until staging succeeds.')));
    else if (readiness.canStage) content.append(el('div', { class: 'detail-section' }, notice(plan.batch_id ? 'Review approved. The batch controls when this switch is dispatched for staging.' : 'Ready to stage. No staging request has been queued. Select Stage packages to request preparation using the switch’s configured maintenance check policy; execution requires a separate confirmation.')));
    else if (readiness.canExecute) content.append(el('div', { class: 'detail-section' }, notice('The collector reported successful staging. Review the recorded checks and exact target before requesting execution.', 'success')));
    else if (readiness.status === 'pending_reassessment') content.append(el('div', { class: 'detail-section' }, notice('The package action was reported. A new inventory and central assessment must establish the vulnerability outcome; execution completion alone does not mark a finding fixed. This dialog refreshes automatically while waiting.', 'warning')));
    else if (readiness.completed) content.append(el('div', { class: 'detail-section' }, notice('This plan is complete. Inspect the scoped reassessment evidence below for the observed package version and selected CVE outcome.', 'success')));
    else if (['queued', 'executing'].includes(readiness.status)) content.append(el('div', { class: 'detail-section' }, notice('The explicit execution request is queued or running. This dialog refreshes automatically to show the collector’s result.')));
    else if (readiness.status === 'denied') content.append(el('div', { class: 'detail-section' }, notice('The collector denied this request. No action is still queued for this plan. Resolve the reported prerequisite before preparing another request.', 'danger')));
    else if (['failed', 'unknown', 'staging_failed', 'stage_failed', 'staging_unknown', 'execution_failed', 'rollback_failed'].includes(readiness.status)) content.append(el('div', { class: 'detail-section' }, notice('The recorded outcome is failed or unknown. Execution is unavailable. Inspect the collector result and current inventory before preparing another plan.', 'warning')));
    else if (readiness.status === 'approved' && !readiness.canStage) content.append(el('div', { class: 'detail-section' }, notice('Review approval is recorded, but the service has not established staging eligibility. Inspect target verification, repository availability, maintenance requirements, and current findings.', 'warning')));
    const resultReason = readiness.report?.value?.details || readiness.report?.error;
    if (resultReason && ['denied', 'failed', 'unknown', 'staging_failed', 'stage_failed', 'staging_unknown', 'execution_failed', 'rollback_failed'].includes(readiness.status)) content.append(el('section', { class: 'detail-section collector-outcome', role: 'status' }, el('h3', {}, 'Collector reported'), notice(typeof resultReason === 'string' ? resultReason : resultReason.error || resultReason.rollback_error || JSON.stringify(resultReason), 'danger')));
    const checkSummary = maintenanceCheckSummary(readiness.report);
    if (checkSummary) content.append(checkSummary);
    const restartSummary = containerRestartSummary(readiness.report);
    if (restartSummary) content.append(restartSummary);
    const reassessment = reassessmentSummary(plan);
    if (reassessment) content.append(reassessment);
    if (plan.impact) content.append(el('div', { class: 'detail-section' }, notice(plan.impact)));
    if (readiness.reviewRequired) {
      const findingIds = [...new Set([...array(plan.finding_ids), plan.finding?.id].filter(Boolean))];
      content.append(el('section', { class: 'detail-section approval-prerequisite' }, el('h3', {}, 'Scoped finding review required before approval'), notice(plan.target_resolution?.applicability_review_reason || 'The findings in this plan do not yet have the scoped applicability review required for remediation.', 'warning'), el('p', {}, 'Open the current finding, inspect its evidence, and record a scoped verdict. After saving the review, create a new plan from the current finding; this draft retains the original assessment.'), el('div', { class: 'detail-actions' }, findingIds.map((id, index) => button(findingIds.length === 1 ? 'Inspect finding for scoped review' : `Inspect finding ${index + 1} for scoped review`, () => showFinding(id), 'secondary', 'search')))));
    }
    if (readiness.manual) {
      const steps = array(plan.steps);
      const limitations = array(plan.limitations);
      content.append(el('section', { class: 'detail-section manual-maintenance-runbook' }, el('h3', {}, 'Manual maintenance runbook'), el('p', { class: 'form-help' }, 'These are operator instructions, not completed checks. Smart Patch does not track image activation or mark this runbook complete. After the change, collect fresh inventory and inspect the new CVE assessment.'), steps.length ? el('ol', { class: 'preflight-list' }, steps.map((step) => el('li', {}, typeof step === 'string' ? step : JSON.stringify(step)))) : notice('No detailed runbook was returned. Obtain an approved SONiC image or service-image maintenance procedure before proceeding.', 'warning'), limitations.length ? el('div', { class: 'detail-section' }, el('h4', {}, 'Workflow limitations'), el('ul', { class: 'preflight-list' }, limitations.map((item) => el('li', {}, typeof item === 'string' ? item : JSON.stringify(item))))) : null));
    }
    const optionRows = options.map((option) => [cell(option.version, option.architecture || option.source_version), badge(option.status), badge(option.repository_availability || resolution.repository_availability || 'unknown'), el('details', {}, el('summary', {}, 'Evidence & checks'), jsonBlock(option))]);
    content.append(el('section', { class: 'detail-section' }, el('h3', {}, 'Target versions and evidence'), table(['VERSION', 'CENTRAL CHECK', 'REPOSITORY', 'DETAILS'], optionRows, 'No target candidates are recorded. Review the advisory and configured repository evidence.'), el('p', { class: 'form-help' }, readiness.manual ? 'Candidate only means an advisory target with unconfirmed availability. A central recheck examines package metadata; it does not validate a replacement SONiC image or enable automatic deployment.' : 'Candidate only means an advisory target with unconfirmed availability. Recheck passed applies to central vulnerability matching. Collector preparation and optional checks follow the switch’s maintenance policy.')));
    if (options.length && readiness.canValidate && !plan.batch_id) {
      const candidate = el('select', { 'aria-label': 'Target version for central recheck' }, [...new Set(options.map((option) => option.version))].map((version) => el('option', { value: version }, version)));
      candidate.value = plan.target_version || options[0].version;
      content.append(el('div', { class: 'toolbar detail-section' }, candidate, button('Recheck selected target', () => planAction(plan, 'validate-target', { target_version: candidate.value }, 'Central target recheck queued. Refresh the plan for its result.'), 'secondary', 'search')));
      content.append(el('p', { class: 'form-help' }, 'Rechecking or changing the target clears prior approval. Review and approve the resulting plan again.'));
      if (options.length > 1) content.append(el('div', { class: 'detail-actions' }, button('Create separate plan for this version', () => action(async () => { const result = await api('/plans', { method: 'POST', body: { device_id: plan.device_id, finding_ids: plan.finding_ids, target_version: candidate.value } }); showPlanData(result.plan || result); }, 'Version-specific plan created.'), 'quiet')));
    }
    if (!readiness.manual) content.append(el('section', { class: 'detail-section' }, el('h3', {}, 'Collector preparation and check policy'), prerequisites.length ? el('ul', { class: 'preflight-list' }, prerequisites.map((item) => el('li', {}, typeof item === 'string' ? item : JSON.stringify(item)))) : notice('Detailed preparation requirements were not returned. Inspect the collector result for the policy used and any skipped checks.')));
    if (readiness.report) content.append(el('section', { class: 'detail-section' }, el('h3', {}, 'Latest collector result'), jsonBlock(readiness.report)));
    if (plan.target_validation_error || plan.validation_error || plan.last_error) content.append(el('div', { class: 'detail-section' }, notice(text(plan.target_validation_error || plan.validation_error || plan.last_error), 'danger')));
    content.append(el('details', { class: 'detail-section' }, el('summary', {}, 'Full plan record'), jsonBlock(plan)), el('div', { class: 'detail-actions' }, link('View CVE remediation status', remediationHref(plan))));
    const controls = el('div', { class: 'maintenance-controls' });
    const approve = button('2 · Approve review', () => planAction(plan, 'approve', {}, readiness.manual ? 'Review approved. Manual maintenance is required; no switch action was queued.' : 'Plan review approved. Staging remains a separate step.'), 'primary', 'check'); approve.disabled = !readiness.canApprove;
    const stage = button('3 · Stage packages', () => planAction(plan, 'stage', {}, 'Staging requested. Refresh this plan for the collector result.'), readiness.canStage ? 'primary' : 'secondary', 'box'); stage.disabled = !readiness.canStage;
    const execute = button('4 · Review execution', () => confirmPlanExecution(plan), readiness.canExecute ? 'danger' : 'secondary', 'warning'); execute.disabled = !readiness.canExecute;
    if (plan.batch_id) controls.append(button('Back to batch', () => showBatch(plan.batch_id), 'primary', 'fleet'));
    else { controls.append(approve); if (!readiness.manual) controls.append(stage, execute); }
    controls.append(button('Refresh plan', () => showPlan(recordId(plan)), 'secondary', 'refresh'));
    content.append(controls, el('p', { class: 'form-help' }, readiness.manual ? 'Automatic staging and execution are unavailable for this manual runbook. Refresh reads the recorded plan; it does not start maintenance.' : 'Stage prepares target artifacts and reports rollback availability and skipped checks. Apply requires a separate execution confirmation after successful staging.'));
    openDetail(readiness.manual ? 'MANUAL MAINTENANCE RUNBOOK' : 'STAGED MAINTENANCE', plan.title || 'Component remediation plan', content);
    if (preserveView) {
      [...dialog.querySelectorAll('details')].forEach((node, index) => { node.open = opened[index] || false; });
      if (focused?.isConnected) focused.focus({ preventScroll: true });
      else if (focusKey) [...dialog.querySelectorAll('button,input,select,textarea,summary,a')].find((node) => !node.disabled && JSON.stringify([node.tagName, node.id, node.getAttribute('aria-label'), node.textContent]) === JSON.stringify(focusKey))?.focus({ preventScroll: true });
      dialog.scrollTop = scrollTop;
    }
    watchPlan(plan);
  }
  function confirmPlanExecution(plan) {
    if (!maintenanceState(plan).canExecute) { showPlanData(plan); toast('Execution requires a current approved plan with successful recorded staging.', 'error'); return; }
    const form = el('form');
    const confirmation = el('input', { id: 'execution-confirmation', required: true, autocomplete: 'off', placeholder: 'Type the switch identity', 'aria-label': 'Confirm target switch identity' });
    form.append(notice(`Request application of ${text(plan.package_name)} ${text(plan.from_version)} → ${text(plan.target_version)} on ${text(plan.hostname || plan.device_id)} in ${text(plan.scope)}. Review the successful staging result and operational impact before proceeding.`, 'warning'));
    if (String(plan.scope || '').startsWith('container:')) form.append(notice(`This also authorizes an automatic restart of ${text(plan.scope)}. Keep switch maintenance mode enabled and arrange any required traffic drain. Recreating the container can discard its writable-layer package change.`, 'warning'));
    const checkSummary = maintenanceCheckSummary(maintenanceState(plan).report);
    if (checkSummary) form.append(checkSummary);
    form.append(el('div', { class: 'detail-grid' }, field('Plan ID', el('span', { class: 'mono' }, text(recordId(plan)))), field('Target package SHA-256', el('span', { class: 'mono' }, text(plan.target_package_sha256))), field('Staging request', el('span', { class: 'mono' }, text(plan.stage_request_id))), field('Plan expires', date(plan.expires_at))), el('section', { class: 'detail-section' }, el('h3', {}, 'Recorded staging result'), jsonBlock(maintenanceState(plan).report)), el('div', { class: 'detail-section' }, el('label', { for: 'execution-confirmation' }, `Type ${text(plan.device_id)} to confirm the target`), confirmation), el('div', { class: 'detail-actions' }, button('Back to review', () => showPlanData(plan), 'secondary'), el('button', { type: 'submit', class: 'button button-danger' }, 'Request plan execution')));
    form.addEventListener('submit', async (event) => { event.preventDefault(); if (confirmation.value.trim() !== String(plan.device_id)) { toast('The switch identity does not match the plan target.', 'error'); return; } const submit = $('button[type=submit]', form); submit.disabled = true; try { await planAction(plan, 'execute', { confirmed_device_id: plan.device_id }, 'Execution requested. Its outcome still requires collector results and central reassessment.'); } finally { submit.disabled = false; } });
    openDetail('AUTHORIZE STAGED SWITCH CHANGE', 'Confirm plan execution', form);
  }
  function formField(label, name, options = {}) {
    const attrs = { name, id: `field-${name}-${++fieldSequence}`, ...options }; const tag = attrs.tag || 'input'; delete attrs.tag; const help = attrs.help; delete attrs.help; const selectOptions = attrs.options; delete attrs.options; delete attrs.fullWidth;
    const input = tag === 'select' ? el('select', attrs, array(selectOptions).map(([value, title]) => el('option', { value }, title))) : el(tag, attrs);
    if (tag === 'select' && options.value != null) input.value = options.value;
    return el('div', { class: `form-field${options.fullWidth ? ' full-width' : ''}` }, el('label', { for: input.id }, label), input, help ? el('p', { class: 'form-help' }, help) : null);
  }
  function formObject(form) { return Object.fromEntries(new FormData(form).entries()); }
  async function renderTools() {
    const toolResponse = await api('/tools'); const tools = array(toolResponse.tools).map((entry) => entry.function ? { name: entry.function.name, description: entry.function.description, input_schema: entry.function.parameters } : entry); state.toolList = tools;
    const form = el('form', { class: 'tool-form' }); const select = el('select', { id: 'tool-select', required: true }, el('option', { value: '' }, 'Choose an evidence tool'), tools.map((tool) => el('option', { value: tool.name }, tool.name)));
    const description = el('p', { class: 'tool-description' }, 'Tools run centrally against configured sources. Results are bounded by the service.');
    const argumentsInput = el('textarea', { id: 'tool-arguments', name: 'arguments', rows: 12, spellcheck: false, class: 'mono', 'aria-label': 'Tool arguments as JSON' }, '{}');
    const schema = el('div'); const result = el('pre', { class: 'code-output empty', id: 'tool-output' }, 'Choose a tool and inspect its input schema.\nNo tool has been run in this tab.');
    const resultMeta = el('div', { class: 'tool-result-meta' }, 'Awaiting a request');
    select.addEventListener('change', () => { const tool = tools.find((item) => item.name === select.value); description.textContent = text(tool?.description, 'Choose a tool to view its purpose and input schema.'); const inputs = {}; for (const [key, value] of Object.entries(tool?.input_schema?.properties || {})) if (array(tool?.input_schema?.required).includes(key) || value.default !== undefined) inputs[key] = value.default ?? value.enum?.[0] ?? (value.type === 'integer' || value.type === 'number' ? 20 : value.type === 'array' ? [] : value.type === 'boolean' ? false : ''); argumentsInput.value = JSON.stringify(inputs, null, 2); schema.replaceChildren(tool ? el('details', {}, el('summary', {}, 'Input schema'), jsonBlock(tool.input_schema)) : el('span')); });
    form.append(el('div', {}, el('label', { for: 'tool-select' }, 'Evidence tool'), select), description, schema, el('div', {}, el('label', { for: 'tool-arguments' }, 'Arguments · JSON'), argumentsInput), el('div', { class: 'form-actions' }, el('button', { type: 'submit', class: 'button button-primary' }, icon('code'), 'Run evidence tool')));
    form.addEventListener('submit', async (event) => { event.preventDefault(); const submit = $('button[type=submit]', form); await action(async () => { if (!select.value) throw new Error('Choose an evidence tool.'); let args; try { args = JSON.parse(argumentsInput.value); } catch { throw new Error('Arguments must be valid JSON.'); } if (!args || Array.isArray(args) || typeof args !== 'object') throw new Error('Arguments must be a JSON object.'); submit.disabled = true; const started = performance.now(); try { const response = await api(`/tools/${encodeURIComponent(select.value)}`, { method: 'POST', body: { arguments: args } }); result.textContent = JSON.stringify(response.result ?? response, null, 2); result.classList.remove('empty'); resultMeta.textContent = `${select.value} · ${Math.round(performance.now() - started)} ms · ${new Date().toLocaleTimeString()}`; } finally { submit.disabled = false; } }); });
    return el('div', {}, notice('Evidence tools return observations, not automatic proof that a component is unaffected. Preserve source revision, scope, and missing evidence when interpreting a result.'), el('div', { class: 'two-column' }, card('Investigation console', `${tools.length} registered tools`, el('div', { class: 'card-body' }, form)), card('Tool result', 'A bounded response from the configured evidence source.', el('div', { class: 'card-body' }, resultMeta, result))));
  }
  async function renderSettings() {
    const response = await api('/settings'); const settings = response.settings || response;
    const form = el('form'); const fields = el('div', { class: 'form-grid' }, formField('AI provider', 'ai_provider', { value: settings.ai_provider || '', placeholder: 'openai-compatible' }), formField('Model', 'ai_model', { value: settings.ai_model || '', placeholder: 'Configured model identifier' }), formField('API base URL', 'ai_api_url', { type: 'url', value: settings.ai_api_url || '', placeholder: 'https://…' }), formField('Provider API key', 'ai_api_key', { type: 'password', autocomplete: 'new-password', placeholder: settings.ai_api_key_set ? 'Key configured · leave empty to retain' : 'No key configured', help: 'The saved key is never returned to this browser.' }), settings.build_evidence_policy ? formField('Build evidence for applicability', 'build_evidence_policy', { tag: 'select', value: settings.build_evidence_policy || 'required', options: [['required', 'Required (default)'], ['optional', 'Optional for inventory advisory matches']], fullWidth: true, help: 'Optional permits exact distribution matches without a verified build. Custom packages and cross-release candidates still need evidence. This does not verify build provenance.' }) : null, formField('Source revision', 'source_revision', { value: settings.source_revision || '', placeholder: 'Exact checked-out revision' }), formField('Scan interval (seconds)', 'scan_interval_seconds', { type: 'number', min: 60, value: settings.scan_interval_seconds ?? 3600 }), formField('CVEs per provider batch', 'ai_max_findings', { type: 'number', min: 0, max: 100, required: true, value: settings.ai_max_findings ?? 10, help: 'Remaining cases continue from saved evidence. Zero pauses provider batches.' }), formField('Scanner binary', 'scanner_binary', { value: settings.scanner_binary || '', placeholder: 'grype', disabled: true, help: 'Set SCANNER_BINARY in deployment configuration and restart the service.' }), el('div', { class: 'form-field' }, el('label', {}, 'AI investigation'), el('label', { class: 'checkbox-label' }, el('input', { type: 'checkbox', name: 'ai_enabled', checked: settings.ai_enabled }), 'Enable evidence-assisted AI analysis')), formField('Source roots · JSON', 'source_roots', { tag: 'textarea', rows: 5, class: 'mono', fullWidth: true, help: 'Configured local source repositories, using the existing service schema.' }));
    $('textarea[name=source_roots]', fields).value = JSON.stringify(settings.source_roots ?? [], null, 2);
    fields.append(el('div', { class: 'form-field full-width detail-section' }, el('h3', {}, 'Operational alert thresholds'), el('p', { class: 'form-help' }, 'Rules evaluate recent recorded measurements and create service alerts and audit events. Minimum sample counts prevent small samples from triggering rate/latency alerts.')), el('div', { class: 'form-field full-width' }, el('label', { class: 'checkbox-label' }, el('input', { type: 'checkbox', name: 'alerts_enabled', checked: settings.alerts_enabled }), 'Enable operational alerts')), formField('Minimum measured samples', 'alert_min_samples', { type: 'number', min: 1, required: true, value: settings.alert_min_samples ?? 20 }), formField('API latency p95 threshold · seconds', 'alert_latency_p95_seconds', { type: 'number', min: 0.01, step: 0.01, required: true, value: settings.alert_latency_p95_seconds ?? 2 }), formField('Minimum cache hit rate · percent', 'alert_cache_hit_rate_percent', { type: 'number', min: 0, max: 100, step: 0.1, required: true, value: settings.alert_cache_hit_rate_percent ?? 70 }), formField('Maximum API error rate · percent', 'alert_error_rate_percent', { type: 'number', min: 0, max: 100, step: 0.1, required: true, value: settings.alert_error_rate_percent ?? 5 }), formField('Queue depth alert threshold', 'alert_queue_depth', { type: 'number', min: 0, required: true, value: settings.alert_queue_depth ?? 100 }));
    form.append(fields, notice('Changing build evidence policy marks existing assessments stale and schedules reassessment when workers are enabled. Queue central scan to request it explicitly. Inventory-only matches need a scoped operator review before maintenance approval.'), notice('After enabling or changing the provider, start Scan or Investigate for devices, or Sync for a release. Existing analysis remains bound to the provider and evidence used for that assessment.'), el('div', { class: 'form-actions' }, el('button', { type: 'submit', class: 'button button-primary' }, icon('check'), 'Save configuration')));
    form.addEventListener('submit', async (event) => { event.preventDefault(); const values = formObject(form); await action(async () => { let roots; try { roots = JSON.parse(values.source_roots); } catch { throw new Error('Source roots must be valid JSON.'); } if (!Array.isArray(roots) || roots.some((root) => typeof root !== 'string')) throw new Error('Source roots must be a JSON array of directory paths.'); const payload = { build_evidence_policy: values.build_evidence_policy, ai_max_findings: Number(values.ai_max_findings), ai_provider: values.ai_provider, ai_model: values.ai_model, ai_api_url: values.ai_api_url, ai_enabled: $('input[name=ai_enabled]', form).checked, source_roots: roots, source_revision: values.source_revision, scan_interval_seconds: Number(values.scan_interval_seconds), alerts_enabled: $('input[name=alerts_enabled]', form).checked, alert_min_samples: Number(values.alert_min_samples), alert_latency_p95_seconds: Number(values.alert_latency_p95_seconds), alert_cache_hit_rate_percent: Number(values.alert_cache_hit_rate_percent), alert_error_rate_percent: Number(values.alert_error_rate_percent), alert_queue_depth: Number(values.alert_queue_depth) }; if (values.ai_api_key) payload.ai_api_key = values.ai_api_key; await api('/settings', { method: 'PUT', body: payload }); $('input[name=ai_api_key]', form).value = ''; await loadPage(false); }, 'Configuration saved.'); });
    return el('div', {}, notice('Changing an AI provider does not change prior assessment evidence. Provider secrets remain on the server. Source tools only access configured repositories.'), card('Analysis configuration', 'Central scanning and bounded source investigation.', el('div', { class: 'card-body' }, form)), el('div', { class: 'full-width-card' }, card('Effective non-secret configuration', 'Returned by the service.', el('div', { class: 'card-body' }, el('details', {}, el('summary', {}, 'Inspect settings'), jsonBlock(settings))))));
  }
  async function renderTokens() {
    const { tokens = [] } = await api('/tokens'); const reveal = el('div'); const form = el('form');
    form.append(el('div', { class: 'form-grid' }, formField('Description', 'description', { required: true, maxlength: 200, placeholder: 'e.g. lab switch collector' }), formField('Role', 'role', { tag: 'select', options: [['agent', 'Device collector'], ['operator', 'Operator'], ['admin', 'Administrator']] }), formField('Device ID', 'device_id', { placeholder: 'Required for a device token', help: 'Bind a collector token to its assigned device identity.' })), el('div', { class: 'form-actions' }, el('button', { type: 'submit', class: 'button button-primary' }, icon('key'), 'Create token')));
    form.addEventListener('submit', async (event) => { event.preventDefault(); const values = formObject(form); await action(async () => { if (values.role === 'agent' && !values.device_id.trim()) throw new Error('A device token needs a device ID.'); const result = await api('/tokens', { method: 'POST', body: { description: values.description, role: values.role, device_id: values.device_id.trim() || null } }); reveal.replaceChildren(el('div', { class: 'secret-box' }, el('h3', {}, 'Copy this token now'), el('p', {}, 'The service returns the token only at creation. Keep it in your deployment’s secret store.'), el('code', {}, result.token), el('div', { class: 'form-actions' }, button('Dismiss token', () => reveal.replaceChildren(), 'secondary'), button('Copy token', async () => { try { await navigator.clipboard.writeText(result.token); toast('Token copied.', 'success'); } catch { toast('Select and copy the token manually; clipboard access is unavailable.', 'error'); } }, 'secondary')))); form.reset(); await refreshTokenTable(list); }, 'Access token created.'); });
    const list = el('div'); renderTokenTable(list, tokens);
    return el('div', {}, el('div', { class: 'two-column' }, card('Create access token', 'Use a separate scoped token for every collector.', el('div', { class: 'card-body' }, form)), card('Access boundaries', 'Credentials identify an administrator, operator, or device.', el('div', { class: 'card-body signal-list' }, signal('key', 'Administrator', 'Manages settings, releases, and access credentials.'), signal('shield', 'Operator', 'Reviews operational security data within the service’s permissions.'), signal('fleet', 'Device collector', 'Publishes inventory for its bound device identity.')))), reveal, el('div', { class: 'full-width-card' }, list));
  }
  async function refreshTokenTable(container) { const { tokens = [] } = await api('/tokens'); renderTokenTable(container, tokens); }
  function renderTokenTable(container, tokens) {
    container.replaceChildren(card('Issued tokens', 'Raw token values are never listed.', table(['DESCRIPTION', 'ROLE', 'DEVICE', 'LAST USED', 'STATE', ''], tokens.map((token) => [cell(token.description, token.id), badge(token.role), text(token.device_id, '—'), relative(token.last_used_at), badge(token.revoked ? 'revoked' : 'active'), token.revoked ? '' : button('Revoke', () => confirmRevoke(token, container), 'danger')]), 'No additional tokens have been issued.')));
  }
  function confirmRevoke(token, container) {
    openDetail('ACCESS MANAGEMENT', 'Revoke access token?', el('div', {}, el('p', { class: 'muted' }, `Revoking “${text(token.description, token.id)}” stops future API access using that token. A new token can be issued if needed.`), el('div', { class: 'detail-actions' }, button('Cancel', () => $('#detail-dialog').close(), 'secondary'), button('Revoke token', () => action(async () => { await api(`/tokens/${encodeURIComponent(token.id)}`, { method: 'DELETE' }); $('#detail-dialog').close(); await refreshTokenTable(container); }, 'Token revoked.'), 'danger'))));
  }
  async function renderReleases() {
    const [{ releases = [] }, uploadLimits] = await Promise.all([api('/releases'), api('/upload-limits').catch(() => ({ sbom_bytes: 50 * 1024 * 1024 }))]); const form = el('form');
    const sbomLimit = Number.isSafeInteger(uploadLimits.sbom_bytes) && uploadLimits.sbom_bytes > 0 ? uploadLimits.sbom_bytes : 50 * 1024 * 1024;
    const sbomLimitLabel = `${number(sbomLimit / (1024 * 1024))} MiB`;
    form.append(el('div', { class: 'form-grid' }, formField('Release / build ID', 'release_id', { required: true, placeholder: 'sonic.<branch>.<build>-<commit> or custom:<name>' }), formField('Source URL', 'source_url', { type: 'url', placeholder: 'https://…' }), formField('Pinned source revision', 'source_revision', { pattern: '[0-9a-fA-F]{7,64}', placeholder: 'Exact commit hash', help: 'Required for custom release source cloning; the service resolves and pins the commit.' }), formField('SBOM source', 'sbom_source', { placeholder: 'Configured artifact path or URL', help: 'Registration does not imply successful ingestion.' }), el('div', { class: 'form-field' }, el('label', {}, 'Default release'), el('label', { class: 'checkbox-label' }, el('input', { name: 'primary', type: 'checkbox' }), 'Mark as primary'))), el('div', { class: 'form-actions' }, el('button', { type: 'submit', class: 'button button-primary' }, icon('box'), 'Register release')));
    const repositoryField = formField('Signed APT repositories · JSON', 'repositories', { tag: 'textarea', rows: 6, class: 'mono', fullWidth: true, help: 'Configure actual HTTPS repositories and an existing server-approved public keyring. No repositories are assumed.' });
    $('textarea', repositoryField).value = '[]';
    $('.form-grid', form).append(repositoryField, el('div', { class: 'form-field full-width' }, el('details', {}, el('summary', {}, 'Repository schema example'), jsonBlock([{ base_url: 'https://deb.debian.org/debian', suite: 'bookworm', components: ['main'], architectures: ['amd64'], keyring: '/usr/share/keyrings/debian-archive-keyring.gpg' }]))));
    form.addEventListener('submit', async (event) => { event.preventDefault(); const values = formObject(form); await action(async () => {
      let repositories; try { repositories = JSON.parse(values.repositories); } catch { throw new Error('Repository configuration must be valid JSON.'); }
      if (!Array.isArray(repositories) || repositories.length > 16) throw new Error('Repositories must be an array of at most 16 configurations.');
      for (const repository of repositories) {
        const keys = ['base_url', 'suite', 'components', 'architectures', 'keyring'];
        if (!repository || Array.isArray(repository) || typeof repository !== 'object' || Object.keys(repository).some((key) => !keys.includes(key))) throw new Error('Repository fields are limited to base_url, suite, components, architectures, and keyring.');
        const url = safeUrl(repository.base_url); if (!url || !url.startsWith('https://')) throw new Error('Repository base_url must use HTTPS.');
        const parsed = new URL(url); if (parsed.username || parsed.password || parsed.search || parsed.hash) throw new Error('Repository URLs cannot contain credentials, query parameters, or fragments.');
        if (typeof repository.suite !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$/.test(repository.suite)) throw new Error('Repository suite must be a valid identifier.');
        for (const field of ['components', 'architectures']) if (!Array.isArray(repository[field]) || !repository[field].length || repository[field].length > 8 || new Set(repository[field]).size !== repository[field].length || repository[field].some((value) => typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(value))) throw new Error(`${field} requires 1–8 unique valid identifiers.`);
        if (typeof repository.keyring !== 'string' || !repository.keyring.startsWith('/')) throw new Error('Repository keyring must name an approved absolute server path.');
      }
      if (values.source_url && values.release_id.startsWith('custom:') && !values.source_revision.trim()) throw new Error('Custom release source cloning needs an explicit pinned source revision.');
      await api('/releases', { method: 'POST', body: { release_id: values.release_id, source_url: values.source_url, source_revision: values.source_revision.trim(), repositories, sbom_source: values.sbom_source, primary: $('input[name=primary]', form).checked } }); await loadPage(false);
    }, 'Release registered.'); });
    const uploadForm = el('form', {}, formField('Release / build ID', 'release_id', { required: true, placeholder: 'Match the registered build identity' }), el('div', { class: 'detail-section' }, formField('SBOM document', 'file', { type: 'file', required: true, accept: '.json,application/json', help: `Maximum ${sbomLimitLabel} (${number(sbomLimit)} bytes). Upload the original inventory artifact; the service validates its contents.` })), el('div', { class: 'form-actions' }, el('button', { type: 'submit', class: 'button button-secondary' }, icon('upload'), 'Upload SBOM')));
    uploadForm.addEventListener('submit', async (event) => { event.preventDefault(); const submit = $('button[type=submit]', uploadForm); await action(async () => { const file = $('input[name=file]', uploadForm).files[0]; if (!file) throw new Error('Select an SBOM document to upload.'); if (file.size > sbomLimit) throw new Error(`SBOM upload exceeds ${sbomLimitLabel} limit. Select a smaller file.`); submit.disabled = true; try { const result = await api('/sbom-upload', { method: 'POST', body: new FormData(uploadForm) }); toast(result.message || `SBOM accepted${result.operation_id ? ` · job ${result.operation_id}` : ''}.`, 'success'); await loadPage(false); } finally { submit.disabled = false; } }); });
    return el('div', {}, el('div', { class: 'two-column' }, card('Register build identity', 'Associate a release with its source and SBOM artifact.', el('div', { class: 'card-body' }, form)), card('Import inventory', 'Upload a local SBOM to the central service.', el('div', { class: 'card-body' }, uploadForm))), el('div', { class: 'full-width-card' }, card('Registered releases', `${releases.length} build records`, table(['RELEASE', 'SOURCE', 'SBOM', 'STATUS', ''], releases.map((release) => [cell(release.release_id || release.id, release.primary ? 'Primary release' : release.created_at ? date(release.created_at) : null), el('span', { class: 'mono' }, text(release.source_url)), el('span', { class: 'mono' }, text(release.sbom_source)), el('div', { class: 'pill-row' }, badge(release.status || (release.components_count != null ? 'imported' : 'registered')), release.verification ? badge(release.verification) : null), el('div', { class: 'cell-actions' }, el('button', { class: 'button-link', onclick: () => openDetail('BUILD RECORD', release.release_id || release.id, jsonBlock(release)) }, 'Inspect'), release.artifact_id ? button('Verify binding', () => verifyRelease(release), 'secondary', 'shield') : null)]), 'No releases have been registered.'))));
  }

  function verifyRelease(release) {
    const form = el('form');
    form.append(notice('Verifies the builder signature connecting the manifest, registered SBOM, and release image digest. This records a signed release baseline; it does not perform TPM or runtime attestation.'), el('div', { class: 'detail-grid' }, field('Registered release', release.release_id || release.id), field('Registered artifact', el('span', { class: 'mono' }, text(release.artifact_id)))), el('div', { class: 'form-grid detail-section' }, formField('Approved public-key ID', 'key_id', { required: true, maxlength: 64, pattern: '[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', placeholder: 'e.g. community-builder-2026', fullWidth: true, help: 'An administrator must provision this public key in the service’s trusted-build-keys directory. Private keys are never uploaded.' }), formField('Embedded manifest · original JSON file', 'manifest_file', { type: 'file', required: true, accept: '.json,application/json', fullWidth: true, help: 'Use the exact file bytes emitted by the build pipeline; maximum 1 MiB.' }), formField('Signed external release index · original JSON file', 'index_file', { type: 'file', required: true, accept: '.json,application/json', fullWidth: true, help: 'Use the .smart-patch.json file whose exact bytes were signed; maximum 1 MiB.' }), formField('Detached signature · binary .sig file', 'signature_file', { type: 'file', required: true, accept: '.sig,application/octet-stream', fullWidth: true, help: 'RSA PKCS#1 v1.5 with SHA-256 or Ed25519; maximum 1024 bytes.' })), el('div', { class: 'detail-actions' }, button('Cancel', () => $('#detail-dialog').close(), 'secondary'), el('button', { type: 'submit', class: 'button button-primary' }, icon('shield'), 'Verify signed binding')));
    form.addEventListener('submit', async (event) => { event.preventDefault(); const submit = $('button[type=submit]', form); await action(async () => { const manifest = $('input[name=manifest_file]', form).files[0]; const index = $('input[name=index_file]', form).files[0]; const signature = $('input[name=signature_file]', form).files[0]; if (!manifest || !index || !signature) throw new Error('Select the original manifest, release index, and detached signature files.'); if (manifest.size > 1048576 || index.size > 1048576 || signature.size > 1024 || signature.size === 0) throw new Error('Manifest/index files must be at most 1 MiB and the signature 1–1024 bytes.'); submit.disabled = true; try { const [manifestText, indexText, signatureBytes] = await Promise.all([manifest.text(), index.text(), signature.arrayBuffer()]); const result = await api('/artifacts/verify', { method: 'POST', body: { release_id: release.release_id || release.id, manifest_text: manifestText, release_index_text: indexText, signature_base64: btoa(String.fromCharCode(...new Uint8Array(signatureBytes))), key_id: $('input[name=key_id]', form).value.trim() } }); openDetail('SIGNED RELEASE BASELINE', 'Builder signature verified', el('div', {}, notice('The release signature and artifact digests match. A matching reported switch manifest identifies this signed baseline; current runtime integrity remains a separate assessment.', 'success'), jsonBlock(result))); await loadPage(false); } finally { submit.disabled = false; } }, 'Signed release binding verified.'); });
    openDetail('BUILD PROVENANCE', 'Verify release signature', form);
  }
  function svgNode(tag, attrs = {}, content = null) {
    const node = document.createElementNS('http://www.w3.org/2000/svg', tag);
    for (const [name, value] of Object.entries(attrs)) node.setAttribute(name, String(value));
    if (content !== null) node.textContent = content;
    return node;
  }
  function trendChart(rows, series, label, { discovery = false } = {}) {
    const stamp = (row) => row.snapshot_time || row.measured_at || row.date;
    const recorded = array(rows).filter((row) => stamp(row)).sort((a, b) => String(stamp(a)).localeCompare(String(stamp(b))));
    if (!recorded.length) return empty(discovery ? 'No first-observed CVEs are recorded in this window. This does not establish scan coverage or mean the fleet is free of vulnerabilities.' : 'No historical snapshots have been recorded in this window. Earlier days are not backfilled.');
    const max = Math.max(1, ...recorded.flatMap((row) => series.map((item) => Number(row[item.key]) || 0)));
    const svg = svgNode('svg', { viewBox: '0 0 740 255', role: 'img', 'aria-label': label, class: 'trend-svg' });
    svg.append(svgNode('title', {}, label));
    const left = 45, top = 15, width = 670, height = 195;
    const moments = recorded.map((row) => Date.parse(stamp(row))); const firstMoment = moments[0], lastMoment = moments[moments.length - 1];
    const inset = discovery ? 16 : 0; const plotWidth = width - inset * 2;
    const x = (index) => left + inset + (recorded.length === 1 || lastMoment === firstMoment ? plotWidth / 2 : Number.isFinite(firstMoment) && Number.isFinite(lastMoment) ? (moments[index] - firstMoment) / (lastMoment - firstMoment) * plotWidth : index * plotWidth / (recorded.length - 1));
    const y = (value) => top + height - Math.max(0, Number(value) || 0) / max * height;
    const ticks = Math.min(4, Math.ceil(max));
    for (let index = 0; index <= ticks; index++) {
      const axis = top + index * height / ticks;
      svg.append(svgNode('line', { x1: left, x2: left + width, y1: axis, y2: axis, stroke: 'var(--line)', 'stroke-dasharray': index === ticks ? '' : '3 5' }));
      svg.append(svgNode('text', { x: left - 10, y: axis + 3, 'text-anchor': 'end', fill: 'var(--muted)', 'font-size': 9 }, Math.round(max * (1 - index / ticks)).toLocaleString()));
    }
    for (const item of series) {
      if (discovery) {
        const gaps = recorded.slice(1).map((_row, index) => x(index + 1) - x(index)).filter((gap) => gap > 0);
        const barWidth = Math.max(1, Math.min(28, (gaps.length ? Math.min(...gaps) : plotWidth) * 0.65));
        recorded.forEach((row, index) => { if (row[item.key] == null) return; const bar = svgNode('rect', { x: x(index) - barWidth / 2, y: y(row[item.key]), width: barWidth, height: top + height - y(row[item.key]), rx: 2, fill: item.color }); bar.append(svgNode('title', {}, `${stamp(row)} · ${number(row[item.key])} distinct CVEs first observed in this UTC ${row.granularity === 'hour' ? 'hour' : 'day'}`)); svg.append(bar); });
        continue;
      }
      const points = recorded.map((row, index) => row[item.key] == null ? null : [x(index), y(row[item.key])]);
      const segments = []; let segment = [];
      for (const point of points) { if (point) segment.push(point.join(',')); else if (segment.length) { segments.push(segment); segment = []; } }
      if (segment.length) segments.push(segment);
      for (const values of segments) svg.append(svgNode('polyline', { points: values.join(' '), fill: 'none', stroke: item.color, 'stroke-width': 2.5, 'stroke-dasharray': item.dashed ? '5 5' : '', 'stroke-linejoin': 'round', 'stroke-linecap': 'round' }));
      recorded.forEach((row, index) => { if (row[item.key] == null) return; const dot = svgNode('circle', { cx: x(index), cy: y(row[item.key]), r: 3.7, fill: item.color, stroke: 'var(--surface)', 'stroke-width': 1.5 }); dot.append(svgNode('title', {}, `${item.key === 'peak_affected' ? `${row.date} UTC day` : text(row.measured_at || row.date)} · ${item.label}: ${number(row[item.key])}${row.observation_count ? ` · ${number(row.observation_count)} recorded observations` : ''}`)); svg.append(dot); });
    }
    const indices = [...new Set([0, Math.floor((recorded.length - 1) / 2), recorded.length - 1])];
    for (const index of indices) svg.append(svgNode('text', { x: x(index), y: top + height + 25, 'text-anchor': 'middle', fill: 'var(--muted)', 'font-size': 9 }, `${String(stamp(recorded[index])).slice(5, 10)}${recorded[index].granularity === 'hour' ? ` ${String(stamp(recorded[index])).slice(11, 16)}Z` : ''}`));
    const legend = el('div', { class: 'chart-legend' }, series.map((item) => { const dot = el('i'); dot.style.background = item.color; return el('span', {}, dot, item.label); }));
    const headers = discovery ? ['FIRST-SEEN UTC BUCKET', ...series.map((item) => item.label.toUpperCase())] : ['LAST OBSERVED AT', 'OBSERVATIONS', ...series.map((item) => item.label.toUpperCase())];
    const values = recorded.map((row) => discovery ? [stamp(row), ...series.map((item) => number(row[item.key]))] : [date(row.measured_at || row.date), number(row.observation_count ?? 1), ...series.map((item) => number(row[item.key]))]);
    return el('div', { class: 'card-body' }, legend, svg, el('p', { class: 'form-help' }, discovery ? 'Bars count first-observed CVE identities per UTC bucket. Only buckets with recorded discoveries appear; gaps do not establish scan coverage or zero risk.' : 'Only observed snapshots are shown. Lines connect observations; missing history is not filled with zeroes.'), el('details', { class: 'chart-data' }, el('summary', {}, 'Inspect recorded values'), table(headers, values)));
  }
  async function renderAnalytics(kind) {
    const response = await api(`/analytics?days=${analyticsWindow}`);
    const toolbar = el('div', { class: 'toolbar' }, el('span', { class: 'muted' }, 'Observation window'), el('select', { 'aria-label': 'Observation window', onchange: async (event) => { analyticsWindow = Number(event.target.value); await loadPage(false); } }, [7, 30, 90, 366].map((days) => el('option', { value: days, selected: days === analyticsWindow }, `Last ${days} days`))));
    if (kind !== 'requests') toolbar.append(el('span', { class: 'badge purple' }, response.history_resolution === 'day' ? (kind === 'cves' ? 'Daily observations · discovery counts per day' : 'Daily · last observed value') : (kind === 'cves' ? 'Hourly observations · discovery counts per hour' : 'Hourly observations')));
    const notes = array(response.notes).length ? notice(response.notes.map((item) => typeof item === 'string' ? item : JSON.stringify(item)).join(' ')) : notice('Trends begin with recorded service observations. Inventory and vulnerability counts describe different units.');
    const content = el('div', {}, toolbar, notes);
    if (kind === 'packages') {
      const rows = array(response.package_trends); const latest = response.current_inventory || rows[rows.length - 1] || {};
      content.append(el('div', { class: 'coverage-grid' }, stat('Component occurrences', number(latest.components), 'Current reported fleet inventory', 'box'), stat('Unique package tuples', number(latest.unique_packages), 'Source name, version and architecture', 'code'), stat('Observed switches', number(latest.devices), 'In current reported inventory', 'fleet')),
        card('Inventory over time', 'Component occurrences and unique source-package/version/architecture tuples from recorded snapshots.', trendChart(rows, [{ key: 'components', label: 'Component occurrences', color: 'var(--accent)' }, { key: 'unique_packages', label: 'Unique packages', color: 'var(--green)' }], 'Recorded package inventory over time')));
      const types = array(response.package_type_breakdown); const changed = array(response.top_updated_packages); const changeCoverage = response.package_change_coverage || {};
      content.append(el('div', { class: 'two-column full-width-card' }, card('Current package families', 'Recorded type or name-based classification; component occurrences across scopes.', table(['FAMILY', 'COMPONENTS', 'PACKAGE TUPLES', 'SWITCHES'], types.map((item) => [pretty(item.package_type), number(item.components), number(item.unique_packages), number(item.devices)]), 'No package-family observations are available.')), card('Most updated packages', 'Recorded version transitions; initial baseline additions and removals are excluded.', table(['PACKAGE', 'UPDATES', 'SWITCHES', 'LAST CHANGE'], changed.map((item) => [cell(item.package_name, item.latest_observed_version), number(item.updates), number(item.devices), cell(relative(item.last_updated), date(item.last_updated))]), 'No package version updates are recorded in this window.'))));
      if (changeCoverage.complete === false) content.append(notice(`Update ranking is partial: ${number(changeCoverage.incomplete_events)} truncated inventory events and ${number(changeCoverage.legacy_events_without_changes)} legacy events without detailed transitions. Unrecorded changes are not estimated.`, 'warning'));
      else if (changeCoverage.first_recorded_change_at) content.append(el('p', { class: 'form-help' }, `Detailed inventory change recording in this window starts ${date(changeCoverage.first_recorded_change_at)}.`));
    } else if (kind === 'cves') {
      const rows = array(response.cve_trends); const latest = rows[rows.length - 1] || {};
      const discoveries = response.cve_discovery_summary || {}; const coverage = discoveries.coverage || {};
      content.append(card('CVE discovery', 'Distinct CVEs first observed across Smart Patch devices, including unresolved scanner candidates. Repeated or reappearing CVEs are counted once.', el('div', {}, el('div', { class: 'card-body detail-grid' }, field('First observed in this window', number(discoveries.distinct_cves_in_window)), field('Distinct CVEs in discovery ledger', number(discoveries.total_distinct_cves)), field('Earliest retained first observation', date(discoveries.earliest_recorded_first_seen)), field('Durable discovery tracking since', date(coverage.ledger_started_at))), trendChart(array(response.cve_discovery_trends), [{ key: 'first_seen_cves', label: 'First observed CVEs', color: 'var(--accent)' }], 'Distinct CVEs first observed by Smart Patch', { discovery: true }), coverage.history_complete !== true ? notice('Historical discovery coverage is partial. Migrated entries use the earliest retained finding or assessment timestamp; older missing or archived records are not reconstructed. CVE publication dates and release-catalog-only findings are excluded.', 'warning') : null)));
      content.append(el('div', { class: 'stat-grid' }, stat('Unique CVEs', number(latest.unique_cves), 'Distinct advisories in latest snapshot', 'shield'), stat('Affected findings', number(latest.affected), 'Scoped component findings', 'warning', 'danger'), stat('Under investigation', number(latest.under_investigation), 'Evidence still unresolved', 'search', 'warning'), stat('Fixed findings', number(latest.fixed), 'Retained with supporting evidence', 'check', 'success')),
        card('Applicability over time', 'Finding counts by recorded applicability state.', trendChart(rows, [{ key: 'affected', label: 'Affected', color: 'var(--red)' }, { key: 'under_investigation', label: 'Under investigation', color: 'var(--amber)' }, { key: 'fixed', label: 'Fixed', color: 'var(--green)' }, { key: 'not_affected', label: 'Not affected', color: 'var(--blue)' }, ...(response.history_resolution === 'day' ? [{ key: 'peak_affected', label: 'Peak affected (observed)', color: 'var(--red)', dashed: true }] : [])], 'Recorded CVE applicability over time')));
    } else {
      const metrics = response.request_metrics || {};
      content.append(el('div', { class: 'stat-grid' }, stat('Assessment requests', number(metrics.total_requests), `${number(metrics.completed)} completed · ${number(metrics.failed)} failed`, 'jobs'), stat('Average duration', metrics.average_duration_ms == null ? '—' : `${number(Math.round(metrics.average_duration_ms))} ms`, 'Recorded assessment API durations', 'clock'), stat('p95 duration', metrics.p95_duration_ms == null ? '—' : `${number(Math.round(metrics.p95_duration_ms))} ms`, 'Measured request duration distribution', 'activity'), stat('Cache reuse', metrics.cache_hit_rate == null ? '—' : `${(Number(metrics.cache_hit_rate) * 100).toFixed(1)}%`, `${number(metrics.cache_hits)} hits · ${number(metrics.cache_misses)} misses`, 'memory')),
        card('Assessment request history', 'Most recent 500 matching assessment API requests; central scanning jobs are listed separately.', table(['REQUEST', 'DEVICE / RELEASE', 'CVEs', 'STATUS', 'DURATION', 'CACHE', 'SUBMITTED'], array(response.requests).map((request) => [el('button', { class: 'button-link', onclick: () => openDetail('ASSESSMENT REQUEST', String(request.id || request.request_id), el('div', {}, el('div', { class: 'detail-badges' }, badge(request.status)), request.error_message || request.error ? notice(text(request.error_message || request.error), 'danger') : null, jsonBlock(request))) }, cell(String(request.id || request.request_id).slice(0, 16), null, true)), cell(request.smart_patch_instance_id || request.device_id, request.sonic_version), number(request.cve_count), badge(request.status), request.assessment_duration_ms == null ? 'Not measured' : `${number(request.assessment_duration_ms)} ms`, request.response_cached == null ? 'Not recorded' : request.response_cached ? badge('cache_hit') : el('span', { class: 'muted' }, 'Miss'), cell(relative(request.submitted_at), date(request.submitted_at))]), 'No assessment API requests have been recorded. Central scans appear under Analysis jobs.')));
    }
    if (kind !== 'requests') {
      const grid = array(response.severity_package_grid);
      content.append(el('div', { class: 'full-width-card' }, card('Findings by package and severity', 'Current scoped finding occurrences. A package can appear on multiple switches.', table(['PACKAGE', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN', 'AFFECTED SWITCHES', 'OCCURRENCES'], grid.map((row) => [el('span', { class: 'mono' }, text(row.package_name)), ...['critical', 'high', 'medium', 'low', 'unknown'].map((severity) => el('span', { class: `heat-cell ${Number(row[severity]) > 0 ? tone(severity) : ''}` }, number(row[severity]))), number(row.affected_devices), number(row.occurrences)]), 'No package findings have been recorded.'))));
    }
    return content;
  }

  const renderers = { 'remediation-status': renderRemediationStatus, 'packages-trends': () => renderAnalytics('packages'), 'cve-trends': () => renderAnalytics('cves'), 'request-status': () => renderAnalytics('requests'), overview: renderOverview, fleet: renderFleet, findings: renderFindings, coverage: renderCoverage, changes: renderChanges, plans: renderPlans, jobs: renderJobs, tools: renderTools, settings: renderSettings, tokens: renderTokens, releases: renderReleases };
  async function loadPage(showLoading = true) {
    if (!state.token || state.loading) return;
    remediationViewCleanup?.(); remediationViewCleanup = null;
    state.loading = true; $('#page-content').setAttribute('aria-busy', 'true'); $('#refresh-button').disabled = true;
    if (showLoading) $('#page-content').replaceChildren(el('div', { class: 'loading-panel' }, el('div', { class: 'spinner' }), 'Loading recorded service data…'));
    try { const view = await (renderers[page] || renderOverview)(); $('#page-content').replaceChildren(view); setConnection(true); $('#last-updated').textContent = `Updated ${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`; }
    catch (error) { $('#page-content').replaceChildren(el('div', { class: 'empty-state' }, el('span', { class: 'empty-icon' }, icon('warning')), el('h2', {}, 'This view is unavailable'), el('p', {}, error.message), button('Retry request', () => loadPage(), 'primary', 'refresh'), button('Manage connection', showAuth, 'quiet'))); $('#last-updated').textContent = 'Data unavailable'; }
    finally { state.loading = false; $('#page-content').setAttribute('aria-busy', 'false'); $('#refresh-button').disabled = false; }
  }
  function init() {
    const info = pages[page] || pages.overview; $('#page-title').textContent = info[0]; $('#page-description').textContent = info[1]; $('#page-eyebrow').textContent = info[2]; $('#breadcrumb').textContent = info[0]; document.title = `${info[0]} · SONiC Smart Patch`;
    document.querySelectorAll('[data-icon]').forEach((node) => node.replaceChildren(icon(node.dataset.icon)));
    document.querySelectorAll('[data-nav]').forEach((node) => { if (node.dataset.nav === page) { node.classList.add('active'); node.setAttribute('aria-current', 'page'); } });
    let theme = 'light'; try { theme = localStorage.getItem('smart_patch_theme') || 'light'; } catch { /* Theme is optional. */ } document.documentElement.dataset.theme = theme;
    function updateThemeLabel() { const dark = document.documentElement.dataset.theme === 'dark'; $('#theme-toggle').replaceChildren(icon(dark ? 'sun' : 'moon')); $('#theme-toggle').setAttribute('aria-label', `Switch to ${dark ? 'light' : 'dark'} theme`); }
    updateThemeLabel(); $('#theme-toggle').addEventListener('click', () => { const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'; document.documentElement.dataset.theme = next; try { localStorage.setItem('smart_patch_theme', next); } catch { /* No persistence. */ } updateThemeLabel(); });
    $('#menu-toggle').addEventListener('click', () => { const open = $('#sidebar').classList.toggle('open'); $('#menu-toggle').setAttribute('aria-expanded', String(open)); });
    document.addEventListener('click', (event) => { if ($('#sidebar').classList.contains('open') && !event.target.closest('#sidebar') && !event.target.closest('#menu-toggle')) { $('#sidebar').classList.remove('open'); $('#menu-toggle').setAttribute('aria-expanded', 'false'); } if (event.target.closest('[data-action=connect]')) showAuth(); });
    document.querySelectorAll('[data-close-dialog]').forEach((node) => node.addEventListener('click', () => $(`#${node.dataset.closeDialog}`).close()));
    $('#detail-dialog').addEventListener('close', stopPlanWatch);
    $('#detail-dialog').addEventListener('close', stopBatchWatch);
    $('#detail-dialog').addEventListener('cancel', stopBatchWatch);
    window.addEventListener('pagehide', stopBatchWatch);
    $('#detail-dialog').addEventListener('cancel', stopPlanWatch);
    $('#detail-dialog').addEventListener('close', stopRemediationWatch);
    $('#detail-dialog').addEventListener('cancel', stopRemediationWatch);
    $('#detail-dialog').addEventListener('close', stopJobWatch);
    $('#detail-dialog').addEventListener('cancel', stopJobWatch);
    window.addEventListener('pagehide', stopJobWatch);
    window.addEventListener('pagehide', stopPlanWatch);
    window.addEventListener('pagehide', stopRemediationWatch);
    window.addEventListener('pagehide', () => { remediationViewCleanup?.(); clearInterval(state.refreshId); });
    $('#auth-button').addEventListener('click', showAuth); $('#refresh-button').addEventListener('click', () => state.token ? loadPage() : showAuth());
    $('#disconnect-button').addEventListener('click', () => { sessionStorage.removeItem(TOKEN_KEY); state.token = ''; location.reload(); });
    $('#auth-form').addEventListener('submit', async (event) => { event.preventDefault(); const token = $('#auth-token').value.trim(); const previous = state.token; state.token = token; const submit = $('button[type=submit]', event.currentTarget); submit.disabled = true; $('#auth-error').hidden = true; try { await api('/settings'); sessionStorage.setItem(TOKEN_KEY, token); $('#auth-token').value = ''; $('#auth-dialog').close(); setConnection(true); await loadPage(); } catch (error) { state.token = previous; $('#auth-error').textContent = error.message; $('#auth-error').hidden = false; } finally { submit.disabled = false; } });
    if (state.token) loadPage();
    // Refresh operational views only when visible, idle, and no detail dialog is open.
    if (['overview', 'fleet', 'jobs', 'changes', 'coverage', 'plans'].includes(page)) state.refreshId = setInterval(() => { if (!document.hidden && !document.querySelector('dialog[open]') && !document.activeElement?.matches('input,select,textarea') && state.token && !state.loading) loadPage(false); }, page === 'jobs' ? 5000 : 30000);
  }
  init();
})();
