#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════════════════════
// AXR - Compliance Report Generator (CRG)
// ═══════════════════════════════════════════════════════════════════════════════
// Egy auditor nem JSONL-t es Merkle-fakat olvas a parancssorbol. Ez az eszkoz egy
// AXR logbol (receipts + STH + anchors + trust-root/control) EMBER-OLVASHATO,
// onmagaban allo HTML (vagy JSON) jelentest general: lanc-integritas, a kulcsok
// KORABELI ervenyessege (melyik kulcs mit irt ala, autorizalt volt-e az adott
// tree_size-nal), horgonyzasi statusz, redaction/side-effect osszegzes,
// kulcs-governance idovonal, es az EU AI Act Art.12 / GDPR kontroll-leképezes
// (a COMPLIANCE.md soraira epitve).
//
// OSZINTE HATAR (a projekt doktrinaja): ez a jelentes NEZET a verifier verdiktje
// folott. A nagy PASS/FAIL bannert MAGA az axr-verify.js kilepesi kodja adja - a
// riport ezt huen kozli, NEM helyettesiti a fuggetlen verifikaciot, es sosem allit
// ervenyesseget, amit nem ellenoriztek. A riport reprodukalhato: ugyanaz a
// bemenet ugyanazt a jelentest adja (a generalas idobelyege kiveve).
//
// Ket reteg:
//   - buildReportModel(inputs): tiszta fuggveny, strukturalt audit-modellt ad
//     (a mar beolvasott tombokbol + a verifier-verdiktbol). Determinisztikus.
//   - renderHtml(model) / renderJson(model): a modell -> kimenet.
// A CLI: beolvas, futtatja az axr-verify.js-t a hiteles verdiktert, modellt epit,
// rendereл, fajlba ir.
//
// Nulla kulso fuggoseg - csak a Node beepitett moduljai + a kozos AXR-modulok.
// ═══════════════════════════════════════════════════════════════════════════════

const core = require('./axr-core');
const succ = require('./axr-succession');
const control = require('./axr-control');

const LEAF_TYPES = ['step', 'workflow', 'identity'];

// ── HTML-escape (a riport felhasznaloi szoveget jelenit meg) ───────────────────
function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function shortHash(h) {
  const s = String(h || '');
  return s.length > 28 ? s.slice(0, 28) + '…' : s;
}

// ── Kulcs-idovonalak (ha van kibovitett trust-root) ────────────────────────────
// A receipt- es sth-role idovonal felepitese a succession-modullal; minden
// rekord root-verifikalt. Hiba -> ures idovonal (a jelentes jelzi).
function buildTimelines(inputs) {
  const tr = inputs.trustRoot;
  if (!tr) return { receipt: null, sth: null, effLogId: null, problems: [] };
  const records = Array.isArray(tr) ? tr : [tr];
  const cv = succ.verifyTrustRootChain(records);
  if (!cv.ok) return { receipt: null, sth: null, effLogId: null, problems: cv.problems };
  const effective = cv.effective;
  const effLogId = inputs.logId || (inputs.sths[0] && inputs.sths[0].log_id) ||
    (Array.isArray(effective.logs) && effective.logs.length === 1 ? effective.logs[0].log_id : null);
  if (!effLogId) return { receipt: null, sth: null, effLogId: null, problems: ['a log_id nem allapithato meg'] };

  const problems = [];
  const succPool = [], revPool = [];
  const seenS = new Set(), seenR = new Set();
  const addS = (r) => {
    if (!r || r.record_type !== 'key_succession') return;
    const h = core.sha256(r); if (seenS.has(h)) return; seenS.add(h);
    if (!succ.verifyKeySuccession(r, effective).ok || r.log_id !== effLogId) return;
    succPool.push(r);
  };
  const addR = (r) => {
    if (!r || r.record_type !== 'key_revocation') return;
    const h = core.sha256(r); if (seenR.has(h)) return; seenR.add(h);
    if (!succ.verifyKeyRevocation(r, effective).ok || r.log_id !== effLogId) return;
    revPool.push(r);
  };
  (inputs.successions || []).forEach(addS);
  (inputs.revocations || []).forEach(addR);
  (inputs.control || []).forEach(r => { addS(r); addR(r); });
  for (const s of inputs.sths) if (s.embedded_succession) addS(s.embedded_succession);

  const mk = (role) => {
    const g = succ.genesisKey(effective, effLogId, role);
    if (!g) return null;
    const tl = succ.buildKeyTimeline(g, succPool, role, effective, revPool);
    for (const p of tl.problems) problems.push(role + ': ' + p);
    return tl.timeline;
  };
  return { receipt: mk('receipt'), sth: mk('sth'), effective, effLogId, problems };
}

// ── Audit-modell felepitese ────────────────────────────────────────────────────
// inputs: { receipts, sths, anchors, publicKeyPem, sthKeyPem, trustRoot,
//           successions, revocations, control, logId, verdict, now, title }
//   verdict: { code, ok, source } - az axr-verify.js authoritativ kilepese
function buildReportModel(inputs) {
  const now = (inputs.now || (() => new Date().toISOString()))();
  const receipts = inputs.receipts || [];
  const sths = (inputs.sths || []).slice().sort((a, b) => a.tree_size - b.tree_size);
  const anchors = inputs.anchors || [];

  const workflows = receipts.filter(r => r.receipt_type === 'workflow');
  const steps = receipts.filter(r => r.receipt_type === 'step');
  const leafReceipts = receipts.filter(r => LEAF_TYPES.includes(r.receipt_type));

  // verzio-eloszlas
  const versions = {};
  for (const r of receipts) { const v = r.axr_version || '(nincs)'; versions[v] = (versions[v] || 0) + 1; }

  // idotartomany (workflow trigger_timestamp-ekbol)
  const times = workflows.map(w => w.workflow && w.workflow.trigger_timestamp).filter(Boolean).sort();

  const timelines = buildTimelines(inputs);

  // ── alairas-integritas (a NEZET szamara; a hiteles verdikt a verifiere) ──
  // a receiptet a level-poziciojanal (idovonal mellett), kulonben a fo kulccsal
  const leafPos = new Map();
  leafReceipts.forEach((r, i) => leafPos.set(r, i + 1));
  let sigOk = 0, sigBad = 0;
  for (const r of receipts) {
    let pem = inputs.publicKeyPem;
    if (timelines.receipt && leafPos.has(r)) {
      const e = succ.keyAtTreeSize(timelines.receipt, leafPos.get(r));
      if (e) pem = e.pem;
    }
    // robusztus: hianyzo/rossz kulcs vagy verify-hiba = rossz alairas (a nezet
    // szamara), nem osszeomlas - a hiteles verdikt ugyis a verifiere
    let valid = false;
    try { valid = !!pem && core.verifyReceipt(r, pem); } catch (e) { valid = false; }
    if (valid) sigOk++; else sigBad++;
  }

  // ── horgonyzas ──
  let anchored = 0, pending = 0;
  for (const r of leafReceipts) { if (r.anchor_ref) anchored++; else pending++; }

  // ── redaction / side-effect ──
  let redactable = 0, redactedFields = 0, sideEffects = 0, attested = 0;
  for (const r of receipts) {
    if ('redactable_root' in r) {
      redactable++;
      const fs2 = r.redactable && Array.isArray(r.redactable.fields) ? r.redactable.fields : [];
      redactedFields += fs2.filter(f => f.redacted || f.value === undefined).length;
    }
    if (Array.isArray(r.side_effects)) for (const e of r.side_effects) { sideEffects++; if (e && e.attestation) attested++; }
  }

  // ── kulcs-governance idovonal (ember-olvashato) ──
  const govEvents = [];
  const fpShort = (fp) => String(fp || '').replace(/^sha256:/, '').slice(0, 12);
  for (const role of ['sth', 'receipt']) {
    const tl = timelines[role];
    if (!tl) continue;
    for (const e of tl) {
      govEvents.push({
        role, from_tree_size: e.from_tree_size,
        fingerprint: e.fingerprint, fpShort: fpShort(e.fingerprint),
        kind: e.from_tree_size === 0 ? 'genesis' : 'succession',
        authorized: e.authorized, revoked_from: e.revoked_from != null ? e.revoked_from : null
      });
    }
  }
  govEvents.sort((a, b) => a.from_tree_size - b.from_tree_size || a.role.localeCompare(b.role));

  // ── control-commitment osszegzes ──
  const committedSths = sths.filter(s => typeof s.control_root_hash === 'string');
  let controlSummary = null;
  if (inputs.control || committedSths.length) {
    const top = committedSths[committedSths.length - 1];
    controlSummary = {
      committedSthCount: committedSths.length,
      maxControlSize: top ? top.control_size : 0,
      controlRecords: (inputs.control || []).length,
      hasControlLog: !!inputs.control
    };
  }

  // ── aktiv kulcs (a legnagyobb fa-meretnel) ──
  const topSize = sths.length ? sths[sths.length - 1].tree_size : 0;
  const activeKeys = {};
  for (const role of ['sth', 'receipt']) {
    const tl = timelines[role];
    if (!tl) { activeKeys[role] = null; continue; }
    const e = succ.keyAtTreeSize(tl, topSize);
    activeKeys[role] = e ? { fpShort: fpShort(e.fingerprint), authorized: e.authorized,
      revoked: e.revoked_from != null && topSize >= e.revoked_from } : null;
  }

  // trust-root fingerprint (a horgony azonositoja a jelentesben)
  let trustRootMode = null, trustRootFp = null;
  if (timelines.effective) {
    const m = succ.trustRootMode(timelines.effective);
    trustRootMode = m.mode;
    trustRootFp = (m.keys || []).map(k => fpShort(succ.keyFingerprint(k))).join(', ');
  }

  return {
    title: inputs.title || 'AXR Compliance Report',
    generated_at: now,
    verdict: inputs.verdict || { code: null, ok: null, source: 'nem futott' },
    log: {
      receipts: receipts.length, workflows: workflows.length, steps: steps.length,
      versions, time_from: times[0] || null, time_to: times[times.length - 1] || null,
      log_id: timelines.effLogId || inputs.logId || (sths[0] && sths[0].log_id) || null
    },
    integrity: { signatures_ok: sigOk, signatures_bad: sigBad, sth_count: sths.length },
    anchoring: { anchored, pending, anchor_records: anchors.length,
      backends: [...new Set(anchors.map(a => a.backend).filter(Boolean))] },
    privacy: { redactable_receipts: redactable, redacted_fields: redactedFields,
      side_effects: sideEffects, attested_side_effects: attested },
    governance: { trust_root_mode: trustRootMode, trust_root_fingerprints: trustRootFp,
      events: govEvents, active_keys: activeKeys, problems: timelines.problems },
    control: controlSummary,
    controls: complianceControls()
  };
}

// ── EU AI Act Art.12 / GDPR kontroll-leképezes (a COMPLIANCE.md-bol) ───────────
function complianceControls() {
  return [
    { framework: 'EU AI Act', ref: 'Art. 12 (record-keeping)',
      expectation: 'Automatic, per-execution event logging over the lifecycle',
      mechanism: 'Signed, chained, append-only step + workflow receipts, independently anchored',
      caveat: 'Records what the workflow asserts it did; not decision correctness (N1).' },
    { framework: 'EU AI Act', ref: 'Traceability',
      expectation: 'How an output was produced is reconstructable',
      mechanism: 'inputs evidence graph + generative receipts (model id, params, prompt/completion hashes)',
      caveat: 'Generative steps captured as evidence, not reproducible computation.' },
    { framework: 'EU AI Act', ref: 'Post-market monitoring',
      expectation: 'Defensible, tamper-evident timeline; after-the-fact tampering detected',
      mechanism: 'Anchored STH chain + an independent Monitor (equivocation/truncation/withholding)',
      caveat: 'Requires an actually-running, ideally independent monitor (N4).' },
    { framework: 'GDPR', ref: 'Art. 17 (erasure)',
      expectation: 'Personal data erasable without breaking the audit trail',
      mechanism: 'Field-level salted redactable commitments: drop cleartext+salt, keep the leaf hash',
      caveat: 'The salted commitment remains; whether that counts as erased is a legal determination.' },
    { framework: 'GDPR', ref: 'Art. 5(1)(c) (minimisation)',
      expectation: 'Minimise personal data held in the record',
      mechanism: 'customer_ref is a hash of name+email+phone, not the values',
      caveat: 'The deployer chooses what to place in input_summary / retained content.' },
    { framework: 'GDPR', ref: 'Art. 5(1)(f) (integrity)',
      expectation: 'Integrity and confidentiality of records',
      mechanism: 'Ed25519 signatures + two-level hash chaining + anchoring; retention/redaction modes',
      caveat: 'Key management is operator-grade by default.' }
  ];
}

// ── JSON render ────────────────────────────────────────────────────────────────
function renderJson(model) {
  return JSON.stringify(model, null, 2) + '\n';
}

// ── HTML render (onmagaban allo, inline CSS) ───────────────────────────────────
function renderHtml(model) {
  const v = model.verdict;
  const pass = v.ok === true;
  const verdictColor = pass ? '#1a7f37' : (v.ok === false ? '#b3261e' : '#9a6700');
  const verdictText = v.ok === true ? 'PASS — VERIFIED' : (v.ok === false ? 'FAIL — INTEGRITY VIOLATION' : 'UNVERIFIED');
  const row = (cells) => '<tr>' + cells.map(c => `<td>${c}</td>`).join('') + '</tr>';
  const kv = (k, val) => row([`<strong>${esc(k)}</strong>`, esc(val)]);

  const govRows = model.governance.events.map(e => row([
    esc(e.role), esc(e.kind), e.from_tree_size === 0 ? '0 (genesis)' : 'tree_size ≥ ' + e.from_tree_size,
    `<code>${esc(e.fpShort)}</code>`,
    e.authorized ? '<span class="ok">authorized</span>' : '<span class="bad">UNAUTHORIZED</span>',
    e.revoked_from != null ? `<span class="bad">revoked @${e.revoked_from}</span>` : '—'
  ])).join('');

  const ctrlRows = model.controls.map(c => row([
    esc(c.framework), `<strong>${esc(c.ref)}</strong>`, esc(c.expectation), esc(c.mechanism),
    `<em>${esc(c.caveat)}</em>`
  ])).join('');

  const ak = model.governance.active_keys;
  const akLine = (role) => ak[role]
    ? `${role}: <code>${esc(ak[role].fpShort)}</code>${ak[role].authorized ? '' : ' <span class="bad">[UNAUTHORIZED]</span>'}${ak[role].revoked ? ' <span class="bad">[REVOKED]</span>' : ''}`
    : `${role}: <em>egykulcsos / nincs idovonal</em>`;

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(model.title)}</title>
<style>
  body { font: 15px/1.5 -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; color: #1f2328; max-width: 960px; margin: 2rem auto; padding: 0 1rem; }
  h1 { font-size: 1.6rem; margin-bottom: .2rem; } h2 { font-size: 1.2rem; margin-top: 2rem; border-bottom: 1px solid #d0d7de; padding-bottom: .3rem; }
  .banner { color: #fff; padding: 1rem 1.25rem; border-radius: 8px; font-size: 1.25rem; font-weight: 700; letter-spacing: .02em; }
  .meta { color: #57606a; font-size: .9rem; margin: .3rem 0 1.5rem; }
  table { border-collapse: collapse; width: 100%; margin: .5rem 0; font-size: .92rem; }
  th, td { text-align: left; padding: .45rem .6rem; border-bottom: 1px solid #eaeef2; vertical-align: top; }
  th { background: #f6f8fa; font-weight: 600; }
  code { background: #f6f8fa; padding: .1rem .3rem; border-radius: 4px; font-size: .85em; }
  .ok { color: #1a7f37; font-weight: 600; } .bad { color: #b3261e; font-weight: 700; }
  .note { background: #fff8c5; border: 1px solid #d4a72c; border-radius: 6px; padding: .8rem 1rem; font-size: .9rem; margin: 1rem 0; }
  footer { margin-top: 2.5rem; color: #57606a; font-size: .82rem; border-top: 1px solid #d0d7de; padding-top: 1rem; }
</style></head>
<body>
<h1>${esc(model.title)}</h1>
<div class="meta">Generated ${esc(model.generated_at)} · log <code>${esc(model.log.log_id || '(n/a)')}</code></div>

<div class="banner" style="background:${verdictColor}">${esc(verdictText)}</div>
<div class="note"><strong>How to read this report.</strong> The verdict above is the exit
result of the independent AXR verifier (<code>${esc(v.source)}</code>, exit code
<code>${esc(v.code)}</code>). This document is a <em>human-readable view</em> over what the
verifier proves — it does not replace independent verification, and it asserts nothing it did
not check. AXR is an evidence layer: it proves a record was not altered, suppressed or
backdated after the fact, not that it was correct when made (see Limits below).</div>

<h2>1. Log overview</h2>
<table>
${kv('Receipts (total)', model.log.receipts)}
${kv('Workflows / steps', model.log.workflows + ' / ' + model.log.steps)}
${kv('Versions', Object.entries(model.log.versions).map(([k, n]) => k + ': ' + n).join(', '))}
${kv('Time range', (model.log.time_from || '—') + '  →  ' + (model.log.time_to || '—'))}
${kv('Signed Tree Heads', model.integrity.sth_count)}
</table>

<h2>2. Integrity</h2>
<table>
${kv('Signatures valid', model.integrity.signatures_ok)}
${row([`<strong>Signatures invalid</strong>`, model.integrity.signatures_bad > 0 ? `<span class="bad">${model.integrity.signatures_bad}</span>` : '<span class="ok">0</span>'])}
${kv('Anchored receipts', model.anchoring.anchored + ' (pending: ' + model.anchoring.pending + ')')}
${kv('Anchor backends', model.anchoring.backends.join(', ') || '—')}
</table>

<h2>3. Key governance</h2>
<table>
${kv('Trust-root mode', model.governance.trust_root_mode || 'none (TOFU pinning)')}
${model.governance.trust_root_fingerprints ? kv('Root key fingerprints', model.governance.trust_root_fingerprints) : ''}
${row([`<strong>Active key (at largest tree)</strong>`, akLine('sth') + '<br>' + akLine('receipt')])}
</table>
${model.governance.events.length ? `<table><tr><th>Role</th><th>Kind</th><th>Effective from</th><th>Fingerprint</th><th>Status</th><th>Revocation</th></tr>${govRows}</table>` : '<p><em>No key-governance timeline (single-key / no trust root).</em></p>'}
${model.governance.problems.length ? `<div class="note"><strong>Timeline notes:</strong><br>${model.governance.problems.map(esc).join('<br>')}</div>` : ''}

${model.control ? `<h2>4. Control log (governance distribution)</h2>
<table>
${kv('Committing STHs', model.control.committedSthCount)}
${kv('Committed governance-set size', model.control.maxControlSize)}
${kv('Control records supplied', model.control.hasControlLog ? model.control.controlRecords : 'NOT SUPPLIED')}
</table>` : ''}

<h2>${model.control ? '5' : '4'}. Privacy &amp; side-effects</h2>
<table>
${kv('Redactable receipts', model.privacy.redactable_receipts)}
${kv('Redacted fields', model.privacy.redacted_fields)}
${kv('Side-effects (attested)', model.privacy.side_effects + ' (' + model.privacy.attested_side_effects + ')')}
</table>

<h2>${model.control ? '6' : '5'}. Compliance control mapping</h2>
<p class="meta">Orientation mapping (non-normative, not legal advice) — see COMPLIANCE.md.</p>
<table><tr><th>Framework</th><th>Reference</th><th>Expectation</th><th>AXR mechanism</th><th>Honest caveat</th></tr>${ctrlRows}</table>

<h2>${model.control ? '7' : '6'}. Limits (what this evidence does NOT establish)</h2>
<ul>
<li><strong>Not proof of truth at signing (N1).</strong> AXR proves a record was not altered, suppressed or backdated — not that it was honest when made.</li>
<li><strong>Not protection against a stolen key (N2).</strong> Key succession/revocation bound the damage; they do not prevent a compromised key from signing.</li>
<li><strong>Not effective without a monitor (N4).</strong> The anti-tampering guarantees become actual only when an independent party runs the Monitor.</li>
<li><strong>Not legal compliance.</strong> AXR is a technical control, not a compliance programme.</li>
</ul>

<footer>Generated by axr-report (AXR Compliance Report Generator). This report is reproducible:
the same inputs yield the same report (generation timestamp aside). Verify independently with
<code>axr-verify.js</code> / <code>axr_verify.py</code>.</footer>
</body></html>
`;
}

module.exports = { buildReportModel, renderHtml, renderJson, complianceControls };

// ── CLI ──────────────────────────────────────────────────────────────────────
if (require.main === module) {
  const fs = require('fs');
  const path = require('path');
  const { execFileSync } = require('child_process');

  const argv = process.argv.slice(2);
  const positional = [];
  const flags = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith('--')) { flags[argv[i].slice(2)] = argv[i + 1]; i++; }
    else positional.push(argv[i]);
  }
  const [logPath, keyPath, sthPath, anchorPath] = positional;
  if (!logPath || !keyPath) {
    console.error('Hasznalat: node axr-report.js <receipts.jsonl> <public-key.pem> [sth.jsonl] [anchors.jsonl]\n' +
      '            [--trust-root <json>] [--successions <jsonl>] [--revocations <jsonl>] [--control <jsonl>]\n' +
      '            [--sth-key <pem>] [--log-id <id>] [--out <fajl>] [--format html|json] [--title <szoveg>]');
    process.exit(2);
  }
  const readJsonl = (p) => p && fs.existsSync(p)
    ? fs.readFileSync(p, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse) : [];
  const readMaybe = (p) => p ? fs.readFileSync(p, 'utf8') : null;

  // 1. hiteles verdikt: az axr-verify.js futtatasa UGYANAZOKKAL a flagekkel
  function runVerifier() {
    const args = [path.join(__dirname, 'axr-verify.js'), logPath, keyPath];
    if (sthPath) args.push(sthPath);
    if (anchorPath) args.push(anchorPath);
    for (const f of ['trust-root', 'successions', 'revocations', 'control', 'sth-key', 'log-id'])
      if (flags[f]) args.push('--' + f, flags[f]);
    try { execFileSync('node', args, { stdio: 'pipe' }); return { code: 0, ok: true, source: 'axr-verify.js' }; }
    catch (e) { return { code: e.status == null ? -1 : e.status, ok: false, source: 'axr-verify.js' }; }
  }

  const trustRoot = flags['trust-root']
    ? succ.parseTrustRootInput(fs.readFileSync(flags['trust-root'], 'utf8')) : null;
  const model = buildReportModel({
    receipts: readJsonl(logPath),
    sths: readJsonl(sthPath).filter(r => r.record_type === 'sth'),
    anchors: readJsonl(anchorPath).filter(r => r.record_type === 'anchor'),
    publicKeyPem: readMaybe(keyPath),
    sthKeyPem: readMaybe(flags['sth-key']),
    trustRoot,
    successions: flags.successions ? readJsonl(flags.successions) : null,
    revocations: flags.revocations ? readJsonl(flags.revocations) : null,
    control: flags.control ? readJsonl(flags.control) : null,
    logId: flags['log-id'],
    title: flags.title,
    verdict: runVerifier()
  });

  const out = (flags.format === 'json') ? renderJson(model) : renderHtml(model);
  if (flags.out) { fs.writeFileSync(flags.out, out); console.error('Riport kiirva: ' + flags.out + ' (verdikt: ' + (model.verdict.ok ? 'PASS' : 'FAIL') + ')'); }
  else process.stdout.write(out);
  process.exit(model.verdict.ok ? 0 : 1);
}
