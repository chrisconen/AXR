#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════════════════════
// AXR - "records its own making": a fejlesztesi naplo -> AXR receipt-log
// ═══════════════════════════════════════════════════════════════════════════════
// A multi-AI munkapad kozos naploja (agents/journal.jsonl) maga egy execution
// trail: mit/miert/mikor, agensenkent attribualva. Ez a generator azt AXR
// receipt-logga alakitja - igy a projekt SAJAT fejlodese verifikalhato AXR-loggá
// valik, a teljes 1.0 stacken (anchor -> monitor -> witness -> verifier).
//
// Lekepezes: minden journal-bejegyzes egy 'step' receipt; az egesz naplo egy
// 'workflow' receipt, ami csoportositja. A bejegyzes mezoi:
//   agent -> a step actora (step.node_name = az AI agens neve)
//   what  -> a lepes leirasa (io.input_summary.what)
//   why   -> a dontes indoka (io.input_summary.why)
//   refs  -> az erintett fajlok (io.input_summary.refs)
//   ts    -> a receipt timestampje
// Az io.input_hash a bejegyzes KANONIKUS hash-e (tartalom-kotes): ha a naplo
// barmely bejegyzese valtozik, a receipt alairasa torik.
//
// OSZINTE HATAR (N1): a receiptek azt bizonyitjak, hogy a naplo NEM valtozott
// az alairas ota - NEM azt, hogy a bejegyzesek igazak voltak iraskor. A demo
// a MECHANIZMUST mutatja valos adaton, nem igazsagot bizonyit.
//
// Determinisztikus: ugyanaz a journal + kulcs ugyanazt a receipt-logot adja
// (a receipt_id a bejegyzes-tartalombol szarmazik, nem random). Zero-dep.
//
// Hasznalat:
//   node axr-journal-receipts.js <journal.jsonl> <signing-key.pem> [--log-id id] [--out receipts.jsonl]
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const core = require('./axr-core');

const JOURNAL_LOG_ID = 'axr:devlog:v1';

// Egy journal-bejegyzes -> step receipt body (alairas nelkul).
function entryToStepBody(entry, sequence, prevHash, logId) {
  // determinisztikus receipt_id a bejegyzes tartalmabol (nem random uuid)
  const idSeed = core.sha256({ ts: entry.ts, agent: entry.agent, what: entry.what, seq: sequence });
  return {
    axr_version: '0.3',
    receipt_type: 'step',
    receipt_id: 'devlog-' + idSeed.replace(/^sha256:/, '').slice(0, 24),
    workflow_receipt_id: logId,
    sequence,
    timestamp: entry.ts,
    step: {
      node_name: entry.agent,                 // az aktiv AI agens (fable/meridian/nexus/qwen/chris)
      node_type: 'axr.devlog.entry',
      kind: 'deterministic', deterministic: true, model: null
    },
    io: {
      // tartalom-kotes: a teljes bejegyzes kanonikus hash-e
      input_hash: core.sha256({ ts: entry.ts, agent: entry.agent, what: entry.what, why: entry.why, refs: entry.refs || [] }),
      output_hash: null,
      input_summary: { what: entry.what, why: entry.why, refs: entry.refs || [] },
      decision: null
    },
    inputs: [], approval: null, previous_receipt_hash: prevHash, anchor_ref: null
  };
}

// A teljes naplo -> receipts.jsonl (step-ek + egy workflow-wrapper), alairva.
//   journalEntries: a beolvasott bejegyzesek tombje
//   signKeyPem:     a dev-log alairo kulcsa
//   logId:          a log azonositoja
// -> { receipts, workflowHash }
function buildJournalReceipts(journalEntries, signKeyPem, logId) {
  logId = logId || JOURNAL_LOG_ID;
  const sign = (body) => { const r = { ...body }; delete r.signature; r.signature = core.signReceipt(r, signKeyPem); return r; };
  const steps = [];
  let prev = null;
  journalEntries.forEach((entry, i) => {
    const st = sign(entryToStepBody(entry, i + 1, prev, logId));
    steps.push(st);
    prev = core.chainHash(st);
  });
  const agents = [...new Set(journalEntries.map(e => e.agent))].sort();
  const wf = sign({
    axr_version: '0.3', receipt_type: 'workflow', receipt_id: logId,
    workflow: {
      workflow_id: 'axr-development-log', workflow_version: '1.0',
      webhook_path: null,
      trigger_timestamp: journalEntries.length ? journalEntries[0].ts : null,
      completion_timestamp: journalEntries.length ? journalEntries[journalEntries.length - 1].ts : null
    },
    actor: { agent_id: 'conen-digital-multi-ai', agent_type: 'multi-agent-workbench',
             operator: 'conen-digital', on_behalf_of: 'AXR', identity_ref: null },
    request: { input_hash: core.sha256({ entries: journalEntries.length }), customer_ref: null },
    outcome: { final_status: 'DEVELOPMENT_LOG', available: true,
               decision_summary: journalEntries.length + ' attributalt fejlesztesi lepes, agensek: ' + agents.join(', ') },
    step_chain: steps.map(s => s.receipt_id),
    chain_root_hash: steps.length ? core.chainHash(steps[steps.length - 1]) : null,
    approval: null, previous_receipt_hash: null, anchor_ref: null
  });
  return { receipts: [...steps, wf], workflowHash: core.chainHash(wf), agents };
}

module.exports = { buildJournalReceipts, entryToStepBody, JOURNAL_LOG_ID };

// ── CLI ──────────────────────────────────────────────────────────────────────
if (require.main === module) {
  const argv = process.argv.slice(2);
  const positional = [];
  const flags = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith('--')) { flags[argv[i].slice(2)] = argv[i + 1]; i++; }
    else positional.push(argv[i]);
  }
  const [journalPath, keyPath] = positional;
  if (!journalPath || !keyPath) {
    console.error('Hasznalat: node axr-journal-receipts.js <journal.jsonl> <signing-key.pem> [--log-id id] [--out receipts.jsonl]');
    process.exit(2);
  }
  const entries = fs.readFileSync(journalPath, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse);
  const signKeyPem = fs.readFileSync(keyPath, 'utf8');
  const { receipts, agents } = buildJournalReceipts(entries, signKeyPem, flags['log-id']);
  const out = receipts.map(r => JSON.stringify(r)).join('\n') + '\n';
  if (flags.out) { fs.writeFileSync(flags.out, out); console.error(`Dev-log receiptek: ${receipts.length} (${entries.length} bejegyzes, agensek: ${agents.join(', ')}) -> ${flags.out}`); }
  else process.stdout.write(out);
  process.exit(0);
}
