// ═══════════════════════════════════════════════════════════════════════════════
// AXR 0.4 - Side-effect attestation (N1 mitigacio) end-to-end
// ═══════════════════════════════════════════════════════════════════════════════
// Futtatas:  node axr-sideeffect-test.js
//
// Egy "Create Booking" lepes ket side-effect bejegyzest hordoz:
//   - RECHECKABLE: a naptar-event referenciaja + a valasz hashe, provider-alairas
//     nelkul. Egy auditor fuggetlenul ujra le tudja kerdezni - oszinte N1-mersekles.
//   - ATTESTED: a (szimulalt) szolgaltato sajat kulccsal co-signolja a bejegyzest.
//     Ez kriptografiailag egy az operatortol FUGGETLEN felhez koti az esemenyt.
//
// Mit ellenoriz:
//   1. ep log (recheckable + attested side-effect) -> verifier 0
//   2. core.verifySideEffect: az attesztalt bejegyzes attested=true
//   3. a teljes pipeline horgonyzassal is 0
//   4. NEGATIV: az attesztalt bejegyzes utolagos hamisitasa (operator re-sign,
//      provider attestation marad) -> provider-attestation bukik -> verifier 1
//   5. NEGATIV: hianyos side-effect (nincs reference, operator re-sign) -> verifier 1
//
// Nulla kulso fuggoseg.  Kilepesi kod: 0 ha minden zold, 1 ha barmi megbukik.
// ═══════════════════════════════════════════════════════════════════════════════

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const core = require('./axr-core');
const { runAnchor } = require('./axr-anchor');

let passed = 0;
async function check(name, fn) {
  try { await fn(); passed++; console.log(`  ok  - ${name}`); }
  catch (e) { console.log(`  HIBA - ${name}\n        ${e.message}`); process.exitCode = 1; }
}

// operator + (kulonallo) provider kulcspar
const op = crypto.generateKeyPairSync('ed25519');
const opPriv = op.privateKey.export({ type: 'pkcs8', format: 'pem' });
const opPub = op.publicKey.export({ type: 'spki', format: 'pem' });
const prov = crypto.generateKeyPairSync('ed25519');
const provPriv = prov.privateKey.export({ type: 'pkcs8', format: 'pem' });
const provPub = prov.publicKey.export({ type: 'spki', format: 'pem' });

const sign = (o) => { const r = { ...o }; delete r.signature; r.signature = core.signReceipt(r, opPriv); return r; };

// A naptar-API valaszanak hashe (amit az auditor ujra le tudna kerdezni)
const calendarResponse = { id: 'evt_abc123', status: 'confirmed', start: '2026-06-15T14:00', end: '2026-06-15T15:25' };

function buildLog() {
  const wfId = core.uuid();

  // recheckable side-effect: kulso referencia + valasz-hash, provider-alairas nelkul
  const recheckable = {
    type: 'calendar.event.created', provider: 'google-calendar',
    reference: 'evt_abc123', evidence_hash: core.sha256(calendarResponse),
    occurred_at: '2026-06-08T08:00:00.000Z'
  };
  // attested side-effect: a provider co-signolja (fuggetlen kulcs)
  const attested = core.attestSideEffect({
    type: 'payment.authorized', provider: 'stripe',
    reference: 'pi_xyz789', evidence_hash: core.sha256({ id: 'pi_xyz789', amount: 12000, currency: 'huf' }),
    occurred_at: '2026-06-08T08:00:01.000Z'
  }, provPriv, provPub);

  const step = sign({
    axr_version: '0.4', receipt_type: 'step', receipt_id: core.uuid(),
    workflow_receipt_id: wfId, sequence: 1, timestamp: '2026-06-08T08:00:00.000Z',
    step: { node_name: 'Create Booking', node_type: 'n8n-nodes-base.googleCalendar',
            kind: 'deterministic', deterministic: true, model: null },
    io: { input_hash: core.sha256('cb-in'), output_hash: core.sha256('cb-out'), input_summary: {},
          decision: { status: 'ANCHOR_BOOKING', available: true } },
    inputs: [], approval: null, previous_receipt_hash: null, anchor_ref: null,
    side_effects: [recheckable, attested]
  });

  const wf = sign({
    axr_version: '0.4', receipt_type: 'workflow', receipt_id: wfId,
    workflow: { workflow_id: 'wf', workflow_version: '1', webhook_path: 'p', trigger_timestamp: 't', completion_timestamp: 't' },
    actor: { agent_id: 'a', agent_type: 'n8n-workflow', operator: 'op', on_behalf_of: 'cust', identity_ref: null },
    request: { input_hash: core.sha256('raw'), customer_ref: core.customerRef('a', 'b', 'c') },
    outcome: { final_status: 'ANCHOR_BOOKING', available: true, decision_summary: 'foglalva' },
    step_chain: [step.receipt_id], chain_root_hash: core.chainHash(step),
    approval: null, previous_receipt_hash: null, anchor_ref: null
  });

  return { step, wf };
}

function writeAndVerify(dir, receipts, withAnchors) {
  const kp = path.join(dir, 'public-key.pem');
  fs.writeFileSync(kp, opPub);
  fs.writeFileSync(path.join(dir, 'receipts.jsonl'), receipts.map(r => JSON.stringify(r)).join('\n') + '\n');
  const args = [path.join(__dirname, 'axr-verify.js'), path.join(dir, 'receipts.jsonl'), kp];
  if (withAnchors) args.push(path.join(dir, 'sth.jsonl'), path.join(dir, 'anchors.jsonl'));
  try { return { code: 0, out: execFileSync('node', args, { encoding: 'utf8' }) }; }
  catch (e) { return { code: e.status == null ? -1 : e.status, out: (e.stdout || '').toString() }; }
}

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-se-'));
  const log = buildLog();

  await check('core.verifySideEffect: attesztalt bejegyzes attested=true, recheckable ok', () => {
    const a = core.verifySideEffect(log.step.side_effects[1]);
    assert.ok(a.ok && a.attested, 'az attesztalt bejegyzes nem attested: ' + JSON.stringify(a.problems));
    const r = core.verifySideEffect(log.step.side_effects[0]);
    assert.ok(r.ok && !r.attested, 'a recheckable bejegyzes statusa rossz: ' + JSON.stringify(r.problems));
  });

  await check('ep log (recheckable + attested) -> verifier 0', () => {
    const res = writeAndVerify(dir, [log.step, log.wf], false);
    assert.strictEqual(res.code, 0, `a verifier nem 0:\n${res.out}`);
    assert.ok(/provider-attesztalt/.test(res.out), 'az osszegzes nem jelzi az attesztaciot');
  });

  await check('teljes pipeline: sidecar horgonyzas + verifier (anchors) -> 0', async () => {
    const rp = path.join(dir, 'receipts.jsonl');
    const r = await runAnchor({ receiptsPath: rp, privateKeyPem: opPriv, backends: ['local'],
      now: () => '2026-06-08T08:00:02.000Z' });
    assert.ok(r.created && r.anchored === 2, `2 levelt kellett horgonyozni, lett: ${r.anchored}`);
    // a runAnchor helyben irta az anchor_ref-et; kozvetlenul a horgonyzott fajlon verifikalunk
    const kp = path.join(dir, 'public-key.pem'); fs.writeFileSync(kp, opPub);
    let code, out = '';
    try {
      out = execFileSync('node', [path.join(__dirname, 'axr-verify.js'), rp, kp,
        path.join(dir, 'sth.jsonl'), path.join(dir, 'anchors.jsonl')], { encoding: 'utf8' });
      code = 0;
    } catch (e) { code = e.status; out = (e.stdout || '').toString(); }
    assert.strictEqual(code, 0, `a horgonyzott log nem verifikal:\n${out}`);
  });

  await check('NEGATIV: attesztalt side-effect hamisitasa (operator re-sign) -> verifier 1', () => {
    const d2 = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-se-n1-'));
    const l = buildLog();
    // a payment referenciat atirjuk, de a provider-attestationt NEM ujrazzuk;
    // az operator viszont ujraalairja a receiptet (igy a sajat alairas ervenyes marad)
    l.step.side_effects[1].reference = 'pi_HAMISITOTT';
    delete l.step.signature; l.step.signature = core.signReceipt(l.step, opPriv);
    const res = writeAndVerify(d2, [l.step, l.wf], false);
    assert.strictEqual(res.code, 1, `a provider-attestation serulest nem fogta el:\n${res.out}`);
    assert.ok(/ERVENYTELEN/.test(res.out), 'nem a provider-attestation alairasat jelezte');
    fs.rmSync(d2, { recursive: true, force: true });
  });

  await check('NEGATIV: hianyos side-effect (nincs reference, re-sign) -> verifier 1', () => {
    const d3 = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-se-n2-'));
    const l = buildLog();
    delete l.step.side_effects[0].reference;
    delete l.step.signature; l.step.signature = core.signReceipt(l.step, opPriv);
    const res = writeAndVerify(d3, [l.step, l.wf], false);
    assert.strictEqual(res.code, 1, `a hianyos side-effectet nem fogta el:\n${res.out}`);
    fs.rmSync(d3, { recursive: true, force: true });
  });

  fs.rmSync(dir, { recursive: true, force: true });
  console.log('-'.repeat(72));
  if (process.exitCode === 1) {
    console.log(`EREDMENY: NEM minden teszt zold (${passed} sikeres). Lasd a [HIBA] sorokat.`);
  } else {
    console.log(`EREDMENY: mind a ${passed} teszt zold. A side-effect attestation (N1 mitigacio) mukodik.`);
  }
})();
