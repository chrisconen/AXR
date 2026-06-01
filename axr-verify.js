// ═══════════════════════════════════════════════════════════════════════════════
// AXR Verifier v0.2 - receipt-lanc integritas ellenorzes
// ═══════════════════════════════════════════════════════════════════════════════
// Hasznalat:  node axr-verify.js <receipts.jsonl> <public-key.pem>
//
// Ellenoriz:
//   1. minden receipt alairasa ervenyes-e (ed25519)
//   2. a step-lancok folytonosak-e minden workflow-n belul
//   3. a chain_root_hash egyezik-e az utolso lepessel
//   4. a step_chain ID-lista egyezik-e a tenyleges lepesekkel
//   5. a workflow-receiptek osszelancoltak-e
//   6. minden step-nek van-e letezo szulo workflow-receiptje
//
// VERZIO-KEZELES (0.2):
//   A verifier a receipt sajat axr_version mezoje szerint agazik el. A regi
//   0.1 lancok TOVABBRA IS ERVENYESEK - a kriptografiai integritas (alairas,
//   hash-lanc) verziotol fuggetlen. A kulonbseg az input_hash ELLENORZESEBEN
//   van: 0.2-ben az input_hash a lepes tenyleges inputjabol szamol, ezert nem
//   lehet trivialisan uniform a lanc menten - a verifier ezt a 0.2 lepeseknel
//    extra ellenorzeskent jelzi (a regi 7.1 bug visszacsuszasanak detektalasa).
//
// Nulla kulso fuggoseg - csak a Node beepitett crypto es fs modulja.
// Kilepesi kod: 0 ha minden rendben, 1 ha barmi hiba, 2 ha rossz hasznalat.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const fs = require('fs');

const [,, logPath, keyPath] = process.argv;
if (!logPath || !keyPath) {
  console.error('Hasznalat: node axr-verify.js <receipts.jsonl> <public-key.pem>');
  process.exit(2);
}

// ── Kanonikus szerializalas - ugyanaz, mint a generatorban ────────────────────
function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalize(value[k])).join(',') + '}';
}
function sha256(value) {
  const input = typeof value === 'string' ? value : canonicalize(value);
  return 'sha256:' + crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}
function verifySignature(receipt, publicKey) {
  const { signature, ...rest } = receipt;
  if (!signature) return false;
  try {
    return crypto.verify(null, Buffer.from(canonicalize(rest), 'utf8'),
      publicKey, Buffer.from(signature, 'base64'));
  } catch (e) { return false; }
}

// ── Beolvasas ──────────────────────────────────────────────────────────────────
let publicKey;
try {
  publicKey = crypto.createPublicKey(fs.readFileSync(keyPath, 'utf8'));
} catch (e) {
  console.error('HIBA: a publikus kulcs nem olvashato: ' + e.message);
  process.exit(2);
}
let lines;
try {
  lines = fs.readFileSync(logPath, 'utf8').trim().split('\n').filter(Boolean);
} catch (e) {
  console.error('HIBA: a receipt-fajl nem olvashato: ' + e.message);
  process.exit(2);
}

let problems = 0;
const problem = (msg) => { problems++; console.log('  [HIBA] ' + msg); };
const notice  = (msg) => { console.log('  [megj] ' + msg); };

// ── Verzio-osszehasonlitas helper ──────────────────────────────────────────────
// "0.2" >= "0.2" -> true ; "0.1" >= "0.2" -> false. Egyszeru major.minor parse,
// elegendo amig a verzio "X.Y" formatumu.
function versionAtLeast(v, min) {
  if (!v) return false;
  const pa = String(v).split('.').map(Number);
  const pb = String(min).split('.').map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const a = pa[i] || 0, b = pb[i] || 0;
    if (a > b) return true;
    if (a < b) return false;
  }
  return true;
}

// ── 1. Parse + alairas-ellenorzes ──────────────────────────────────────────────
const receipts = [];
for (let i = 0; i < lines.length; i++) {
  let r;
  try { r = JSON.parse(lines[i]); }
  catch (e) { problem(`${i+1}. sor: ervenytelen JSON`); continue; }
  if (!verifySignature(r, publicKey)) {
    problem(`${r.receipt_type || '?'} ${r.receipt_id || '(nincs id)'}: ERVENYTELEN ALAIRAS ` +
            `- a receipt tartalma megvaltozott az alairas ota, vagy mas kulccsal keszult`);
  }
  receipts.push(r);
}

const workflows = receipts.filter(r => r.receipt_type === 'workflow');
const steps     = receipts.filter(r => r.receipt_type === 'step');

// ── Verzio-attekintes ──────────────────────────────────────────────────────────
const versionCounts = {};
for (const r of receipts) {
  const v = r.axr_version || '(nincs)';
  versionCounts[v] = (versionCounts[v] || 0) + 1;
}

// ── Step-ek csoportositasa workflow szerint ────────────────────────────────────
const stepsByWf = {};
for (const s of steps) {
  (stepsByWf[s.workflow_receipt_id] ||= []).push(s);
}

// ── 2-4. Minden workflow belso ellenorzese ─────────────────────────────────────
for (const wf of workflows) {
  const wfSteps = (stepsByWf[wf.receipt_id] || []).slice().sort((a,b) => a.sequence - b.sequence);

  // step-lanc folytonossag
  for (let i = 0; i < wfSteps.length; i++) {
    const expectedPrev = i === 0 ? null : sha256(wfSteps[i-1]);
    if (wfSteps[i].previous_receipt_hash !== expectedPrev) {
      problem(`workflow ${wf.receipt_id}: a(z) ${i+1}. lepes (${wfSteps[i].step?.node_name}) ` +
              `previous_receipt_hash-e nem egyezik - a lanc megszakadt vagy lepest modositottak`);
    }
  }
  // chain_root_hash
  if (wfSteps.length) {
    const expectedRoot = sha256(wfSteps[wfSteps.length-1]);
    if (wf.chain_root_hash !== expectedRoot) {
      problem(`workflow ${wf.receipt_id}: chain_root_hash nem egyezik az utolso lepessel ` +
              `- lepest tavolitottak el a lanc vegerol`);
    }
  } else {
    if (wf.chain_root_hash !== null) {
      problem(`workflow ${wf.receipt_id}: van chain_root_hash, de nincs egyetlen lepes-receipt sem`);
    }
  }
  // step_chain ID-lista egyezes
  const actualIds = wfSteps.map(s => s.receipt_id).join(',');
  const declaredIds = (wf.step_chain || []).join(',');
  if (actualIds !== declaredIds) {
    problem(`workflow ${wf.receipt_id}: a step_chain ID-lista nem egyezik a tenyleges lepesekkel ` +
            `- lepest toroltek vagy adtak hozza`);
  }

  // ── 0.2 extra: input_hash tartalmi ellenorzes ────────────────────────────────
  // Csak a 0.2 (vagy ujabb) workflow-knal fut. A 0.1 lancoknal az uniform
  // input_hash ISMERT es ELFOGADOTT viselkedes (spec 7.1) - nem hiba.
  if (versionAtLeast(wf.axr_version, '0.2') && wfSteps.length >= 2) {
    const v02steps = wfSteps.filter(s => versionAtLeast(s.axr_version, '0.2'));

    // null input_hash: a node nem hagyott __axr_input markert
    for (const s of v02steps) {
      if (s.io?.input_hash === null || s.io?.input_hash === undefined) {
        notice(`workflow ${wf.receipt_id}: a(z) "${s.step?.node_name}" lepes input_hash-e null ` +
               `- a node nem hagyott __axr_input markert (0.2 konfiguracios hiany, nem manipulacio)`);
      }
    }

    // uniform input_hash: a regi 7.1 bug visszacsuszasanak jele
    const nonNull = v02steps
      .map(s => s.io?.input_hash)
      .filter(h => h !== null && h !== undefined);
    if (nonNull.length >= 2 && new Set(nonNull).size === 1) {
      problem(`workflow ${wf.receipt_id}: minden 0.2 lepes input_hash-e AZONOS ` +
              `- ez a 0.1-es 7.1 hiba: a lepesek nem a sajat inputjukat hash-elik`);
    }
  }
}

// ── 6. Arva step-ek (nincs szulo workflow) ─────────────────────────────────────
const wfIds = new Set(workflows.map(w => w.receipt_id));
for (const wfId of Object.keys(stepsByWf)) {
  if (!wfIds.has(wfId)) {
    problem(`${stepsByWf[wfId].length} db step-receipt a(z) ${wfId} workflow-hoz tartozik, ` +
            `de az a workflow-receipt hianyzik a fajlbol`);
  }
}

// ── 5. Workflow-receiptek osszelancolasa (fajlbeli sorrendben) ─────────────────
for (let i = 0; i < workflows.length; i++) {
  const expectedPrev = i === 0 ? null : sha256(workflows[i-1]);
  if (workflows[i].previous_receipt_hash !== expectedPrev) {
    if (i === 0) {
      // az elso lehet nem-null is, ha a fajl egy korabbi lanc folytatasa - csak figyelmeztetes
      notice(`az elso workflow-receipt previous_receipt_hash-e nem null ` +
             `(${workflows[i].previous_receipt_hash}) - ez akkor helyes, ha a fajl ` +
             `egy korabbi lanc folytatasa`);
    } else {
      problem(`workflow ${workflows[i].receipt_id}: previous_receipt_hash nem egyezik az elozo ` +
              `workflow-receipttel - futast toroltek, atrendeztek vagy modositottak`);
    }
  }
}

// ── Osszegzes ──────────────────────────────────────────────────────────────────
console.log('-'.repeat(72));
console.log(`Fajl:       ${logPath}`);
console.log(`Receiptek:  ${receipts.length} osszesen  (${workflows.length} workflow, ${steps.length} lepes)`);
const verStr = Object.keys(versionCounts).sort()
  .map(v => `${v}: ${versionCounts[v]}`).join(', ');
console.log(`Verziok:    ${verStr}`);
console.log('-'.repeat(72));
for (const wf of workflows) {
  const n = (stepsByWf[wf.receipt_id] || []).length;
  const ts = wf.workflow?.trigger_timestamp || '(nincs idobelyeg)';
  const status = (wf.outcome?.final_status || '?').padEnd(24);
  const ver = (wf.axr_version || '?').padEnd(5);
  console.log(`  ${ts}  v${ver}  ${status}  ${n} lepes`);
}
console.log('-'.repeat(72));
if (problems === 0) {
  console.log('EREDMENY: A TELJES LANC ERVENYES.');
  console.log('Minden alairas helyes, minden hash-lanc folytonos, semmit nem modositottak.');
  process.exit(0);
} else {
  console.log(`EREDMENY: ${problems} PROBLEMA TALALVA. A lanc serult vagy manipulalt.`);
  process.exit(1);
}
