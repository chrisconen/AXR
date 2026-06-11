#!/usr/bin/env node
// Teszt-harness az axr-n8n-node-hu-v0.2.3.js-hez.
// Szimulalja az n8n $()/$ input kornyezetet, lefuttatja a node-ot egy
// realisztikus sikeres foglalasi vegrehajtassal, majd a repo sajat
// verifierevel (axr-verify.js) ellenorzi a keletkezett receipteket.
// Tovabbi esetek: fail-open (hianyzo kulcs), canonicalize guard (NaN).

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const NODE_CODE_RAW = fs.readFileSync(path.join(__dirname, 'axr-n8n-node-hu-v0.2.3.js'), 'utf8');
// a sandbox-szimulacioban nincs process.env -> a default AXR_DIR konstanst
// iranyitjuk at a teszt tmp konyvtaraba (a process.env.AXR_DIR a node-ban
// csak NEM-sandbox kornyezetben el, pl. CLI-tesztek)
let NODE_CODE = NODE_CODE_RAW;
function setAxrDir(d) {
  NODE_CODE = NODE_CODE_RAW.replace("|| '/home/node/.n8n/axr'", `|| ${JSON.stringify(d)}`);
}

let failures = 0;
function check(name, cond, extra) {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${cond || !extra ? '' : ' - ' + extra}`);
  if (!cond) failures++;
}

// ── n8n kornyezet-szimulacio ───────────────────────────────────────────────────
function makeEnv(nodeOutputs, inputItems) {
  const $ = (name) => ({
    all: () => {
      if (!(name in nodeOutputs)) throw new Error(`No node ${name}`);
      return nodeOutputs[name].map(j => ({ json: j }));
    }
  });
  const $input = { all: () => inputItems.map(j => ({ json: j })) };
  return { $, $input };
}

function runNode(env) {
  // n8n-sandbox szimulacio: a 'process' parameterkent UNDEFINED - pontosan
  // mint az eles Code node-ban. Ha a node kod guard nelkul nyulna hozza,
  // itt is elbukna, ahogy elesben tette (v0.2.3 regresszio).
  const fn = new Function('$', '$input', 'require', 'process', NODE_CODE);
  return fn(env.$, env.$input, require, undefined);
}

// ── Realisztikus sikeres foglalas adatai ───────────────────────────────────────
const webhookBody = {
  name: 'Teszt Elek', email: 'teszt.elek@example.com', phone: '+36301234567',
  date: '2026-06-15', totalDuration: 120, slotStartTime: '10:00',
  locationData: { city: 'Budapest' }, validation: { hasItems: true },
  items: [{ service: 'windows', qty: 4 }]
};
const normalizeOut = [{
  body: { ...webhookBody },
  originalPayload: { ...webhookBody },
  __axr_input: [{ body: webhookBody }]
}];
const checkDayOut = [{ id: 'evt1', summary: 'Existing', __axr_input: normalizeOut.map(({__axr_input, ...r}) => r) }];
const brainOut = [{
  available: true, status: 'SLOT_AVAILABLE',
  cluster: { id: 'BUDAPEST', country: 'HU' },
  slot: { startTime: '10:00', endTime: '12:00' },
  calendar: { travelBufferApplied: 30 },
  __axr_input: [{ events: 1 }]
}];
const freshOut = [{ id: 'evt1', __axr_input: brainOut.map(({__axr_input, ...r}) => r) }];
const slotFreeOut = [{ slotFree: true, __axr_input: [{ id: 'evt1' }] }];
const createOut = [{ id: 'newEvt', htmlLink: 'https://cal/x', __axr_input: [{ slotFree: true }] }];

const happyOutputs = {
  'Normalize Payload - HU': normalizeOut,
  'Check Day Schedule': checkDayOut.map(({__axr_input, ...r}) => r),
  'AXR Mark: Check Day Schedule': checkDayOut,
  'The Brain (Logic)': brainOut,
  'Fresh Calendar Check': freshOut.map(({__axr_input, ...r}) => r),
  'AXR Mark: Fresh Calendar Check': freshOut,
  'Slot Still Free?': slotFreeOut,
  'Create Booking': createOut.map(({__axr_input, ...r}) => r),
  'AXR Mark: Create Booking': createOut
};

// ── 1. eset: sikeres futas + verifier ──────────────────────────────────────────
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-'));
setAxrDir(dir);
const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
fs.writeFileSync(path.join(dir, 'signing-key.pem'),
  privateKey.export({ type: 'pkcs8', format: 'pem' }));
const pubPath = path.join(dir, 'public-key.pem');
fs.writeFileSync(pubPath, publicKey.export({ type: 'spki', format: 'pem' }));

const sthKp = crypto.generateKeyPairSync('ed25519');
fs.writeFileSync(path.join(dir, 'sth-key.pem'), sthKp.privateKey.export({ type: 'pkcs8', format: 'pem' }));

let out = runNode(makeEnv(happyOutputs, [{ success: true }]));
const ax = out[0].json.__axr;
check('fut es receiptet general', ax && ax.step_count === 6 && !ax.error, JSON.stringify(ax));
check('nincs warning (teljes marker-fedettseg)', ax.warnings.length === 0, JSON.stringify(ax.warnings));

const logPath = path.join(dir, 'receipts-hu.jsonl');
const lines = fs.readFileSync(logPath, 'utf8').trim().split('\n').map(JSON.parse);
const wfRec = lines.find(r => r.receipt_type === 'workflow');
const brainStep = lines.find(r => r.receipt_type === 'step' && r.step.node_name === 'The Brain (Logic)');
check('logic_version frissult (Brain 5.1 HU)', brainStep.step.logic_version === '5.1 HU');
check('logic_hash jelen van a step receiptben', /^sha256:[0-9a-f]{64}$/.test(brainStep.step.logic_hash || ''));
check('customer_ref HMAC-os', /^hmac-sha256:[0-9a-f]{64}$/.test(wfRec.request.customer_ref || ''), wfRec.request.customer_ref);
check('pepper letrejott 600-as moddal',
  fs.existsSync(path.join(dir, 'customer-pepper.key')) &&
  (fs.statSync(path.join(dir, 'customer-pepper.key')).mode & 0o777) === 0o600);

// masodik futas: a lanc folytatodik + a pepper stabil (azonos ugyfel = azonos ref)
let out2 = runNode(makeEnv(happyOutputs, [{ success: true }]));
const lines2 = fs.readFileSync(logPath, 'utf8').trim().split('\n').map(JSON.parse);
const wfRecs = lines2.filter(r => r.receipt_type === 'workflow');
check('masodik workflow receipt lancolodik az elsohoz', wfRecs[1].previous_receipt_hash !== null);
check('azonos ugyfel azonos customer_ref (stabil pepper)',
  wfRecs[0].request.customer_ref === wfRecs[1].request.customer_ref);

// hivatalos verifier a teljes logon
let verifierOk = true, verifierOut = '';
try {
  verifierOut = execFileSync('node',
    [path.join(__dirname, 'axr-verify.js'), logPath, pubPath], { encoding: 'utf8' });
} catch (e) {
  verifierOk = false; verifierOut = (e.stdout || '') + (e.stderr || '');
}
check('hivatalos axr-verify.js elfogadja a logot', verifierOk, verifierOut.split('\n').slice(-6).join(' | '));

// tamper: egy bajt valtoztatas a Brain dontesben -> a verifiernek buknia kell
const tampered = lines2.map(r => {
  if (r.receipt_type === 'step' && r.step.node_name === 'The Brain (Logic)' && r.io.decision) {
    return { ...r, io: { ...r.io, decision: { ...r.io.decision, available: false } } };
  }
  return r;
});
const tamperPath = path.join(dir, 'tampered.jsonl');
fs.writeFileSync(tamperPath, tampered.map(r => JSON.stringify(r)).join('\n') + '\n');
let tamperCaught = false;
try {
  execFileSync('node', [path.join(__dirname, 'axr-verify.js'), tamperPath, pubPath], { encoding: 'utf8' });
} catch (e) { tamperCaught = true; }
check('tamper-elt log elbukik a verifieren', tamperCaught);

// ── 2. eset: fail-open hianyzo kulccsal ────────────────────────────────────────
const dir2 = fs.mkdtempSync(path.join(os.tmpdir(), 'axr-'));
setAxrDir(dir2); // nincs benne signing-key.pem
let outFail = runNode(makeEnv(happyOutputs, [{ success: true }]));
const axFail = outFail[0].json.__axr;
check('fail-open: passthrough tovabbra is valaszol', outFail.length === 1 && outFail[0].json.success === true);
check('fail-open: a hiba hangos a __axr.error-ban', typeof axFail.error === 'string' && axFail.error.includes('elbukott'));

// ── 3. eset: canonicalize guard - NaN a node-kimenetben ────────────────────────
setAxrDir(dir); // ervenyes kulcs vissza
const poisoned = { ...happyOutputs,
  'The Brain (Logic)': [{ ...brainOut[0], badScore: NaN }] };
let outNaN = runNode(makeEnv(poisoned, [{ success: true }]));
const axNaN = outNaN[0].json.__axr;
check('NaN a kimenetben: hangos hiba, nem nema korrupcio',
  typeof axNaN.error === 'string' && /NaN|Infinity/.test(axNaN.error), JSON.stringify(axNaN));
check('NaN-eset is fail-open: a foglalas valaszol', outNaN[0].json.success === true);

// ── 4. eset (v0.2.2 regresszio): lancolas HORGONYZOTT log folott ──────────────
// A sidecar anchor_ref-et ir vissza a lemezre; az uj receipt previous_receipt_hash-ének
// chainHash-szemantikaval (anchor_ref nelkul) kell keszulnie, kulonben a lanc torik.
setAxrDir(dir);
const anchorExit = (() => { try {
  execFileSync('node', [path.join(__dirname, 'axr-anchor.js'), logPath,
    path.join(dir, 'sth-key.pem'), '--sth', path.join(dir, 'sth.jsonl'),
    '--anchors', path.join(dir, 'anchors.jsonl'), '--backend', 'local',
    '--log-id', 'axr:harness:v1'], { encoding: 'utf8' }); return 0;
} catch (e) { return e.status; } })();
check('sidecar lefut a harness-logon', anchorExit === 0);
runNode(makeEnv(happyOutputs, [{ success: true }]));   // foglalas a horgonyzas UTAN
let postAnchorOk = true;
try { execFileSync('node', [path.join(__dirname, 'axr-verify.js'), logPath, pubPath],
  { encoding: 'utf8' }); } catch (e) { postAnchorOk = false; }
check('horgonyzas utani uj receipt: a lanc folytonos marad', postAnchorOk);

console.log(failures === 0 ? '\nMINDEN TESZT ZOLD' : `\n${failures} TESZT BUKOTT`);
process.exit(failures === 0 ? 0 : 1);
