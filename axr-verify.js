// ═══════════════════════════════════════════════════════════════════════════════
// AXR Verifier v0.3 - receipt-lanc integritas + kulso horgonyzas ellenorzes
// ═══════════════════════════════════════════════════════════════════════════════
// Hasznalat:
//   node axr-verify.js <receipts.jsonl> <public-key.pem> [sth.jsonl] [anchors.jsonl]
//
// Ellenoriz (0.1/0.2 - valtozatlan):
//   1. minden receipt alairasa ervenyes-e (ed25519)
//   2. a step-lancok folytonosak-e minden workflow-n belul
//   3. a chain_root_hash egyezik-e az utolso lepessel
//   4. a step_chain ID-lista egyezik-e a tenyleges lepesekkel
//   5. a workflow-receiptek osszelancoltak-e
//   6. minden step-nek van-e letezo szulo workflow-receiptje
//   7. (0.2) uniform input_hash detektalas a 0.2+ lancokon
//
// Ellenoriz (0.3 - uj):
//   8.  generativ lepes jol-formaltsag (model, prompt/completion hash, decision=null)
//   9.  evidence-graph integritas (inputs[] letezo, korabbi lepesre mutat)
//   10. inclusion proof: minden horgonyzott receipt benne van-e a hivatkozott faban
//   11. STH-lanc + consistency proof: az ujabb fa az append-only bovitese a reginek
//   12. anchor cross-check (offline: explicit ANCHOR_UNVERIFIED jelzes)
//   13. redactable commitment integritas (0.4): a mezo-fa gyokere == redactable_root,
//       a jelenlevo mezok a sozott leaf_hash-ukkel; torolt mezo cleartext nelkul is ervenyes
//   14. side-effect attestation (0.4, N1): a side_effects bejegyzesek jol-formaltak,
//       a provider-attestation (ha van) alairasa verifikal; attestation nelkul recheckable
//
// Ellenoriz (0.5 - uj):
//   15. kulcs-utodlas (key succession): ha a --trust-root kibovitett (genesis-
//       tartalmu) es van succession-forras (--successions es/vagy az STH-kba
//       agyazott embedded_succession), a verifier kulcs-idovonalat epit, es
//       MINDEN alairast a megfelelo korszak kulcsaval ellenoriz: a receipteket
//       a levelpoziciojuk (leaf_index+1), az STH-kat a tree_size szerint ervenyes
//       kulccsal. Igy a rotacion ativelo log egyben verifikalhato. Minden
//       succession ELOBB a root-kulccsal verifikalodik. Trust-root vagy genesis
//       nelkul minden a regi (egykulcsos / --sth-key) uton fut.
//
// VERZIO-KEZELES:
//   A verifier a receipt sajat axr_version mezoje szerint agazik el. A regi 0.1/0.2
//   lancok TOVABBRA IS ERVENYESEK - az alairas es a hash-lanc verziotol fuggetlen.
//   0.3-nal az alairas a 'signature' ES az 'anchor_ref' nelkul szamol (az anchor_ref
//   az alairas utan irodik), es a lanc-hash is anchor_ref nelkul kepzodik.
//
// Nulla kulso fuggoseg - csak a Node beepitett crypto/fs + a kozos axr-core.js.
// Kilepesi kod: 0 ha minden rendben, 1 ha barmi hiba, 2 ha rossz hasznalat.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const fs = require('fs');
const https = require('https');
const core = require('./axr-core');
const succ = require('./axr-succession');
const control = require('./axr-control');

// Hasznalat:
//   node axr-verify.js <receipts.jsonl> <public-key.pem> [sth.jsonl] [anchors.jsonl]
//                      [--strict] [--sth-key <pem>] [--trust-root <json>] [--online]
// Az STH es anchor fajlok OPCIONALISAK: ha meg vannak adva, a 0.3 horgonyzasi
// ellenorzesek (10-12) is lefutnak. Nelkuluk a 0.1/0.2 + 0.3-sema ellenorzesek
// (1-9) futnak, a horgonyzott receiptek pedig "fuggoben" jelzest kapnak.
//
// Kapcsolok:
//   --strict            a "puha" jelzeseket (null input_hash, hianyzo redactable
//                       detail, ismeretlen reproducibility-szint, trust-root nelkuli
//                       attestation) HIBAVA emeli - CI-kapunak
//   --sth-key <pem>     az STH-kat egy KULON kulccsal verifikalja (kulcs-szerep
//                       szetvalasztas): a receipteket a fo kulcs, az STH-kat ez.
//                       Megadasa nelkul az STH-t is a fo kulccsal ellenorzi.
//   --trust-root <json> egy alairt provider-allowlist; a side-effect attestation
//                       kulcsanak benne kell lennie, kulonben az "attested" hibava
//                       fokozodik (N1 lezarasa)
//   --online            a 12. ellenorzesnel a kulso backendet (OpenTimestamps
//                       naptarak) TENYLEGESEN lekerdezi a digest ismertsegere
//                       (best-effort; a Bitcoin-fejlec szintu PoW ellenorzes az
//                       'ots' CLI-re marad - lasd README)
function parseArgs(argv) {
  const positional = [];
  const flags = { strict: false, online: false, sthKey: null, trustRoot: null,
                  successions: null, revocations: null, control: null, logId: null,
                  requireWitnesses: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--strict') flags.strict = true;
    else if (a === '--online') flags.online = true;
    else if (a === '--sth-key') flags.sthKey = argv[++i];
    else if (a === '--trust-root') flags.trustRoot = argv[++i];
    else if (a === '--successions') flags.successions = argv[++i];
    else if (a === '--revocations') flags.revocations = argv[++i];
    else if (a === '--control') flags.control = argv[++i];
    else if (a === '--require-witnesses') flags.requireWitnesses = true;
    else if (a === '--log-id') flags.logId = argv[++i];
    else if (a.startsWith('--')) { console.error('ismeretlen kapcsolo: ' + a); process.exit(2); }
    else positional.push(a);
  }
  return { positional, flags };
}
const { positional: _pos, flags: ARGS } = parseArgs(process.argv.slice(2));
const [logPath, keyPath, sthPath, anchorPath] = _pos;
if (!logPath || !keyPath) {
  console.error('Hasznalat: node axr-verify.js <receipts.jsonl> <public-key.pem> [sth.jsonl] [anchors.jsonl]\n' +
    '            [--strict] [--sth-key <pem>] [--trust-root <json>] [--online]\n' +
    '            [--successions <jsonl>] [--revocations <jsonl>] [--control <jsonl>] [--require-witnesses] [--log-id <id>]');
  process.exit(2);
}

// ── Kanonikus szerializalas - a core-bol, hogy a ket oldal ne terjen el ─────────
const canonicalize = core.canonicalize;
const sha256 = core.sha256;

// Verzio-fuggo alairas-ellenorzes: 0.3-nal a 'signature' ES az 'anchor_ref' is
// kimarad az alairt reszbol (core.signablePart kezeli).
function verifySignature(receipt, publicKey) {
  if (!receipt.signature) return false;
  try {
    return crypto.verify(null, Buffer.from(canonicalize(core.signablePart(receipt)), 'utf8'),
      publicKey, Buffer.from(receipt.signature, 'base64'));
  } catch (e) { return false; }
}

// Lanc-hash: a previous_receipt_hash / chain_root_hash szamitasanal a 0.3-ban az
// anchor_ref-et ki kell hagyni (az alairas + lancolas utan irodik). 0.1/0.2-nel
// nincs anchor_ref, igy ez no-op. A core-bol jon, hogy a generator es a verifier
// garantaltan ne terjen el.
const chainHash = core.chainHash;

// ── Beolvasas ──────────────────────────────────────────────────────────────────
let publicKey;
try {
  publicKey = crypto.createPublicKey(fs.readFileSync(keyPath, 'utf8'));
} catch (e) {
  console.error('HIBA: a publikus kulcs nem olvashato: ' + e.message);
  process.exit(2);
}

// Kulcs-szerep szetvalasztas: ha --sth-key meg van adva, az STH-kat ezzel
// (es CSAK ezzel) verifikaljuk; a receipteket tovabbra is a fo kulccsal. Igy
// egy receipt-alairo kulcs kompromittalodasa nem teszi hamisithatova a fa-fejeket
// (es forditva). Megadasa nelkul az STH-t is a fo kulcs fedi (visszafele komp.).
let sthPublicKey = publicKey;
if (ARGS.sthKey) {
  try {
    sthPublicKey = crypto.createPublicKey(fs.readFileSync(ARGS.sthKey, 'utf8'));
  } catch (e) {
    console.error('HIBA: a --sth-key nem olvashato: ' + e.message);
    process.exit(2);
  }
}

// Trust-root: ha meg van adva, eloszor ONMAGAT kell verifikalnia (a sajat
// root-kulcsaval), kulonben nem hasznaljuk (es hibat jelzunk). A side-effect
// attestation ezutan ehhez kotodik (core.verifySideEffect masodik parametere).
let trustRoot = null;
if (ARGS.trustRoot) {
  // 0.6: a --trust-root lehet egyetlen rekord (0.5), kvorum-modu root vagy
  // teljes rotacios LANC (genesis + utod-rootok, JSONL/tomb). A lanc fejet
  // a fajl birtokosa pinneli; minden utodot az elod kvoruma autorizal; az
  // effektiv root (kulcsok, genesisek, providerek) a lanc utolso eleme.
  let trRecords;
  try {
    trRecords = succ.parseTrustRootInput(fs.readFileSync(ARGS.trustRoot, 'utf8'));
  } catch (e) {
    console.error('HIBA: a --trust-root nem olvashato/ervenytelen JSON: ' + e.message);
    process.exit(2);
  }
  const trChk = succ.verifyTrustRootChain(trRecords);
  if (!trChk.ok) {
    console.error('HIBA: a --trust-root (lanc) nem verifikal: ' + trChk.problems.join('; '));
    process.exit(2);
  }
  trustRoot = trChk.effective;
}

// Kulso succession-rekordok (0.5): root-alairt key_succession-ok JSONL-ben.
// Csak trust-root mellett ertelmesek - a root-kulcs nelkul nem verifikalhatok.
let successionRecords = [];
if (ARGS.successions) {
  try {
    successionRecords = fs.readFileSync(ARGS.successions, 'utf8')
      .trim().split('\n').filter(Boolean).map(JSON.parse);
  } catch (e) {
    console.error('HIBA: a --successions nem olvashato/ervenytelen: ' + e.message);
    process.exit(2);
  }
  if (!trustRoot) {
    console.error('HIBA: a --successions csak --trust-root mellett hasznalhato (a root-kulcs verifikalja oket)');
    process.exit(2);
  }
}
// Revokaciok (0.6): out-of-band key_revocation rekordok - csak trust-root mellett.
let revocationRecords = [];
if (ARGS.revocations) {
  try {
    revocationRecords = fs.readFileSync(ARGS.revocations, 'utf8')
      .trim().split('\n').filter(Boolean).map(JSON.parse);
  } catch (e) {
    console.error('HIBA: a --revocations nem olvashato/ervenytelen: ' + e.message);
    process.exit(2);
  }
  if (!trustRoot) {
    console.error('HIBA: a --revocations csak --trust-root mellett hasznalhato');
    process.exit(2);
  }
}
// Control log (0.7): governance-rekordok + STH-commitment ellenorzes.
let controlRecords = [];
if (ARGS.control) {
  try {
    controlRecords = fs.readFileSync(ARGS.control, 'utf8')
      .trim().split('\n').filter(Boolean).map(JSON.parse);
  } catch (e) {
    console.error('HIBA: a --control nem olvashato/ervenytelen: ' + e.message);
    process.exit(2);
  }
  if (!trustRoot) {
    console.error('HIBA: a --control csak --trust-root mellett hasznalhato');
    process.exit(2);
  }
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
// soft: strict modban HIBA, kulonben csak figyelmeztetes. Azokra a minosegi
// jelzesekre, amik nem feltetlen manipulacio, de egy CI-kapunal nem szabad
// atengedni (null input_hash, hianyzo redactable detail, ismeretlen
// reproducibility-szint, trust-root nelkuli attestation).
let softWarnings = 0;
const soft = (msg) => {
  softWarnings++;
  if (ARGS.strict) { problems++; console.log('  [HIBA] (strict) ' + msg); }
  else console.log('  [megj] ' + msg);
};

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

// ── 1. Parse ───────────────────────────────────────────────────────────────────
// Az alairas-ellenorzes NEM itt fut, hanem a kulcs-idovonal felepitese UTAN
// (lasd 15. ellenorzes): rotacion ativelo lognal a "melyik kulcs ervenyes ehhez
// a receipthez" a levelpozicio fuggvenye, amihez elobb a teljes log kell.
const receipts = [];
for (let i = 0; i < lines.length; i++) {
  let r;
  try { r = JSON.parse(lines[i]); }
  catch (e) { problem(`${i+1}. sor: ervenytelen JSON`); continue; }
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
    const expectedPrev = i === 0 ? null : chainHash(wfSteps[i-1]);
    if (wfSteps[i].previous_receipt_hash !== expectedPrev) {
      problem(`workflow ${wf.receipt_id}: a(z) ${i+1}. lepes (${wfSteps[i].step?.node_name}) ` +
              `previous_receipt_hash-e nem egyezik - a lanc megszakadt vagy lepest modositottak`);
    }
  }
  // chain_root_hash
  if (wfSteps.length) {
    const expectedRoot = chainHash(wfSteps[wfSteps.length-1]);
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
        soft(`workflow ${wf.receipt_id}: a(z) "${s.step?.node_name}" lepes input_hash-e null ` +
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
  const expectedPrev = i === 0 ? null : chainHash(workflows[i-1]);
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

// ═══════════════════════════════════════════════════════════════════════════════
// 0.3 ELLENORZESEK (8-12) - generativ lepes, evidence-graph, horgonyzas
// ═══════════════════════════════════════════════════════════════════════════════

// Receipt-id -> receipt terkep (evidence-graph ellenorzeshez)
const byId = {};
for (const r of receipts) if (r.receipt_id) byId[r.receipt_id] = r;

// ── 8. Generativ lepes jol-formaltsag ──────────────────────────────────────────
for (const s of steps) {
  if (s.step?.kind !== 'generative') continue;
  const g = s.generation || {};
  const okHash = (h) => typeof h === 'string' && /^sha256:[0-9a-f]{64}$/.test(h);
  if (!okHash(g.prompt_hash))
    problem(`step ${s.receipt_id} ("${s.step?.node_name}"): generativ, de a generation.prompt_hash hianyzik/rossz`);
  if (!okHash(g.completion_hash))
    problem(`step ${s.receipt_id} ("${s.step?.node_name}"): generativ, de a generation.completion_hash hianyzik/rossz`);
  if (!s.step?.model || !s.step.model.id || !s.step.model.provider)
    problem(`step ${s.receipt_id} ("${s.step?.node_name}"): generativ, de a step.model.id/provider hianyzik`);
  if (s.io && s.io.decision !== null && s.io.decision !== undefined)
    problem(`step ${s.receipt_id} ("${s.step?.node_name}"): generativ lepesnek io.decision-je null kell legyen (a dontest a lefele kovetkezo determinisztikus lepes hordozza)`);
  const lvl = g.reproducibility?.level;
  if (!['none', 'best_effort', 'deterministic', 'pinned'].includes(lvl))
    soft(`step ${s.receipt_id} ("${s.step?.node_name}"): ismeretlen reproducibility.level "${lvl}"`);
}

// ── 9. Evidence-graph integritas ───────────────────────────────────────────────
// Minden inputs[]-ben hivatkozott receipt letezzen, ugyanabban a workflow-lancban,
// korabbi sequence-szel (a forras a fogyaszto ELOTT futott).
for (const s of steps) {
  if (!Array.isArray(s.inputs)) continue;
  for (const refId of s.inputs) {
    const src = byId[refId];
    if (!src) {
      problem(`step ${s.receipt_id} ("${s.step?.node_name}"): inputs hivatkozas (${refId}) nem letezo receiptre mutat`);
    } else if (src.workflow_receipt_id !== s.workflow_receipt_id) {
      problem(`step ${s.receipt_id}: inputs hivatkozas (${refId}) masik workflow-lancbeli lepesre mutat`);
    } else if (!(src.sequence < s.sequence)) {
      problem(`step ${s.receipt_id}: inputs hivatkozas (${refId}) nem korabbi lepesre mutat (sequence ${src.sequence} >= ${s.sequence})`);
    }
  }
}

// ── 13. Redactable commitment integritas (0.4) ─────────────────────────────────
// Ahol van redactable_root, ott a mezo-fa gyokere egyezzen a commitmenttel, es
// minden JELENLEVO mezo erteke a sajat sozott leaf_hash-evel. A torolt mezok
// cleartext nelkul is ervenyesek - a commitment all, az alairas ep marad.
let redactableCount = 0, redactedFieldCount = 0;
for (const r of receipts) {
  if (!('redactable_root' in r)) continue;
  redactableCount++;
  const res = core.verifyRedactable(r);
  if (res.detailAbsent) {
    soft(`receipt ${r.receipt_id}: redactable_root jelen, de a detail hianyzik - a commitment alairt, de lokalisan nem ellenorizheto`);
  }
  for (const p of res.problems) {
    if (!res.detailAbsent) problem(`receipt ${r.receipt_id}: redactable - ${p}`);
  }
  const fields = (r.redactable && Array.isArray(r.redactable.fields)) ? r.redactable.fields : [];
  redactedFieldCount += fields.filter(f => f.redacted || f.value === undefined).length;
}

// ── 14. Side-effect attestation (0.4) - N1 mitigacio ───────────────────────────
// Ahol van side_effects, ott minden bejegyzes legyen jol-formalt, es ha provider-
// attestationt hordoz, az alairasa verifikaljon. Az attestation nelkuli bejegyzes
// nem hiba: auditor altal fuggetlenul ujra-ellenorizheto (recheckable) - ez az
// oszinte N1-mersekles, nem onmagat bizonyito allitas.
let sideEffectCount = 0, attestedCount = 0, recheckableCount = 0;
for (const r of receipts) {
  if (!Array.isArray(r.side_effects)) continue;
  for (const entry of r.side_effects) {
    sideEffectCount++;
    const res = core.verifySideEffect(entry, trustRoot);
    for (const p of res.problems) {
      problem(`receipt ${r.receipt_id}: side-effect (${entry && entry.type}) - ${p}`);
    }
    if (res.attested) attestedCount++;
    else if (res.ok) {
      recheckableCount++;
      notice(`receipt ${r.receipt_id}: side-effect "${entry.type}" @ ${entry.provider} (ref ${entry.reference}) ` +
             `- provider-attestation nelkul: auditor altal fuggetlenul ujra-ellenorizheto (recheckable, nem onmagat bizonyito)`);
    }
  }
}

// ── STH / anchor fajlok betoltese (opcionalis) ─────────────────────────────────
function loadJsonl(path, label) {
  if (!path) return null;
  try {
    return fs.readFileSync(path, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse);
  } catch (e) {
    problem(`a(z) ${label} fajl nem olvashato/parse-olhato: ${e.message}`);
    return [];
  }
}
const sths    = loadJsonl(sthPath, 'STH') || [];
const anchors = loadJsonl(anchorPath, 'anchor') || [];

// A Merkle-fa levelei = a receiptek FAJLBELI (append) sorrendben.
const leafReceipts = receipts.filter(r =>
  ['step', 'workflow', 'identity'].includes(r.receipt_type));
const leafHashes = leafReceipts.map(core.leafHash);
const sthByRootSize = {};
for (const sth of sths) sthByRootSize[`${sth.root_hash}|${sth.tree_size}`] = sth;

// ═══════════════════════════════════════════════════════════════════════════════
// 15. KULCS-UTODLAS (0.5) - idovonalak epitese, majd alairas-ellenorzes
// ═══════════════════════════════════════════════════════════════════════════════
// Egyetlen ora a tree_size: az STH-t a tree_size-anal, a receiptet a level-
// poziciojanal (leaf_index+1) ervenyes kulcs irja ala - a hatar-szabaly igy
// byte-ra ugyanaz, mint a monitornal (utod: pozicio >= effective_from).
// SORREND-INVARIANS: minden succession ELOBB root-verifikalt, es csak utana
// szamit barmely kulcsa az alairas-ellenorzesben.

// A log_id felodasa: explicit flag > az elso STH-bol > az egyetlen trust-root
// log bejegyzes. Enelkul nincs genesis-lookup -> regi (egykulcsos) ut.
const effLogId = ARGS.logId || (sths[0] && sths[0].log_id) ||
  (trustRoot && Array.isArray(trustRoot.logs) && trustRoot.logs.length === 1
    ? trustRoot.logs[0].log_id : null);

function buildTimelineForRole(role) {
  if (!trustRoot || !Array.isArray(trustRoot.logs)) return null;
  if (!effLogId) {
    notice(`kulcs-idovonal (${role}): a log_id nem allapithato meg (--log-id?) - a regi egykulcsos ut fut`);
    return null;
  }
  const genesisPem = succ.genesisKey(trustRoot, effLogId, role);
  if (!genesisPem) return null; // nincs genesis ehhez a role-hoz -> regi ut
  const pool = [];
  const seen = new Set();
  const add = (rec, src) => {
    if (!rec || rec.record_type !== 'key_succession' || rec.role !== role) return;
    const h = sha256(rec);
    if (seen.has(h)) return;
    seen.add(h);
    const v = succ.verifyKeySuccession(rec, trustRoot);
    if (!v.ok) {
      problem(`${src}: a key_succession NEM verifikal a root-kulcsra: ${v.problems.join('; ')}`);
      return;
    }
    if (rec.log_id !== effLogId) {
      problem(`${src}: a key_succession idegen loghoz tartozik (${rec.log_id} != ${effLogId})`);
      return;
    }
    pool.push(rec);
  };
  successionRecords.forEach((rec, i) => add(rec, `successions[${i + 1}. sor]`));
  // 0.7: a control log governance-rekordjai ugyanabba a poolba (dedup)
  controlRecords.forEach((rec, i) => add(rec, `control[${i + 1}. sor]`));
  // 1.0 EMBEDDED_BYPASS: control log mellett a benne NEM szereplo beagyazott
  // succession a governance-csatorna megkerulese -> fail-closed (nem a poolba)
  const ctlHashes = new Set(controlRecords.map(r => sha256(r)));
  const usingControl = controlRecords.length > 0;
  if (role === 'sth')
    for (const sth of sths)
      if (sth.embedded_succession) {
        if (usingControl && !ctlHashes.has(sha256(sth.embedded_succession)))
          problem(`EMBEDDED_BYPASS: STH (tree_size=${sth.tree_size}): embedded_succession nincs a control logban - a governance-csatorna megkerulese`);
        else add(sth.embedded_succession, `STH (tree_size=${sth.tree_size}) embedded_succession`);
      }
  // revokaciok (0.6): root-verifikalt, log-egyezo rekordok a timeline-ra
  const revPool = [];
  const seenRev = new Set();
  const addRev = (rec, src) => {
    if (!rec || rec.record_type !== 'key_revocation' || rec.role !== role) return;
    const h = sha256(rec);
    if (seenRev.has(h)) return;
    seenRev.add(h);
    const v = succ.verifyKeyRevocation(rec, trustRoot);
    if (!v.ok) { problem(`${src}: a key_revocation NEM verifikal: ${v.problems.join('; ')}`); return; }
    if (rec.log_id !== effLogId) { problem(`${src}: idegen loghoz tartozik (${rec.log_id})`); return; }
    revPool.push(rec);
  };
  revocationRecords.forEach((rec, i) => addRev(rec, `revocations[${i + 1}. sor]`));
  controlRecords.forEach((rec, i) => addRev(rec, `control[${i + 1}. sor]`));
  const tl = succ.buildKeyTimeline(genesisPem, pool, role, trustRoot, revPool);
  for (const p of tl.problems) notice(`kulcs-idovonal (${role}): ${p}`);
  // elore letrehozott kulcs-objektumok (ne minden receiptnel parse-oljunk PEM-et)
  for (const e of tl.timeline) e.keyObj = crypto.createPublicKey(e.pem);
  return tl.timeline;
}

const receiptTimeline = buildTimelineForRole('receipt');
const sthTimeline = buildTimelineForRole('sth');

// ── 1. Alairas-ellenorzes (idovonallal, ha van; kulonben a regi egykulcsos ut) ──
{
  const leafPos = new Map(); // receipt -> 1-alapu levelpozicio
  leafReceipts.forEach((r, i) => leafPos.set(r, i + 1));
  for (const r of receipts) {
    let key = publicKey;
    if (receiptTimeline && leafPos.has(r)) {
      const pos = leafPos.get(r);
      const e = succ.keyAtTreeSize(receiptTimeline, pos);
      if (!e.authorized)
        problem(`receipt ${r.receipt_id || '(nincs id)'} (pozicio ${pos}): KEY_CHANGED_UNAUTHORIZED ` +
                `- a(z) ${e.fingerprint.slice(0, 20)}... kulcs valtasa NEM root-autorizalt`);
      // 0.6 revokacio, 3-szintu szabaly: a hatar utani pozicio KEY_REVOKED;
      // a hatar elotti CSAK anchorolt bizonyitekkal ervenyes (az anchor_ref
      // inclusion proofjat a 10. ellenorzes verifikalja) - bizonyitek nelkul
      // fail-closed, mert lopott regi kulccsal utolag gyarthato lenne
      // "pre-boundary" receipt.
      if (e.revoked_from != null) {
        if (pos >= e.revoked_from)
          problem(`receipt ${r.receipt_id || '(nincs id)'} (pozicio ${pos}): KEY_REVOKED - a(z) ` +
                  `${e.fingerprint.slice(0, 20)}... kulcs a hatar (${e.revoked_from}) utan nem irhat ala`);
        else if (!r.anchor_ref)
          problem(`receipt ${r.receipt_id || '(nincs id)'} (pozicio ${pos}): revokalt kulcs korszaka, ` +
                  `anchor-bizonyitek NELKUL - fail-closed (a hatar elotti pozicio csak anchorolt inclusion prooffal ervenyes)`);
      }
      key = e.keyObj;
    }
    if (!verifySignature(r, key)) {
      problem(`${r.receipt_type || '?'} ${r.receipt_id || '(nincs id)'}: ERVENYTELEN ALAIRAS ` +
              `- a receipt tartalma megvaltozott az alairas ota, vagy mas kulccsal keszult`);
    }
  }
}

// ── 11. STH-lanc + consistency proof ───────────────────────────────────────────
if (sths.length) {
  for (const sth of sths) {
    let sthKeyForThis = sthPublicKey, sthKeyNote = '';
    if (sthTimeline) {
      const e = succ.keyAtTreeSize(sthTimeline, sth.tree_size);
      if (!e.authorized)
        problem(`STH (tree_size=${sth.tree_size}): KEY_CHANGED_UNAUTHORIZED - a(z) ` +
                `${e.fingerprint.slice(0, 20)}... kulcs valtasa NEM root-autorizalt`);
      if (e.revoked_from != null && sth.tree_size >= e.revoked_from)
        problem(`STH (tree_size=${sth.tree_size}): KEY_REVOKED - a(z) ${e.fingerprint.slice(0, 20)}... ` +
                `kulcs a hatar (${e.revoked_from}) utan nem irhat ala`);
      sthKeyForThis = e.keyObj;
      sthKeyNote = ' (idovonal szerinti kulcs)';
    }
    if (!verifySignature(sth, sthKeyForThis))
      problem(`STH (tree_size=${sth.tree_size}): ERVENYTELEN ALAIRAS${sthKeyNote}`);
    const recomputed = core.merkleRootFromLeaves(leafHashes.slice(0, sth.tree_size));
    if (sth.tree_size <= leafHashes.length && recomputed !== sth.root_hash)
      problem(`STH (tree_size=${sth.tree_size}): root_hash nem egyezik az elso ${sth.tree_size} level Merkle-gyokerevel`);
    if (sth.tree_size > leafHashes.length)
      notice(`STH (tree_size=${sth.tree_size}) tobb levelet allit, mint amennyi a fajlban van (${leafHashes.length}) - reszleges log?`);
  }
  const sorted = sths.slice().sort((a, b) => a.tree_size - b.tree_size);
  for (let i = 0; i < sorted.length; i++) {
    const expectedPrev = i === 0 ? null : chainHash(sorted[i-1]);
    if (i > 0 && sorted[i].previous_sth_hash !== expectedPrev)
      problem(`STH (tree_size=${sorted[i].tree_size}): previous_sth_hash nem az elozo STH-ra mutat - az STH-lanc serult`);
    if (i > 0) {
      const m = sorted[i-1].tree_size, n = sorted[i].tree_size;
      if (n <= leafHashes.length) {
        const proof = core.consistencyProof(m, leafHashes.slice(0, n));
        const ok = core.verifyConsistency(m, n, sorted[i-1].root_hash, sorted[i].root_hash, proof);
        if (!ok)
          problem(`STH ${m} -> ${n}: a consistency proof MEGBUKOTT - az ujabb fa NEM az append-only bovitese a reginek (atiras/forkolas jele)`);
      }
    }
  }

  // ── 16. (0.7) Control-log commitment ─────────────────────────────────────────
  // Ha --control adott, minden commitolo STH-t a tenyleges control log ellen
  // ellenorzunk, es a commitolo STH-k kozott append-only-t. A verifier offline
  // (a fajlok kezben vannak), igy a withheld AZONNAL fail-closed - nincs
  // lag-turelem (az a monitor poll-modelljee). DOWNGRADE: a legnagyobb fa-meretu
  // STH nem commitol, de egy kisebb igen.
  // A blokk akkor fut, ha --control adott VAGY barmely STH commitol. Utobbi a
  // kulcs (NEXUS-review): ha az STH-k commitolnak, de a hivo nem adott
  // control logot, az NEM csendben atlepheto - pont az a withholding, amit a
  // commitment elkapni hivatott. Ilyenkor controlRecords ures -> CONTROL_WITHHELD.
  if (ARGS.control || sorted.some(t => typeof t.control_root_hash === 'string')) {
    const committed = sorted.filter(t => typeof t.control_root_hash === 'string');
    // DOWNGRADE (Meridian-review): az elso commitolo STH utan MINDEN nagyobb
    // fa-meretu STH commitoljon - nem eleg a legnagyobbat nezni (commit ->
    // no-control -> commit kozteso STH-ja is revokacio-rejtes lenne)
    let firstCommitTree = null;
    for (const sth of sorted) {
      const commits = typeof sth.control_root_hash === 'string';
      if (commits) { if (firstCommitTree === null) firstCommitTree = sth.tree_size; }
      else if (firstCommitTree !== null)
        problem(`CONTROL_DOWNGRADE: STH (tree_size=${sth.tree_size}) nem commitol, de egy korabbi (tree_size>=${firstCommitTree}) igen`);
    }
    let prevC = null;
    for (const sth of committed) {
      const chk = control.checkSthCommitment(sth, controlRecords);
      if (chk.withheld)
        problem(`CONTROL_WITHHELD: STH (tree_size=${sth.tree_size}): ${chk.problems.join('; ')}`);
      else if (!chk.ok)
        problem(`CONTROL_ROOT_MISMATCH: STH (tree_size=${sth.tree_size}): ${chk.problems.join('; ')}`);
      if (prevC) {
        const cc = control.checkControlConsistency(prevC, sth, controlRecords);
        for (const p of cc.problems) problem(`CONTROL_NON_APPEND_ONLY: STH ${prevC.tree_size} -> ${sth.tree_size}: ${p}`);
      }
      prevC = sth;
    }
  }

  // ── 17. (0.8) Witness-cosignature ellenorzes ─────────────────────────────────
  // A control logbeli witness_set rekordokbol witness-idovonal; minden STH-nal a
  // tree_size-nal aktiv keszlet ellen. Az anomalia (manipulalt/nem-deklaralt
  // cosignature) MINDIG hiba; a threshold-alattisag UNDER_WITNESSED - csak
  // --require-witnesses mellett hiba (kulonben megjegyzes az osszegzesben).
  if (trustRoot && controlRecords.length) {
    const wsets = [];
    controlRecords.forEach((rec, i) => {
      if (!rec || rec.record_type !== 'witness_set') return;
      const v = succ.verifyWitnessSet(rec, trustRoot);
      if (!v.ok) { problem(`control witness_set[${i + 1}]: NEM verifikal: ${v.problems.join('; ')}`); return; }
      wsets.push(rec);
    });
    if (wsets.length) {
      const wtl = succ.buildWitnessTimeline(wsets, trustRoot);
      // ambiguous witness-policy fail-closed (Meridian-review), nem csendes kihagyas
      for (const p of wtl.problems) problem(`WITNESS_SET_AMBIGUOUS: ${p}`);
      for (const sth of sorted) {
        const we = succ.witnessAt(wtl.timeline, sth.tree_size);
        if (!we) continue;
        const wr = succ.verifyWitnessCosignatures(sth, we);
        for (const a of wr.anomalies) problem(`WITNESS_COSIGNATURE_INVALID: STH (tree_size=${sth.tree_size}): ${a}`);
        if (wr.validCount < wr.threshold) {
          const m = `STH (tree_size=${sth.tree_size}): ${wr.validCount}/${wr.threshold} witness-cosignature`;
          if (ARGS.requireWitnesses) problem(`UNDER_WITNESSED: ${m} - a kuszob alatt (--require-witnesses)`);
          else soft(`UNDER_WITNESSED: ${m} - a kuszob alatt (--require-witnesses mellett hiba)`);
        }
      }
    }
  }
}

// ── 10. Inclusion proof minden horgonyzott receiptre ───────────────────────────
let anchored = 0, pending = 0;
for (const r of leafReceipts) {
  const ar = r.anchor_ref;
  if (!ar) { pending++; continue; }
  anchored++;
  let recomputed = null;
  try {
    recomputed = core.rootFromInclusionProof(core.leafHash(r), ar.leaf_index, ar.tree_size, ar.inclusion_proof || []);
  } catch (e) {
    problem(`receipt ${r.receipt_id}: inclusion proof ervenytelen (${e.message})`);
    continue;
  }
  if (recomputed !== ar.sth_root_hash)
    problem(`receipt ${r.receipt_id}: az inclusion proof-bol szamolt gyoker NEM egyezik az anchor_ref.sth_root_hash-sel - a receipt nincs benne abban a faban`);
  if (sths.length && !sthByRootSize[`${ar.sth_root_hash}|${ar.tree_size}`])
    problem(`receipt ${r.receipt_id}: az anchor_ref olyan STH-ra hivatkozik (root/${ar.tree_size}), ami nincs az STH-fajlban`);
}

// ── 12. Anchor cross-check (kulso halozat) ─────────────────────────────────────
// Offline modban (default) NEM kerdezzuk le a backendet - explicit jelzes, nem
// hallgatolagos elfogadas (spec 10.2 #12). --online eseten az OpenTimestamps
// naptarakat TENYLEGESEN lekerdezzuk: ismeri-e a naptar a lehorgonyzott digestet.
//
// FONTOS HATAR: ez azt bizonyitja, hogy a digest bekerult egy fuggetlen OTS
// naptarba (tehat letezik es kovetheto) - NEM a vegleges Bitcoin-blokk PoW
// attesztaciot. A teljes .ots proof osszeallitasat es a Bitcoin-fejlec szintu
// ellenorzest a standard 'ots verify' CLI vegzi a tarolt naptar-valaszokbol.
// Igy a verifier online modja "a horgony letezik es a naptar ismeri" szintig
// zar - a tovabbit szandekosan a referencia OTS eszkozre delegaljuk.

// Egy OTS naptar GET /timestamp/<digest-hex> lekerdezese. 200 -> a naptar ismeri
// a commitmentet; 404 -> meg nem; egyeb/halozati hiba -> nem eldontheto.
function otsCalendarKnows(calendarUrl, digestHex, timeoutMs) {
  return new Promise((resolve) => {
    let u;
    try { u = new URL(calendarUrl.replace(/\/$/, '') + '/timestamp/' + digestHex); }
    catch (e) { return resolve({ status: 'bad_url', error: e.message }); }
    const req = https.request({
      hostname: u.hostname, path: u.pathname, method: 'GET',
      headers: { 'Accept': 'application/vnd.opentimestamps.v1', 'User-Agent': 'axr-verify/0.4' },
      timeout: timeoutMs || 8000
    }, res => {
      res.on('data', () => {});
      res.on('end', () => {
        if (res.statusCode === 200) resolve({ status: 'known' });
        else if (res.statusCode === 404) resolve({ status: 'pending' });
        else resolve({ status: 'http_' + res.statusCode });
      });
    });
    req.on('error', e => resolve({ status: 'unreachable', error: e.message }));
    req.on('timeout', () => { req.destroy(); resolve({ status: 'timeout' }); });
    req.end();
  });
}

async function crossCheckAnchors() {
  for (const a of anchors) {
    const rootShort = String(a.sth_root_hash).slice(0, 20);
    if (!ARGS.online) {
      notice(`ANCHOR_UNVERIFIED: ${a.backend} anchor (root ${rootShort}..., tree_size=${a.tree_size}) ` +
             `- offline mod, a backend nincs lekerdezve. Online ellenorzeshez: --online (vagy 'ots verify').`);
      continue;
    }
    if (a.backend !== 'opentimestamps') {
      notice(`ANCHOR_UNVERIFIED: ${a.backend} anchor (root ${rootShort}...) - online ellenorzes csak opentimestamps backendre van.`);
      continue;
    }
    const digestHex = String(a.sth_root_hash).replace(/^sha256:/, '');
    const cals = (a.backend_entry && Array.isArray(a.backend_entry.calendars))
      ? a.backend_entry.calendars.map(c => c.calendar).filter(Boolean)
      : [];
    if (!cals.length) {
      notice(`ANCHOR: opentimestamps anchor (root ${rootShort}...) - nincs rogzitett naptar a backend_entry-ben, kihagyva.`);
      continue;
    }
    let known = 0, pending = 0, unknown = 0;
    for (const cal of cals) {
      const r = await otsCalendarKnows(cal, digestHex, 8000);
      if (r.status === 'known') known++;
      else if (r.status === 'pending') pending++;
      else unknown++;
    }
    if (known > 0) {
      notice(`ANCHOR_ONLINE_OK: opentimestamps (root ${rootShort}..., tree_size=${a.tree_size}) ` +
             `- ${known}/${cals.length} naptar ismeri a digestet. (Bitcoin PoW: 'ots verify'.)`);
    } else if (pending > 0) {
      notice(`ANCHOR_ONLINE_PENDING: opentimestamps (root ${rootShort}...) ` +
             `- a naptarak meg nem adtak vissza a commitmentet (${pending} pending). Probald kesobb / 'ots upgrade'.`);
    } else {
      // egyetlen naptar sem volt elerheto / nem dontheto el -> nem hiba, de jelezzuk
      notice(`ANCHOR_ONLINE_UNVERIFIED: opentimestamps (root ${rootShort}...) ` +
             `- egyetlen naptar sem volt lekerdezheto (halozat?).`);
    }
  }
}

async function finalize() {
  await crossCheckAnchors();

  // ── Osszegzes ────────────────────────────────────────────────────────────────
  console.log('-'.repeat(72));
  console.log(`Fajl:       ${logPath}`);
  console.log(`Receiptek:  ${receipts.length} osszesen  (${workflows.length} workflow, ${steps.length} lepes)`);
  const verStr = Object.keys(versionCounts).sort()
    .map(v => `${v}: ${versionCounts[v]}`).join(', ');
  console.log(`Verziok:    ${verStr}`);
  if (ARGS.sthKey) console.log(`STH-kulcs:  kulon (--sth-key) - kulcs-szerep szetvalasztva`);
  if (receiptTimeline || sthTimeline) {
    const seg = (tl) => tl ? `${tl.length} szegmens` : 'egykulcsos';
    console.log(`Kulcs-utodlas: receipt-idovonal ${seg(receiptTimeline)}, sth-idovonal ${seg(sthTimeline)} (root-horgonyzott, log: ${effLogId})`);
  }
  if (trustRoot) {
    const np = (trustRoot.providers || []).length;
    console.log(`Trust-root: ervenyes, ${np} provider - a side-effect attestation ehhez kotve`);
  }
  if (sths.length || anchored || pending) {
    console.log(`Horgonyzas: ${anchored} horgonyzott, ${pending} fuggoben  |  ${sths.length} STH, ${anchors.length} anchor-rekord`);
  }
  if (redactableCount) {
    console.log(`Redactable: ${redactableCount} receipt commitmenttel, ${redactedFieldCount} torolt mezo (a commitment es az alairas ep)`);
  }
  if (sideEffectCount) {
    console.log(`Side-effect: ${sideEffectCount} bejegyzes (${attestedCount} provider-attesztalt, ${recheckableCount} auditor altal ujra-ellenorizheto)`);
  }
  if (softWarnings) {
    console.log(`Puha jelzes: ${softWarnings} db${ARGS.strict ? ' (strict modban HIBANAK szamitva)' : ' (megj.; --strict eseten hiba lenne)'}`);
  }
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
}

finalize();
