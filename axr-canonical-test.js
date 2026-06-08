// ═══════════════════════════════════════════════════════════════════════════════
// AXR - Kanonizalas teszt-vektorok (RFC 8785 / JCS szellemeben)
// ═══════════════════════════════════════════════════════════════════════════════
// Futtatas:  node axr-canonical-test.js
//
// A "barki, barmely nyelven ellenorizheti" allitas a kanonizalas BAJTRA azonos
// determinizmusan all. Ez a suite ezt rogziti: ismert bemenet -> ismert kimenet,
// kulcs-rendezes, unicode, szam-formazas, es a guardok (NaN/Infinity/undefined/
// nem-plain objektum eldobasa a csendes korrupcio helyett).
//
// Aki AXR-t mas nyelven (Python/Go/Rust) implemental, ezeket a vektorokat kell
// reprodukalnia bajtra. Ezert a vektorok a DOKUMENTACIO is egyben.
//
// Kilepesi kod: 0 ha minden zold, 1 ha barmi megbukik.
// ═══════════════════════════════════════════════════════════════════════════════

const assert = require('assert');
const crypto = require('crypto');
const core = require('./axr-core');

let passed = 0;
function check(name, fn) {
  try { fn(); passed++; console.log(`  ok  - ${name}`); }
  catch (e) { console.log(`  HIBA - ${name}\n        ${e.message}`); process.exitCode = 1; }
}

console.log('A) Ismert bemenet -> ismert kimenet (cross-impl vektorok)');

// [bemenet, elvart kanonikus string]
const VECTORS = [
  [null, 'null'],
  [true, 'true'],
  [false, 'false'],
  [0, '0'],
  [-0, '0'],                              // negativ nulla -> "0"
  [1, '1'],
  [1.0, '1'],                             // egesz-erteku float -> "1"
  [0.97, '0.97'],
  [-12.5, '-12.5'],
  [1e21, '1e+21'],                        // ES Number->String (RFC 8785)
  ['', '""'],
  ['arvizturo', '"arvizturo"'],
  [[], '[]'],
  [{}, '{}'],
  [[3, 1, 2], '[3,1,2]'],                 // tomb-sorrend valtozatlan
  [{ b: 1, a: 2 }, '{"a":2,"b":1}'],      // kulcs-rendezes
  [{ a: { d: 1, c: 2 }, b: [2, 1] }, '{"a":{"c":2,"d":1},"b":[2,1]}'],
  [{ z: 1, a: 1, m: 1 }, '{"a":1,"m":1,"z":1}'],
  [{ k: null, j: false }, '{"j":false,"k":null}']
];

check('alap vektorok bajtra egyeznek', () => {
  for (const [input, expected] of VECTORS) {
    const got = core.canonicalize(input);
    assert.strictEqual(got, expected, `canonicalize(${JSON.stringify(input)}) = ${got}, vart: ${expected}`);
  }
});

check('unicode kulcs-rendezes UTF-16 code unit szerint', () => {
  // 'z' (0x7A) < 'e-acute' (0xE9) code unit szerint
  const got = core.canonicalize({ '\u00e9': 1, z: 2 });
  assert.strictEqual(got, '{"z":2,"\u00e9":1}', `kapott: ${got}`);
});

check('beagyazott melyseg + vegyes tipusok', () => {
  const input = { id: 'x', n: 2, items: [{ q: 1 }, { p: 0 }], meta: { b: true, a: null } };
  const expected = '{"id":"x","items":[{"q":1},{"p":0}],"meta":{"a":null,"b":true},"n":2}';
  assert.strictEqual(core.canonicalize(input), expected);
});

console.log('B) Determinizmus (a kulcs-beszurasi sorrend nem szamit)');

check('eltero beszurasi sorrend -> azonos kanonikus bajtok + azonos hash', () => {
  const a = {}; a.b = 1; a.a = 2; a.c = 3;
  const b = {}; b.c = 3; b.a = 2; b.b = 1;
  assert.strictEqual(core.canonicalize(a), core.canonicalize(b), 'a kanonikus forma elter');
  assert.strictEqual(core.sha256(a), core.sha256(b), 'a hash elter');
});

check('alairas stabil a kulcs-sorrendre: ujraszerializalt receipt is verifikal', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const priv = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const pub = publicKey.export({ type: 'spki', format: 'pem' });
  const r = { axr_version: '0.3', receipt_type: 'step', receipt_id: core.uuid(),
              io: { output_hash: core.sha256('y'), input_hash: core.sha256('x') } };
  r.signature = core.signReceipt(r, priv);
  // ugyanaz a receipt, ELTERO kulcs-sorrendben (JSON kor-ut)
  const reordered = JSON.parse(JSON.stringify({
    signature: r.signature,
    io: { input_hash: r.io.input_hash, output_hash: r.io.output_hash },
    receipt_type: 'step', receipt_id: r.receipt_id, axr_version: '0.3'
  }));
  assert.ok(core.verifyReceipt(reordered, pub), 'az ujraszerializalt receipt alairasa nem verifikal');
});

console.log('C) Guardok - csendes korrupcio helyett hangos hiba');

const MUST_THROW = [
  ['undefined', undefined],
  ['NaN', NaN],
  ['Infinity', Infinity],
  ['-Infinity', -Infinity],
  ['NaN beagyazva', { a: 1, b: NaN }],
  ['undefined mezoertek', { a: undefined }],
  ['undefined tomb-elem', [1, undefined, 3]],
  ['Date objektum', new Date(0)],
  ['Map objektum', new Map()],
  ['RegExp objektum', /x/],
  ['bigint', { n: 10n }]
];

check('a tiltott ertekek dobnak (nem csendben korrumpalodnak)', () => {
  for (const [label, val] of MUST_THROW) {
    assert.throws(() => core.canonicalize(val), /canonicalize:/, `nem dobott: ${label}`);
  }
});

check('kontroll: a JSON.stringify ezeket NEMAN elrontana (ezert kell a guard)', () => {
  // bizonyitek, hogy a guard valos kockazatot zar ki
  assert.strictEqual(JSON.stringify(NaN), 'null', 'a JSON.stringify NaN-t null-na alakit - ezt zarjuk ki');
  assert.strictEqual(JSON.stringify({ a: undefined }), '{}', 'a JSON.stringify undefined mezot elnyel');
});

console.log('-'.repeat(72));
if (process.exitCode === 1) {
  console.log(`EREDMENY: NEM minden teszt zold (${passed} sikeres). Lasd a [HIBA] sorokat.`);
} else {
  console.log(`EREDMENY: mind a ${passed} teszt zold. A kanonizalas determinisztikus es vedett.`);
}
