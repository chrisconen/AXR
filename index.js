// ═══════════════════════════════════════════════════════════════════════════════
// AXR - publikus JS SDK belepesi pont (stabil felulet, 1.x-ben fagyasztva)
// ═══════════════════════════════════════════════════════════════════════════════
// Ez a modul az AXR programozott (konyvtarkent valo) hasznalatanak EGYETLEN
// dokumentalt, stabil felulete. Amit innen exportalunk, az az 1.x sorozatban
// additiv modon valtozhat (uj nevek jonnek), de a meglevo dokumentalt nevek es
// alakjuk NEM tornek (lasd AXR-SDK.md). A feluletet az axr-sdk-surface-test.js
// pinneli - egy nev/alak-drift azonnal piros.
//
// Miert ez kell: eddig az AXR-t parancssorbol (bin/) lehetett hasznalni; a
// modul-export nem volt fagyasztva. Az 1.x adopciohoz egy fogyaszto biztosan
// epithet erre: `const axr = require('axr')`.
//
// Tervezesi elv (zero-dep, fail-closed): csak a BIZTONSAGGAL require-olhato,
// mar moduláris primitivek kerulnek be. A teljes-log verifikacio (a sok-input
// CLI-orchesztracio) tovabbra is a `bin/axr-verify` parancs ill. programozottan
// a `monitor.pollMonitor` - ezert az axr-verify.js / axr-trust-root.js (CLI-only
// scriptek) NEM resze az SDK-nak.
// ═══════════════════════════════════════════════════════════════════════════════

const pkg = require('./package.json');
const core = require('./axr-core');
const governance = require('./axr-succession');
const anchor = require('./axr-anchor');
const monitor = require('./axr-monitor');
const control = require('./axr-control');
const ocsf = require('./axr-ocsf');
const report = require('./axr-report');
const generator = require('./axr-generator');
const journalReceipts = require('./axr-journal-receipts');
const webhook = require('./axr-webhook');
const { verifyLog } = require('./axr-sdk-verify');

module.exports = {
  // Verzio (a package.json-bol; a wire-format/CLI-szerzodes verzioja kulon, a
  // rekordok axr_version mezojeben el).
  version: pkg.version,

  // ── Top-level kenyelmi fuggvenyek (a leggyakoribb belepes) ────────────────
  // Visszafele-kompat: a core nevei top-level is elerhetok maradnak (a korabbi
  // `main: axr-core.js` szerzodes nem torik), plusz nehany rovid alias.
  ...core,
  sign: core.signReceipt,                 // alias: receipt alairasa
  keyFingerprint: governance.keyFingerprint,

  // Teljes-log verifikacio (async): a kanonikus verifikalot futtatja, a verdikt
  // a fagyasztott kilepesi kodbol -> sosem terhet el a CLI-tol. Lasd AXR-SDK.md.
  // verify(opts) -> Promise<{ ok, exitCode, problems, notices, output }>
  verify: verifyLog,

  // ── Nevterek (a teljes, kurált felulet) ──────────────────────────────────
  core,              // kanonikalizalas, hash, alairas/ellenorzes, Merkle/MMR,
                     // inclusion/consistency proof, redactable, side-effect, trust-root
  governance,        // kulcs- es witness-eletcilkus: succession, revokacio,
                     // witness_set + cosign + witness_revocation, idovonalak (axr-succession)
  anchor,            // RFC 6962 STH-horgonyzas: runAnchor, runUpgrade
  monitor,           // split-view / equivocation detekcio: pollMonitor, compareJournals
  control,           // 0.7 control-log: verifyControlRecord/Log, commitment-ellenorzes
  ocsf,              // OCSF Detection Finding mapping (SIEM-export)
  report,            // ember-olvashato HTML/JSON compliance-riport
  generator,         // n8n-futasokbol receipt-generalas (referencia)
  journalReceipts,   // naplo-bejegyzes -> alairt receipt (dogfooding primitiv)
  webhook            // best-effort detekcio-kezbesites
};
