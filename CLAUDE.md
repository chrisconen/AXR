# AXR — projekt-szintű instrukciók (Claude Code)

Ez a fájl a repo-specifikus munkakontextus. A persona és a globális elvek a
`~/.claude/CLAUDE.md`-ben élnek — itt csak az AXR-feladat és a kód-konvenciók.

## Mi ez a repo

Agent Execution Receipt: tamper-evident, Ed25519-aláírt execution receiptek
AI-ágensekhez. Append-only JSONL, RFC 6962 Merkle + inkrementális MMR,
trust-root, key-role szeparáció, redactable mezők, monitor (split-view
equivocation-detektálás). `package.json` verzió: 0.4.1; folyamatban: **0.5**.

## Parancsok

- `npm test` — a teljes suite (run-tests.js auto-discovery: minden
  `axr-*-test.js` a gyökérben). ÚJ TESZT = csak a névkonvenció kell,
  a runner magától felveszi. Kézzel karbantartott listát soha ne vezess be.
- `npm run test:py` — JS↔Python cross-verify (axr_verify.py-t indítja).
- Minden változtatás után a TELJES `npm test` fut, nem csak az érintett fájl.

## Kód-konvenciók (a meglévő kódból derivált, kötelező)

- **Zero-dep**: csak Node beépített `crypto`. `dependencies: {}` marad üres.
  Node >= 18.
- **Kommentnyelv**: magyar, ékezet nélkül (ASCII), a meglévő stílusban.
  Szekció-elválasztó: `═`-sor. Minden modul fejkommentje elmagyarázza a MIÉRT-et,
  nem csak a mit-et.
- **Kanonikalizálás**: kizárólag `core.canonicalize` (rendezett kulcsok, tiltott
  undefined/NaN/bigint/nem-plain objektum). Aláírás: Ed25519
  `crypto.sign(null, canonicalize(body))`, base64; a `signature` mező a
  body-ból mindig kimarad.
- **Kulcs-fingerprint**: PEM-fejléc nélküli, whitespace-mentes törzs sha256-ja,
  `sha256:<hex>` formátum. A monitor `keyFingerprint`-jével byte-azonos kell
  maradjon.
- **Hash-formátum**: minden hash stringként `sha256:<hex>`.
- **RFC 6962**: leaf prefix 0x00, node prefix 0x01, split a legnagyobb
  2-hatvány n alatt. A cross-impl byte-vektorokat (canonical/crossverify teszt)
  SOHA nem törheti változtatás.
- **Záróelv**: minden új record_type aláírt, kanonikus, és a verify-függvénye
  `{ ok, problems }` alakot ad vissza (lásd verifyTrustRoot mintát).

## Aktív munka: 0.5 key succession

Architektúra (rögzített, ne nyisd újra): root-aláírt `key_succession` rekord;
genesis a kibővített trust-rootból (per log_id, per role: sth|receipt);
predecessor-láncolt idővonal; az utód ELSŐ STH-ja beágyazza a successiont
(`embedded_succession`) — withholding-fix; tree_size az egyetlen óra; határ:
utód aláír tree_size >= effective_from_tree_size-tól. Hiányzó root-kulcs =
degradált fail-closed mód (minden kulcsváltás kritikus). Halasztva 0.5-ből,
specben kimondva: revokáció, threshold-aláírás, recovery-ceremónia,
wall-clock érvényességi ablakok.

KÉSZ (2026-06-12, mind a 18 suite zöld):
1. `axr-succession.js` + teszt — timeline tranzitív autorizációval és
   fail-closed fork-kezeléssel (NEXUS + Meridian review-találatok javítva)
2. `axr-anchor.js` — `embedded_succession` az utód első STH-jába (idempotens,
   guardok: role, log_id, aláíró-fingerprint, határ)
3. `axr-monitor.js` — idővonal-alapú STH-verify, `KEY_ROTATED_AUTHORIZED` /
   `KEY_CHANGED_UNAUTHORIZED` / `TRUST_ROOT_INVALID`, journal-bővítés
   (active_key_fingerprint + determinisztikus succession_chain_hash),
   `compareJournals` lánc-konfliktus; trust-root nélkül a régi TOFU marad
4. `axr-verify.js` (15. ellenőrzés) + `axr_verify.py` tükör — rotáción átívelő
   verifikáció (receipt: levélpozíció, STH: tree_size); cross-impl teszt
5. `axr-key-succession.js` CLI (build/verify/fingerprint) — `bin`-ben
6. `AXR-SPEC-0.5.md` + 0.4 §5 forward-pointer; CHANGELOG 0.5.0;
   package.json 0.5.0 + files

KÉSZ (2026-06-12, folytatás):
7. `axr-ocsf.js` — OCSF 1.1.0 Detection Finding mapping (monitor
   `--ocsf-out`); a két kulcs-kód SIEM-eseménnyé vált; determinisztikus
   finding-uid; fail-closed ismeretlen sértés-kódra
8. `axr-webhook.js` — generikus best-effort kézbesítés (monitor `--webhook`);
   token fájl/env-ből; a detekció eredményét sosem befolyásolja

## Aktív munka: 0.6 root-lifecycle hardening — KÉSZ (2026-06-12)

Scope: AXR-0.6-SCOPE.md (Chris delegálta a CTO-nak). Mind az öt inkrementum
leszállítva (kvórum-root, root-rotáció+genesis-pin, revokáció 3-szintű
szabállyal, ceremónia-CLI, spec AXR-SPEC-0.6.md), Meridian+NEXUS
keresztreview-val. Release: v0.6.0. Eredeti terv (referenciának):

1. **P1 kvórum-root:** trust root `root_keys: [pem...]` + `threshold: M`;
   M különböző deklarált kulcs aláírása ugyanazon kanonikus body felett
   (`signatures: [{key_fingerprint, signature}]`, fingerprint szerint
   rendezve, a signed body a signatures/signature mező NÉLKÜL). Fail-closed:
   duplikált/nem-deklarált aláíró, M-1, eltérő body → elutasítás. M=1/N=1 =
   a mai egykulcsos eset (backward-kompat). NEM "threshold-kripto" — a spec
   kimondja a maradék failure mode-okat (quorum collusion, kolokáció).
2. **P3 root-rotáció/recovery:** új trust rootot a RÉGI készlet kvóruma ír
   alá, `predecessor_trust_root_hash` láncolás; a fogyasztók a pinned régi
   roottól láncot követve fogadják el.
3. **P2 revokáció:** kvórum-aláírt `key_revocation` {log_id, role,
   revoked_fingerprint, revoked_at_tree_size, reason}. 3-szintű szabály:
   anchorolt pre-boundary elfogad; bizonyíték nélküli pre-boundary
   fail-closed; utána KEY_REVOKED.
4. **CLI:** `sign` / `assemble` / `revoke` az axr-key-succession-ben,
   önellenőrzéssel.
5. Spec: AXR-SPEC-0.6.md kvórum-policy threat-model szekcióval, 2-of-3
   ajánlással (nem kényszer).

## 1.0 — KÉSZ (2026-06-13): érettségi mérföldkő

Nem új réteg: a 0.2–0.8 konszolidálása egy stabil szerződéssé. Szállítva:
cross-version kompat-mátrix (fagyasztott legacy-0.2 fixture), embedded_succession
governance-cleanup (sidecar megtagadja --succession+--control; EMBEDDED_BYPASS a
fogyasztókban), AXR-SPEC-1.0.md (réteg/record/kód-regiszter + integritás-profil
+ 1.x kompat-policy), README Stable + QUICKSTART, package 1.0.0. A külső szerződés
(wire format, canonicalization, CLI exit-kódok, kódnevek) fagyott 1.x-ig; a JS
modul-export NEM fagyott (1.1-ig). Release: v1.0.0.

Halasztva post-1.0-ra: emergency witness-revokáció (lásd 1.1 — KÉSZ),
részleges control-disclosure, több namespace, fagyott JS SDK-felület,
embedded_succession teljes eltávolítása (2.0).

## 1.1 — KÉSZ (2026-06-13): emergency witness-revokáció

Additív az 1.0 fagyott szerződésen (egy új control-rekordtípus + egy új
violation-kód; nincs wire/kanonikalizálás/exit-kód változás; revokáció nélkül a
log az 1.0-val azonosan verifikál). `witness_revocation` (kvórum/root-aláírt,
control-logban) egy witness-fingerprintet ervénytelenít egy revoked_at_tree_size
határtól — a 0.6 key_revocation tükre a 0.8 witness-réteghez. **2-szintű szabály**
(egyszerűbb, mint a kulcs-revokáció 3-szintűje, mert az STH tree_size az
egyértelmű óra): T<R számít; T>=R nem, és ha a cosig ott van → `WITNESS_REVOKED`
(mindig violation). A threshold NEM csökken → UNDER_WITNESSED, amíg új
witness_set nem pótol. Szállítva: succession-primitívek + revokedWitnessesAt,
control-típus, monitor + JS/Python verifier (check 17 bővítés), OCSF-kód,
CLI (`revoke-witness` + `body witness-revocation`), AXR-SPEC-1.1.md, 34-állításos
teszt. Meridian+NEXUS keresztreview (mindkettő GO): a verifier fail-closed
útja most `CONTROL_ROOT_MISMATCH` kóddal egyezik a monitorral, és log_id-szűr a
witness-governance-re (trust boundary). Release: v1.1.0.

Halasztva 1.1-ből: witness-felfüggesztés (auto-expiry), witness self-revokáció,
recovery teljes lifecycle-e2e (unit + spec fedi).

## 1.2 — KÉSZ (2026-06-13): fagyasztott publikus JS SDK-felület

Additív, nem-protokoll (nincs wire/CLI/viselkedés-változás). Teljesíti az 1.0
ígéretét, hogy a JS modul-export az 1.x-re fagy. `index.js` az EGYETLEN
dokumentált belépési pont (`package.json main`): top-level kényelmi fgv-ek
(version, canonicalize, sha256, sign/signReceipt, verifyReceipt, keyFingerprint)
+ nevterek (core, governance, anchor, monitor, control, ocsf, report, generator,
journalReceipts, webhook). A `core` top-level is spreadelve → a pre-1.2
`main: axr-core.js` szerződés NEM törik. Stabilitás-policy: AXR-SDK.md (a
dokumentált nevek 1.x-ben fagyottak, csak additív bővülés). A CLI-only
axr-verify.js/axr-trust-root.js (require-re futnak) NEM része az SDK-nak; a
teljes-log verify a bin/axr-verify, programozottan a monitor.pollMonitor.
`axr-sdk-surface-test.js` (86 állítás) pinneli a felületet + SDK-n átmenő
smoke-test. Release: v1.2.0. (Nem-protokoll lévén review nélkül, a pinning-teszt
a garancia.)

## 1.3 — KÉSZ (2026-06-13): programozott teljes-log verify az SDK-ban

Additív, nem-protokoll; az 1.2 SDK befejezése. `axr.verify(opts)` (async) a
teljes-log verifikációt adja: `{ ok, exitCode, problems, notices, output }`.
A KANONIKUS verifikálót (axr-verify.js) futtatja, a verdikt a FAGYASZTOTT
exit-kód-szerződésből (0/1/2) → sosem divergálhat a CLI-től (nem refaktoráltam a
kritikus verifikálót — doktrína: integritás > kényelem). receipts+publicKey
kötelező (különben reject). axr-sdk-verify.js + axr-sdk-verify-test.js (9 állítás,
benne a CLI-exitkód non-divergencia keresztcheck), surface-pin + AXR-SDK.md +
README. 39 suite zöld. Release: v1.3.0.

## 1.4 — KÉSZ (2026-06-13): witness-felfüggesztés (ideiglenes, auto-lejáró)

Additív, az 1.1 witness-revokáció párja a TEMPORÁLIS esetre. `witness_suspension`
(kvórum/root-aláírt control-rekord) egy witnesst egy fél-nyílt [from, until)
tree_size-ablakra kizár; until-tól AUTOMATIKUSAN újra számít (nincs új
witness_set). Kulcskülönbség a revokációtól: a felfüggesztés JÓINDULATÚ → az
ablakban a cosig nem számít, de a jelenléte NOTICE (`WITNESS_SUSPENDED`), NEM
violation. A threshold nem csökken → küszöb alá esve UNDER_WITNESSED (until-nál
helyreáll). REVOKÁCIÓ-PRECEDENCIA: revoked+suspended fingerprint → WITNESS_REVOKED
(a kompromittálódás-jelzés sosem degradálódik). Szállítva: succession-primitívek
+ suspendedWitnessesAt, control-típus, monitor + JS/Python verifier (a Python
verdikt-only: nem írja ki a notice-t, de nem is számolja), OCSF (severity 1),
CLI (suspend-witness + body witness-suspension), AXR-SPEC-1.4.md, 29-állításos
teszt. Meridian+NEXUS keresztreview (fix: suspension-minősítés csak deklarált+érvényes
aláírásra). 40 suite zöld. Release: v1.4.0.

## 1.5 — KÉSZ (2026-06-13): partial control-disclosure

Additív, OFF-WIRE (nincs új rekordtípus/wire-mező/verzió-kapu; a log írása/verify-je
változatlan). A 0.7-ből halasztott „inclusion proof a control-fán". Egy holder
bizonyíthatja, hogy EGY governance-rekord benne van a control-fában (RFC 6962
inclusion az STH control_root_hash-ára), a TÖBBI rekord felfedése nélkül.
`control.buildControlDisclosure` / `verifyControlDisclosure` (a receiptekkel azonos
leaf/Merkle gépezet); auditor-lánc: STH-aláírás → disclosure-gyökér == STH
commitment + inclusion → (opc.) rekord root-autorizált. CLI: `control prove` +
`control verify-inclusion`. SDK-pin + Python-tükör (`verify_control_disclosure`,
cross-impl parity). 26-állításos teszt. 41 suite zöld. Meridian+NEXUS review
(GO; fixek: a verify-inclusion `--key` KÖTELEZŐ + log_id-szűrés + a teljes signed
commitment — control_root_hash ÉS control_size — kötése, aláírásilag érvényes
STH-választás). Release: v1.5.0.

## 0.8 witness cosigning — KÉSZ (2026-06-13)

Scope: AXR-0.8-SCOPE.md (Meridian+NEXUS review). Megelőző equivocation-védelem:
stateful witnessek cosignolják az STH-t; egy STH addig nem teljes-bizalmú, amíg
threshold-nyi független witness alá nem írta. A witness_set a control logban
(nem trust-root). Szállítva: witness primitívek (axr-succession), core volatilis
witness_cosignatures mező, axr-witness CLI (stateful sign), monitor + JS/Python
verifier check 17 (UNDER_WITNESSED notice/strict, WITNESS_COSIGNATURE_INVALID +
WITNESS_SET_AMBIGUOUS mindig violation), embedded_succession deprecation,
AXR-SPEC-0.8.md. Release: v0.8.0. Meridian-review két találata javítva: ambiguous
witness_set fail-closed minden fogyasztóban; witness-state-integritás + Python
verdikt-only specben kimondva.

Halasztva 0.9/1.0-ra: emergency witness-revokáció; embedded_succession
eltávolítása (1.0). Korábbról: részleges control-disclosure, több namespace.

## 0.7 control log — KÉSZ (2026-06-13)

Scope: AXR-0.7-SCOPE.md (Meridian+NEXUS review). A governance-rekordok
(receipt-role succession, revokáció) in-log, anchorolt terjesztése:
control.jsonl + STH-commitment (control_root_hash + control_size), a wire
format érintése nélkül. Szállítva: axr-control.js core, sidecar
--control/--control-trust-root (commit előtti teljes kripto-verify),
monitor --control (CONTROL_LAG→WITHHELD eszkaláció, DOWNGRADE, journal-pin),
JS+Python verifier check 16, CLI control add/verify/status, AXR-SPEC-0.7.md.
Release: v0.7.0.

KÉSZ külön sávként (nem protokoll, 2026-06-13): **Compliance Report Generator**
(`axr-report.js`) — ember-olvasható HTML/JSON riport; a PASS/FAIL a verifier
verdiktje (nézet, nem helyettesítés); EU AI Act Art.12 / GDPR control-mapping;
18 teszt + cross-check a verifierrel. `bin`-ben mint `axr-report`.

Halasztva 0.8+-ra: részleges control-disclosure (inclusion proof a
control-fán), több control-namespace, verzió-kapu új control-rekordtípushoz,
embedded_succession kivezetése. Külön sáv (nem protokoll): 0.5+ production
rollout tooling. Elvetve: wall-clock ablakok.

## Sorvégek — figyelem

A repo vegyes: az axr-monitor.js CRLF-et tartalmaz, más fájlok LF-ek.
Szerkesztésnél a fájl meglévő sorvégét őrizd meg; új fájl LF.

## Definition of done (minden inkrementumra)

1. `npm test` teljes zöld (a crossverify-vel együtt)
2. Új viselkedéshez új teszt-eset, a red-team logikával (a támadó útja is tesztelt)
3. Backward-kompat bizonyítva: a régi (0.4) inputok a régi eredményt adják
4. CHANGELOG-bejegyzés
5. Spec-érintő változás spec-szöveggel együtt landol, nem utólag