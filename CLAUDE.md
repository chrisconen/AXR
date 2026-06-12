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

## Aktív munka: 0.6 root-lifecycle hardening

Scope DÖNTÖTT (AXR-0.6-SCOPE.md, 2026-06-12, Chris delegálta a CTO-nak).
Sorrend: P1 → P3 → P2, a CLI minden inkrementummal együtt landol.

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

Halasztva 0.7-re: P4 control-log irány (receipt-succession terjesztés az STH
body-jában commitolt manifesttel), Compliance Report Generator, 0.5 rollout
tooling (a P1 után indulhat párhuzamosan), wall-clock ablakok (elvetve).

## Sorvégek — figyelem

A repo vegyes: az axr-monitor.js CRLF-et tartalmaz, más fájlok LF-ek.
Szerkesztésnél a fájl meglévő sorvégét őrizd meg; új fájl LF.

## Definition of done (minden inkrementumra)

1. `npm test` teljes zöld (a crossverify-vel együtt)
2. Új viselkedéshez új teszt-eset, a red-team logikával (a támadó útja is tesztelt)
3. Backward-kompat bizonyítva: a régi (0.4) inputok a régi eredményt adják
4. CHANGELOG-bejegyzés
5. Spec-érintő változás spec-szöveggel együtt landol, nem utólag