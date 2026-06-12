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

HÁTRA:
- Halasztva 0.6+-ra (specben kimondva): revokáció, threshold-aláírás,
  recovery-ceremónia, wall-clock ablakok.
- README frissítés 0.5-re (key succession + OCSF/webhook szekciók).

## Sorvégek — figyelem

A repo vegyes: az axr-monitor.js CRLF-et tartalmaz, más fájlok LF-ek.
Szerkesztésnél a fájl meglévő sorvégét őrizd meg; új fájl LF.

## Definition of done (minden inkrementumra)

1. `npm test` teljes zöld (a crossverify-vel együtt)
2. Új viselkedéshez új teszt-eset, a red-team logikával (a támadó útja is tesztelt)
3. Backward-kompat bizonyítva: a régi (0.4) inputok a régi eredményt adják
4. CHANGELOG-bejegyzés
5. Spec-érintő változás spec-szöveggel együtt landol, nem utólag