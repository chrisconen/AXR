# AXR 0.6 — scope (DÖNTÖTT, 2026-06-12)

**Döntések (Chris delegálta, CTO: Fable):**
1. Scope = a teljes csomag: P1 (kvórum-root) + P2 (revokáció) + P3
   (root-rotáció/recovery) + operátori CLI. Sorrend: P1 → P3 → P2, a CLI
   minden inkrementummal együtt landol.
2. Kvórum-ajánlás a specben: **2-of-3** (ajánlás, nem kényszer; M=1/N=1
   marad érvényes backward-kompat esetként).
3. Párhuzamos sávok (rollout-tooling, Compliance Report Generator): a P1
   landolása UTÁN indulnak — előbb fókusz a protokollon.
4. Revokáció-szemantika: a 3-szintű szabály elfogadva (anchorolt múlt
   érvényes; bizonyíték nélküli múlt fail-closed; határ után KEY_REVOKED).

**Eredet:** a v1 vázlatot Meridian (architektúra/threat-model) és NEXUS
(auditor/operátor-érték) függetlenül kritizálta; ez a szintézis. A két review
fő konvergenciái: P4 kikerül (0.7: control-log irány), a kulcs-életciklus-zárás
a mag, és az operátori CLI nem extra, hanem feltétel.

---

## A 0.6 magja: root-lifecycle hardening

### 1. Kvórum-root (M-of-N multi-aláírás) — P1

A trust root `root_keys: [pem...]` + `threshold: M` mezőt deklarál; egy
succession / trust-root-utód akkor érvényes, ha ugyanazon kanonikus body
felett M KÜLÖNBÖZŐ deklarált kulcs Ed25519-aláírása áll. Zero-dep, nem hoz
be threshold-kriptográfiát (BLS/FROST elvetve).

**Őszinte névhasználat (Meridian):** ez NEM "threshold root" — a root-
kompromittálás lehetősége nem szűnik meg, a failure mode változik: single-key
compromise → quorum compromise / collusion / policy-hiba / kulcs-kolokáció.
A spec ezt kimondja, és kap egy kvórum-policy threat-model szekciót
(földrajzi/szervezeti szétválasztás, kvórum-tag cseréje, elveszett aláíró,
kompromittált kvórum detektálhatósága).

**Kötelező invariánsok (fail-closed):** azonos kanonikus body; egyedi,
deklarált aláíró-fingerprintek; determinisztikus signature-set
kanonikalizálás. Duplikált aláíró / nem-deklarált kulcs / M-1 aláírás /
eltérő body → elutasítás.

**Backward-kompat:** a mai egykulcsos trust root = M=1, N=1 speciális eset.

### 2. Revokáció — P2 (az auditor-érték csúcsa)

Root-aláírt (0.6-tól: kvórum-aláírt) `key_revocation` rekord:
`{log_id, role, revoked_fingerprint, revoked_at_tree_size, reason}`.

**Szigorított szemantika (Meridian, 3-szintű szabály):**
- `revoked_at` ELŐTTI pozíció + inclusion proof egy pre-revocation STH-hoz
  → ELFOGAD (anchorolt múlt érvényes marad);
- `revoked_at` előtti pozíció, de anchor-bizonyíték NÉLKÜL → FAIL-CLOSED
  (lopott régi kulccsal nem gyártható utólagos pre-boundary narratíva);
- `revoked_at` utáni → `KEY_REVOKED` violation.

A wall-clock "mikor tudtuk meg" továbbra sem kerül a bizalmi útba; a határ a
tree_size. NEXUS megerősítette: SOC2/AI Act auditnál ez az első kérdés
("post-compromise kizárás + múltbeli bizonyítékok sérthetetlensége").

### 3. Root-rotáció / recovery — P3 (a P1-re épül)

Új trust-root rekordot a RÉGI kulcskészlet M-of-N kvóruma ír alá,
`predecessor_trust_root_hash` láncolással; a fogyasztók a pinned régi
roottól láncot követve fogadják el az újat. Amíg M aláíró megvan az N-ből,
a recovery in-protocol; alatta out-of-band új trust root (kimondva).

### 4. Operátori CLI — a 0.6 része, nem utógondolat (NEXUS feltétele)

Kézi kanonikus-JSON gyártás + offline aláírás-gyűjtögetés = garantált
self-lockout. A 0.6 szállítja: `axr-key-succession` bővítés (vagy külön
`axr-quorum`): `sign` (egy aláíró hozzáteszi a magáét), `assemble`
(részaláírások összefésülése + kvórum-ellenőrzés), `revoke build/verify`.
Minden parancs önellenőriz kiírás előtt (a meglévő CLI-minta szerint).

## Kikerül a 0.6-ból

- **P4 (receipt-succession mint új levél-típus):** mindkét review elveti —
  ez lenne az első levél-típus-bővítés a 0.2 freeze óta, és összekeverné a
  kulcs-governance eseményeket az execution-log szemantikával. **0.7 irány
  (Meridian alternatívája, design note-ként rögzítve):** control-log /
  sidecar manifest, amit az STH aláírt body-ja commitol
  (`receipt_succession_set_hash`) — a terjesztés anchorolt, a wire format
  érintetlen.
- **Wall-clock ablakok:** a 0.5 döntés áll.
- **Valódi threshold-kripto, HSM:** változatlanul kívül.

## Párhuzamos sávok (nem protokoll-scope, de ütemezendő — NEXUS)

- **0.5 production rollout tooling:** trust-root bootstrap a futó pilothoz,
  migrációs guide. Nem "majd utána" — a 0.6-tal párhuzamos sáv, különben az
  adopció az operatív kockázat-félelmen reked meg.
- **Compliance Report Generator (auditor-nézet):** ember-olvasható,
  hitelesített HTML/PDF összefoglaló a lánc-sértetlenségről és a kulcsok
  korabeli érvényességéről. NEXUS szerint ez az, amit egy auditor ELSŐKÉNT
  kérne. Termék-döntés: külön sáv most, vagy 0.7.

## Sorrend és DoD

P1 → P3 → P2, a CLI mindegyikkel együtt landol (nem a végén). Minden
inkrementumra a meglévő DoD + Python-tükör ahol verifikáció-érintett +
multi-agent keresztreview.

## Döntési kérdések — LEZÁRVA

A négy nyitott kérdést Chris a CTO-ra (Fable) delegálta 2026-06-12-én; a
döntések a dokumentum elején. A scope innentől a CLAUDE.md "Aktív munka"
szekciójában követett, a DoD változatlan (teljes zöld suite, red-team
tesztek, backward-kompat bizonyítva, spec a kóddal együtt, Python-tükör,
multi-agent keresztreview).
