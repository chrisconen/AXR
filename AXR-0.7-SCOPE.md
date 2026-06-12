# AXR 0.7 — scope (DÖNTÖTT, 2026-06-12)

**Döntések a Meridian + NEXUS review után (CTO: Fable):**
1. **Sidecar-validálás (Meridian kikötése, elfogadva):** a `controlPath`
   mellé `controlTrustRoot` is kötelező — a sidecar commit előtt MINDEN
   control-rekordot teljes kriptográfiai szigorral verifikál (root/kvórum-
   aláírás, log_id, típus-allowlist), és bármely érvénytelen rekordra dob.
   Érvénytelen governance-anyag nem anchorolható — a "majd a fogyasztó
   elbukik rajta" DoS/self-lockout felület lenne.
2. **Control-log identitás (Meridian kikötése, elfogadva):** a control log a
   log_id-hoz kötött (minden rekord hordozza; a commitment az adott log
   STH-iban él). A root-rotáció NEM nullázza: az új kvórum alatt újra
   kiadott rekordok hozzáfűződnek, a régiek történelemként maradnak. A
   monitor journalja a legnagyobb látott control_size-t + gyökeret pinneli.
3. **WITHHELD-race (NEXUS felvetése, eszkalációs megoldás):** a monitor
   determinisztikusan eszkalál — első rövid/hiányzó control-poll =
   `CONTROL_LAG` megjegyzés + journal-marker; ismétlődés a következő
   pollban = `CONTROL_WITHHELD` sértés. Nincs wall-clock grace a bizalmi
   útban; a replikációs race egy poll-ciklusnyi türelmet kap, többet nem.
   A verifierek (offline, fájlok kézben) azonnal fail-closed.
4. **CLI (NEXUS kikötése, elfogadva):** `control add` mellett `control
   status` (aktív kulcskészlet role-onként egy fa-méretnél) és `control
   verify` (offline lint) is a 0.7 része.
5. **embedded_succession (NEXUS javaslata, részben elfogadva):** NEM
   távolítjuk el (a control log opt-in — e nélküli logoknál ez marad a
   withholding-fix, és a 0.5/0.6 kompat törne). A spec kimondja: control-
   logos lognál a control log az ELSŐDLEGES governance-csatorna, az
   embedded_succession átmeneti/opcionális, és egy későbbi major-ben
   kivezethető. A dedup a determinisztikus kanonikalizálás miatt ingyen van.

**Eredet:** a vázlatot Meridian (architektúra) és NEXUS (auditor/operátor)
függetlenül kritizálta; az irányt mindkettő helyesnek ítélte. A 0.6 scope-ban
Meridian által javasolt design kibontása: a kulcs-governance rekordok
(receipt-role succession, revokáció) in-log, anchorolt terjesztése a wire
format érintése NÉLKÜL.

## A probléma

A 0.6-ban a receipt-role successionök és MINDEN revokáció out-of-band fájlban
utazik (`--successions`, `--revocations`). Ez két lyukat hagy:

1. **Withholding:** az operátor (vagy támadó) különböző fogyasztóknak
   különböző rekord-készletet mutathat — semmi nem horgonyozza, MELYIK
   készlet volt érvényben egy adott fa-méretnél.
2. **Visszavonás-elnyelés:** egy kínos revokáció egyszerűen "elveszhet" a
   terjesztés során — a fogyasztó nem tudja, hogy hiányzik valami.

## A javaslat: control log + STH-commitment

- **`control.jsonl`** — append-only JSONL a kulcs-governance rekordoknak
  (`key_succession` bármely role-lal, `key_revocation`). A rekordok
  autoritása változatlanul a root/kvórum-aláírás; a control log csak a
  TERJESZTÉS csatornája.
- **Az STH aláírt body-ja commitol:** `control_root_hash` (RFC 6962 Merkle-
  gyökér a control-rekordok felett, a meglévő core-gépezettel) +
  `control_size`. Mivel a signablePart/chainHash nem vágja le, az aláírás,
  a lánc és az anchor is fedi — a control-készlet minden fa-méretnél
  bizonyíthatóan rögzített.
- **Append-only konzisztencia:** a meglévő consistency-proof gépezet a
  control-fára is fut — két STH control-commitmentje között bizonyítható,
  hogy a készlet csak bővült (rekord eltávolítása = NON_APPEND_ONLY-osztályú
  sértés).
- **Wire format:** érintetlen. A receipts.jsonl, a LEAF_TYPES és a receipt-fa
  nem változik — a control log külön sidecar-fájl, a commitment két új
  opcionális STH-mező (additív, mint az embedded_succession volt).

## Fail-closed szabályok (a kényes döntések)

1. **CONTROL_WITHHELD:** ha bármely STH commitol control-készletet, de a
   fogyasztó nem kapja meg a control logot (vagy rövidebbet kap, mint a
   commitolt méret) → sértés. A commitment attól ér valamit, hogy a
   hiánya hangos.
2. **CONTROL_DOWNGRADE:** ha egy korábbi STH commitolt, egy későbbi pedig
   nem → sértés. Különben a commitment elhagyásával lehetne revokációt
   rejteni.
3. **CONTROL_ROOT_MISMATCH / CONTROL_NON_APPEND_ONLY:** a publikált control
   log nem egyezik a commitolt gyökérrel / a készlet zsugorodott vagy
   átíródott. A monitor journalja a legnagyobb látott control_size-t és
   gyökeret pinneli (poll-ok közötti zsugorodás ellen).
4. Érvénytelen rekord a control logban → a meglévő kódok
   (KEY_CHANGED_UNAUTHORIZED / REVOCATION_UNAUTHORIZED); ismeretlen
   record_type a control logban → sértés (fail-closed; verzió-kapuzás majd
   akkor, ha lesz új típus).

## Csatorna-viszonyok

- Az `embedded_succession` (0.5) marad: az utód első STH-jában utazó sth-role
  succession a rotáció-bejelentés csatornája. A control log az ÁLTALÁNOS
  governance-csatorna; ugyanaz a rekord mindkettőben megjelenhet (a
  determinisztikus aláírás-kanonikalizálás miatt byte-azonos → dedup).
- A `--successions` / `--revocations` out-of-band flagek maradnak (pl. a
  monitor-oldali, operátortól független terjesztéshez), és ugyanabba a
  poolba dedupolódnak.

## Szállítandók

1. `axr-control.js` modul: controlRoot, verifyControlLog, STH-commitment +
   append-only ellenőrzés
2. Sidecar: `runAnchor` `controlPath` opció (+ guardok)
3. Monitor: `--control`, az új kódok, journal-pin (control_size/root)
4. Verifierek: `--control` JS + Python tükörben, cross-impl teszttel
5. CLI: `control add` (validál append előtt — self-lockout védelem)
6. OCSF-bővítés az új kódokkal; AXR-SPEC-0.7.md; release 0.7.0

## Nem 0.7

- Compliance Report Generator, rollout-tooling (külön sáv marad)
- Receipt-fa / LEAF_TYPES változás (továbbra is kizárva)
- Control-rekordok inclusion-proof szintű részleges feltárása (a control
  log kicsi; a teljes készlet átadása a normál út — ha valaha nagyra nő,
  a Merkle-gyökér miatt a proof-os út utólag is nyitva áll)

## Nyitott kérdések a review-nak

1. A CONTROL_DOWNGRADE szabály túl szigorú-e (legitim eset lehet-e a
   commitment elhagyása)? Javaslat: nem — fail-closed.
2. A sidecar mennyit validáljon a control logon commit előtt (teljes
   root-verify trust-roottal, vagy csak strukturális guard)? Javaslat:
   strukturális + log_id guard; a kriptográfiai autoritás a fogyasztóké.
3. Kell-e a control_size=0 commitment (üres készlet explicit rögzítése),
   hogy a "még nincs governance-esemény" is bizonyított legyen? Javaslat:
   igen, ha a controlPath meg van adva — az üres fa gyökere is gyökér.
