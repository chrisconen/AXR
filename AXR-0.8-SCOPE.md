# AXR 0.8 — scope (DÖNTÖTT terv, 2026-06-13; implementáció jóváhagyásra vár)

**Döntések a Meridian (threat-model) + NEXUS (auditor/adopció) review után
(CTO: Fable). Chris a TERVEZÉST kérte — az implementáció a jóváhagyására vár.**

A 0.8 = **stateful, witness-gated STH-acceptance** (Meridian reframe-je). NEM
csak "extra aláírások az STH-n": a witnessing csak akkor preventív, ha a
witness konzisztencia-állapotot tart, és MEGTAGADJA olyan STH aláírását, ami
nem append-only folytatása az általa utoljára látott STH-nak. A spec ezt
viselkedési invariánsként rögzíti.

1. **Witness-kör helye — a CONTROL LOG, nem a trust-root (NEXUS érve, elfogadva).**
   A witness-kör életciklusa operatív és gyakori (egy auditor-csere, egy
   konzorciumi tag kilépése); a trust-root rotációja ceremoniális és ritka.
   Minden witness-cseréhez root-successiont kérni indokolatlan ceremónia +
   self-lockout kockázat. Ezért: új, root/kvórum-aláírt **`witness_set`
   governance-rekord a control logban** (a key_succession/revocation mellé) —
   újrahasználja a 0.7 anchorolt, append-only, withholding-fix csatornát. A
   trust-root marad a ceremoniális horgony.
2. **P2 a version gate ELŐBB, megerősítve** — a `witness_set` egy ÚJ control
   record_type, és az STH új mezőt kap; kell a forward-kompat szabály
   (trust-kritikus ismeretlen = fail-closed, tisztán informatív átléphető),
   mielőtt a réteg mezőket ad. NEXUS külön kiemelte: egy 0.7 verifier ne
   törjön merev sémán.
3. **UNDER_WITNESSED: default notice, `--require-witnesses` (strict) =
   violation, fail-closed** (mindkét reviewer). Egy élő, witness nélküli pilot
   így nem bukik el azonnal; a szigorú transzparencia-mód opt-in.
4. **A cosignature a TELJES kanonikus STH-body-t fedi** a `witness_cosignatures`
   mező nélkül — így a beágyazott succession és a control-commitment is
   witness-fedett (Meridian).
5. **Witness CLI + minimál submission-spec (NEXUS feltétele):** `axr-witness`
   (`sign` egy STH-ra a stateful append-only ellenőrzéssel; `verify`), plusz a
   spec dokumentál egy MINIMÁLIS HTTP submission-mintát (POST STH → cosignature
   válasz), hogy a witness könnyen üzemeltethető legyen. Enélkül halott kód.
6. **Witness-revokáció: lassú-revoke egy új `witness_set` rekorddal** (control
   log) — emergency root-rotáció nélküli witness-kizárás 0.9/1.0 feature
   (Meridian: nevezzük néven, ne ígérjük 0.8-ra).
7. **Sorrend: P2 → P1 → P3**, mindkét reviewer megerősítette.

Az alábbi vázlat-törzs a fenti döntésekkel olvasandó (a witness-allowlist
helye a control logra módosult a trust-roothoz képest).

---

**Eredeti vázlat-státusz:** A 0.5–0.7 lezárta a kulcs-életciklust (kiadás →
rotáció → revokáció → recovery → terjesztés). A 0.8 a következő érdemi lépés:
az **equivocation-védelem megelőzővé tétele**.

## A probléma (a megmaradt rés)

A 0.3 Monitor IDŐBEN és NÉZETEK KÖZÖTT fogja az equivocationt: ha az operátor
két különböző fát mutat két monitornak, a `compare` bizonyítja. De ez
**utólagos detektálás** — van egy ablak a publikálás és az első független poll
között, amikor egy operátor split-view-t mutathat, és egy adott fogyasztó nem
tudja, hogy ő a "rossz" ágat látja. A bizalom egyetlen operátor-aláírású
STH-n nyugszik.

A modern transzparencia-logok (Sigsum, Go checksum DB, CT 2.0) ezt
**witness-ekkel** oldják: egy STH-t addig nem fogad el a fogyasztó, amíg N
független witness alá nem írta (cosignature). Az operátor egyetlen kulcsa már
nem elég ahhoz, hogy egy fát "igazként" mutasson.

## A javaslat: STH witness cosignatures — P1 (a réteg lényege)

- A trust-root deklarál egy **witness-allowlistet** (a `providers` mintájára:
  `witnesses: [{ name, public_keys:[pem] }]`) + egy ajánlott
  `witness_threshold`-ot. A witness-ek az operátortól FÜGGETLEN felek
  (auditor, ügyfél, konzorcium) — pont mint a root-kulcs tulajdonosa.
- Egy witness egy STH-t cosignol: a kanonikus STH (a `witness_cosignatures`
  mező NÉLKÜL) feletti Ed25519-aláírás. A cosignature-ök az STH-hoz tapadva
  utaznak (`witness_cosignatures: [{ witness_fingerprint, signature }]`),
  determinisztikusan rendezve (a 0.6 kvórum-minta: fingerprint szerint).
- A fogyasztók (monitor, verifier) egy STH-t addig **NEM fogadnak el
  teljes bizalommal**, amíg el nem éri a witness-threshold-ot a deklarált
  allowlistből. Új kód: `UNDER_WITNESSED` (a threshold alatti STH; a szint a
  policy dönti el — lehet notice vagy violation, lásd nyitott kérdés).
- A cosignature-verify ugyanaz a gépezet, mint a 0.6 `verifyQuorumSigned`
  (azonos kanonikus body, deklarált aláírók, fail-closed anomáliákra) — a
  kód nagyrészt újrahasznosul.

**Mit ad:** az equivocation-védelem MEGELŐZŐ lesz. Egy operátor nem tud egy
fogyasztónak alá-witnesselt (vagy hamis-witnesselt) split-view STH-t mutatni,
mert a fogyasztó a deklarált witness-allowlistre verifikál. A Monitor
megmarad (idő/nézet, truncation), de a bizalmi alap a publikáláskor erősödik.

**Csatorna:** a witness-protokoll (hogyan jut el az STH a witness-hez és vissza
a cosignature) a 0.8-ban OUT-OF-BAND / operátor-implementáció — a protokoll a
cosignature FORMÁTUMÁT és VERIFIKÁCIÓJÁT rögzíti, nem a hálózati gossipot.
(Mint az anchoringnál: a formátum a spec, a backend az operátoré.)

## Enabler: record-type version gate — P2

A 0.7 a control logban az ismeretlen `record_type`-ot fail-closed elveti. Amint
a 0.8 ÚJ mezőt/típust hoz (witness-allowlist a trust-rootban, cosignature az
STH-ban), kell egy **forward-kompat szabály**: a régi fogyasztó hogyan kezeli
az új, nem-értett mezőt. Elv: a TRUST-KRITIKUS mezők ismeretlensége fail-closed
(egy 0.7 verifier ne fogadjon el vakon egy 0.8 witness-elvárású STH-t úgy, hogy
a witness-mezőt nem érti), a tisztán informatívaké átléphető. Ezt ki kell
mondani, mielőtt a réteg mezőket ad.

## Cleanup: embedded_succession deprecation — P3

A control log (0.7) az elsődleges governance-csatorna. Az `embedded_succession`
(0.5) átmeneti maradt. A 0.8 formálisan **deprecated**-nek jelöli (spec +
a kód egy notice-t ad, ha látja control log mellett), és kimond egy eltávolítási
horizontot (pl. 1.0). Nincs törő változás — csak a kettős csatorna felszámolása.

## Kifejezetten NEM 0.8

- **Részleges control-disclosure** (inclusion proof a control-fán) — nincs
  valós driver (a control log kicsi, teljesen megosztott); a Merkle-gyökér
  miatt utólag is nyitva áll. Marad jelölt, ha lesz nagy control log.
- **Több control-namespace** — nincs driver.
- **Wall-clock ablakok, HSM, valódi threshold-kripto** — változatlanul kívül.

## Sorrend és DoD

P2 (version gate — előbb, mert a P1 mezőket ad) → P1 (witness cosigning) →
P3 (deprecation). Minden inkrementumra a meglévő DoD: teljes zöld suite,
red-team tesztek, backward-kompat bizonyítva (witness-allowlist NÉLKÜL a
viselkedés byte-ra 0.7), CHANGELOG + spec együtt, Python-tükör a verifikáció-
érintett részekre, multi-agent keresztreview.

## Nyitott kérdések a review-nak

1. **UNDER_WITNESSED szint:** a threshold alatti STH violation legyen-e
   (fail-closed, szigorú transzparencia-mód), vagy konfigurálható notice/
   violation (a witnessing fokozatos bevezetéséhez)? Javaslat: konfigurálható,
   default notice, `--require-witnesses` kapcsolóval violation — különben egy
   most élő, witness nélküli pilot azonnal elbukna.
2. **Witness-allowlist helye:** a trust-rootban (egy helyen a bizalmi
   horgonnyal, rotálható a meglévő lánccal) vagy külön rekordban? Javaslat:
   a trust-rootban — újrahasználja a genesis/rotáció gépezetet.
3. **A cosignature mit fed:** csak az STH-t (root_hash + tree_size + log_id),
   vagy a teljes STH-body-t a beágyazott mezőkkel? Javaslat: a teljes
   kanonikus body-t a `witness_cosignatures` nélkül — így a beágyazott
   succession/control-commitment is witness-fedett.
4. **Interakció a kulcs-rotációval:** a witness-allowlist rotációja a
   trust-root-lánccal megy; kell-e witness-revokáció külön, vagy elég a
   trust-root-utód (ami új allowlistet deklarál)? Javaslat: elég a
   trust-root-utód (a 0.6 recovery-út), külön witness-revokáció nélkül.
