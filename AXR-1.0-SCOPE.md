# AXR 1.0 — readiness scope (DÖNTÖTT terv, 2026-06-13; build + tag jóváhagyásra vár)

**Döntések a Meridian (1.0-readiness/threat-model) + NEXUS (érték/adopció)
review után (CTO: Fable).** Meridian verdiktje: *a protokoll mehet 1.0-ra, de
a draft NEM engedhető át, amíg az integritási feltételek normatívan rögzítve és
teszttel fedve nincsenek.* Ezeket a feltételeket a terv most tartalmazza.

1. **Kompat-mátrix (P1) — bővítve + FAGYASZTOTT legacy fixture (Meridian).** A
   mátrix nem regenerálhatja a legacy logokat az AKTUÁLIS kóddal (az csak
   "a kód egyetért magával"). Egy STATIKUS, commitolt 0.2-es fixture
   (rögzített kulcsok+aláírások bájtjai) bizonyítja a frozen wire formatot: ha
   egy jövőbeli core-változás megtöri, a teszt elbukik. A mátrix lefedi:
   byte-stabilitás (canonicalize/signablePart/chainHash/RFC6962 vektorok,
   anchor_ref + witness_cosignatures volatilitás), opt-out sorok, binding sorok
   (CONTROL_WITHHELD/downgrade/unknown fail-closed), full-stack sor, és a
   rétegpár-interakciók (control+succession/revocation, control+witness_set,
   witness+STH-body, embedded+control, root-rotáció+governance).
2. **embedded_succession (P2): ÍRÁS megszűnik 1.0-ban, OLVASÁS/verify marad**
   (mindkét reviewer: non-breaking a meglévő logokra). Meridian legélesebb
   pontja — a legveszélyesebb maradék interakció: ha egy logban VAN control log
   ÉS egy STH embedded_succession-t hordoz, ami NINCS benne a control logban, az
   NEM lehet csendben elfogadott (különben a withholding-detektálható csatorna
   megkerülhető). Új ellenőrzés: `EMBEDDED_BYPASS` (violation) — control log
   mellett az embedded-only governance fail-closed. + migrációs jegyzet (NEXUS:
   "Governance Cleanup" cím alatt).
3. **Integritási feltételek normatívan az AXR-SPEC-1.0.md-be (Meridian-gate):**
   a witness preventív CSAK durable/non-rollbackable witness-state mellett; az
   `UNDER_WITNESSED` default-notice KOMPATIBILITÁSI mód, a witness-gate mint
   tényleges acceptance-gate állítás CSAK `--require-witnesses` mellett áll; az
   emergency witness-revokáció hiánya EXPLICIT non-guarantee. A README NEM
   állíthat gyors kompromittált-witness-kizárást (Meridian: különben blocker).
4. **API-stabilitás (DIVERGENCIA feloldva): 1.0 a KÜLSŐ szerződést fagyasztja,
   a JS modul-export felületet NEM (1.1-ig).** Meridian a modul-exportok
   rögzítését is kérte; NEXUS az adopció miatt 1.1-re halasztaná. CTO-döntés:
   az 1.0 garantálja a wire formatot, a canonicalization/hash/signature
   inputokat, a CLI exit-kódokat és a violation/notice KÓDNEVEKET (amire a
   fogyasztók cross-impl építenek); a JS modul-export felület KIMONDOTTAN nem
   fagyott 1.1-ig (valós SDK-visszajelzésig) — így nincs hamis ígéret.
5. **Getting Started (NEXUS hiányzó-egy-dolga): rövid QUICKSTART a README-be**
   (a meglévő n8n node-ra építve). Teljes middleware-példatár: 1.1.

**Build-terv (a jóváhagyás után):** P1 mátrix+fagyasztott fixture → P2
embedded writer-removal + EMBEDDED_BYPASS + migrációs jegyzet → P3
AXR-SPEC-1.0.md (áttekintő + integritási feltételek + kompat-policy) → P4
README maturity Stable + QUICKSTART + őszinte-állítás pass + COMPLIANCE. Minden
inkrementumra teljes zöld suite + cross-impl + záró keresztreview. A `v1.0.0`
tag Chris kifejezett jóváhagyására vár (piaci érettség-jelzés).

---

**Eredeti vázlat-státusz:** Nem újabb protokoll-réteg, hanem **érettségi
lépés**: a 0.5–0.8 rétegek stabilizálása, a központi állítás (frozen wire
format, additív rétegek) tényleges bizonyítása, és az EGYETLEN 1.0-ra ígért
törő tisztítás.

## Hol tartunk

A kulcs-életciklus és a transzparencia teljes: kiadás → rotáció → revokáció →
recovery → terjesztés (control log) → megelőző equivocation-védelem (witness).
Nyolc release-tag (v0.4.0 … v0.8.0), 33 zöld suite, JS↔Python cross-impl
paritás, tíz keresztellenőrzéses találat zárva. A 0.2 wire format fagyott.

## Mit ad az 1.0 (jelöltek)

### 1. Cross-version kompatibilitási mátrix — JAVASOLT P1 (a headline)

A projekt központi állítása: "0.1–0.8 minden log byte-ra verifikál, minden
réteg additív, semmi nem törik". Ez eddig RÉTEGENKÉNT van tesztelve. Az 1.0
headline-ja egy EGYETLEN, átfogó mátrix-teszt, ami a teljes stacket koherensként
bizonyítja:
- minden réteg OPT-OUT-ja a korábbi viselkedést adja byte-ra (trust-root nélkül
  0.4 TOFU; control nélkül 0.7; witness nélkül 0.7; succession nélkül 0.5 stb.);
- egy 0.1/0.2/0.3 legacy log a 0.8 toolinggal is verifikál (a frozen wire
  format élő bizonyítéka);
- egy 0.8-as teljes log (kvórum-root → rotáció → revokáció → control →
  witness) végigmegy a teljes láncon (anchor → monitor → JS + Python verifier);
- a verzió-mátrix: melyik flag-kombináció melyik viselkedést adja, explicit
  táblaként, teszttel lefedve.
Ez a credibility-gerinc; non-breaking; mindenképp érték.

### 2. embedded_succession eltávolítás — TÖRŐ, 1.0-ra ígérve (Chris-döntés)

A 0.8 deprecated-nek jelölte; a spec eltávolítási horizontja 1.0. Ez az
EGYETLEN szándékolt törő változás. Hatás: a 0.5-ös embedded_succession-t író
sidecar-út megszűnik, a governance kizárólag a control logon megy. A meglévő
0.5–0.7 logok, amik embedded_succession-t HORDOZNAK, továbbra is verifikálnak
(a mező olvasása marad) — csak ÚJ embedded_succession-t nem írunk. Kérdés
Chrisnek: 1.0-ban töröljük (tiszta egy-csatorna), vagy hagyjuk 1.x-ig olvasható-
de-deprecated állapotban? (Javaslat: az ÍRÁS megszűnik 1.0-ban, az OLVASÁS/verify
marad a backward-kompatért — így nincs törő hatás a meglévő logokon.)

### 3. Spec-konszolidáció — JAVASOLT P2

Nyolc spec-fájl (0.2–0.8) + scope-dokumentumok. Az 1.0-hoz egy **AXR-SPEC-1.0.md
áttekintő**: a teljes protokoll egyetlen belépő-dokumentumban (rétegtérkép,
record-type-regiszter, kód-regiszter, a teljes flag-mátrix, a non-guarantee-k
N1–N4 egy helyen), a rétegspecek normatív részleteivel hivatkozva. Nem írja
újra a rétegeket — navigáció + a teljes kép.

### 4. README/COMPLIANCE 1.0-frissítés — JAVASOLT P3

A maturity-tábla: a 0.5–0.8 rétegek "New" → "Stable" (tesztelt, cross-impl,
review-zott). A COMPLIANCE.md a witness/control rétegekkel (több-fél tanúsítás,
governance-transzparencia) bővítve.

## Kifejezetten NEM 1.0

- **Emergency witness-revokáció** — 0.9/1.x feature (a 0.8 specben kimondva).
- **Részleges control-disclosure, több namespace** — nincs driver.
- **Új protokoll-funkció** — az 1.0 stabilizáció, nem bővítés.

## Nyitott kérdések a review-nak

1. Az embedded_succession 1.0-s sorsa: írás-megszüntetés + olvasás-marad
   (javaslat), vagy teljes eltávolítás (törő a meglévő embedded logokon)?
2. A kompat-mátrix mit fedjen MINIMÁLISAN ahhoz, hogy a "frozen wire format"
   állítás valóban bizonyított legyen — elég a flag-opt-out + legacy-verify,
   vagy kell minden rétegpár-kombináció?
3. Az 1.0 jelentsen-e API-stabilitási garanciát (semver: 1.x additív, törő csak
   2.0)? Ha igen, a modul-exportok felületét rögzíteni kell.
