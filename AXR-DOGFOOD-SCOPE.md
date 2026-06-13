# AXR dogfooding (DÖNTÖTT, 2026-06-13; Meridian+NEXUS review után)

**Cím/keret (KÖTELEZŐ, mindkét reviewer egybehangzóan):**
> **"AXR records and verifies the integrity of its own development journal."**
NEM "AXR proves its own making", NEM "AI self-governance". A receipt egy
**journal-entry receipt**, nem execution receipt. N1: a receiptek a napló
MÓDOSÍTHATATLANSÁGÁT bizonyítják az aláírás óta, nem a bejegyzések tartalmi
igazságát. (Meridian példája: ha az AI hibás kódot írt, az AXR azt bizonyítja,
hogy tényleg AZT írta akkor, és utólag senki nem kozmetikázta ki.) NEXUS-keret:
"eszköz a humán auditor kezében az autonóm AI-rendszerek ellenőrzésére" — nem
az AI kormányozza magát.

**Döntések:**
1. **Kulcs-modell: (B) witness-alapú multi-fél** (mindkét reviewer: az (A)
   elrejtené a 0.8 witness-réteg erejét). A dev-log operátor-kulcsa aláírja a
   receipteket/STH-kat (Fable mint orchestrator); a witnessek a reviewer-
   agensek (Meridian, NEXUS) SAJÁT kulccsal cosignolják az STH-kat.
2. **"Látszólagos függetlenség" csapda (KÖTELEZŐ honesty):** a lokális demóban
   a kulcsok egy gépen vannak → ez SZIMULÁLT custody. A README/landing
   kimondja: "Ez a lokális demó szimulálja a független custody-t; élesben a
   witnessek külön biztonsági zónákban (Fable@Anthropic, NEXUS@Google,
   Meridian@külön processz) futnak — ez a valódi zero-trust." A demó NEM állít
   valódi függetlenséget co-located kulcsokkal.
3. **Reprodukálhatóság: build-lépés + fagyasztott pillanatkép.** `npm run
   dogfood` élőben generál+verifikál (efemer kulcsok, a képesség bizonyítéka);
   egy committolt FROZEN snapshot (receipts/sth/control/trust-root + PUBLIKUS
   kulcsok, privát kulcs NÉLKÜL) a gyors, stabil web-demó.
4. A `step`/`workflow` leképezés faithful (Meridian): node_type
   'axr.devlog.entry' jelzi, hogy journal-bejegyzés, nem runtime-lépés.

---

**Eredeti vázlat-státusz:** Nem protokoll-változás (1.0 fagyott) — egy ÚJ
ARTEFAKTUM + generátor, ami a 1.0 stacket VALÓS adaton bizonyítja: a projekt
saját három-AI fejlesztési naplója (`agents/journal.jsonl`) aláírt, anchorolt,
witness-cosignolt AXR receipt-loggá válik.

## Miért ez a stage

A motor 1.0-s és teljes; a hiányzó dolog a valós használat bizonyítéka. A
legautentikusabb valós adat kéznél van: a `journal.jsonl`, ami a Fable /
Meridian / NEXUS fejlesztési lépéseket rögzíti — 30+ bejegyzés, attribútálva.
Ezt AXR-loggá alakítva egyszerre kapunk: (a) élő, verifikálható demót, (b) a
1.0 stack end-to-end validációját nem-teszt adaton, (c) az on-brand sztorit
(a multi-AI munkapad mint verifikálható execution trail — pont az eredeti
vízió).

## A leképezés (megvitatandó)

- **Receipt-tér:** minden journal-bejegyzés → egy `step` receipt; egy
  munkamenet/nap → `workflow` receipt, ami csoportosít. A bejegyzés mezői:
  `agent` → az actor, `what`/`why` → a decision/io-summary, `refs` → az
  érintett fájlok, `ts` → timestamp. A receipt `io.input_hash` a bejegyzés
  kanonikus hash-e (tartalom-kötés).
- **Kulcs-modell (KÉRDÉS a review-nak):**
  - (A) egyetlen "dev-log operator" kulcs ír alá mindent, az agent csak
    actor-adat. Egyszerű, de a multi-Ai-attribúció csak adat.
  - (B) MINDEN agensnek SAJÁT kulcsa (fable/meridian/nexus) — a receiptet az
    aláíró agens kulcsa fedi; ez valódi multi-actor trail. On-brand, de a
    receipt-aláíró-kulcs-modell AXR-ben egy-kulcs-per-log (successionnel). A
    több aktor-kulcs az `identity`/actor-attesztáció terület.
  - Javaslat: (B) szellemében — a workflow/step actorban az agens-fingerprint,
    ÉS a 0.8 witness-mechanizmus a valódi multi-fél: lásd lent.
- **Witness = a reviewer-agensek (a legszebb, on-brand 0.8-használat):** a
  három-AI keresztreview, ami 11 találatot fogott, LITERÁLISAN witness-
  cosignature-ré válik. Meridian és NEXUS saját kulccsal cosignolják a dev-log
  STH-it. Ez GENUINE független attesztáció (külön modellek/processzek), nem
  szimbolikus — feltéve, hogy a kulcsok tényleg külön custodyban vannak.
- **Trust-root + control log:** a dev-log root-kulcsa deklarálja a genesis
  receipt/sth kulcsot; a witness-kört egy `witness_set` a control logban (a
  reviewer-agensek). Így a teljes 1.0 governance-stack VALÓS logon fut.
- **Anchor:** local backend (offline, determinisztikus) + opcionálisan OTS.

## Őszinte keret (KÖTELEZŐ, N1)

A receiptek azt bizonyítják, hogy a napló NEM változott az aláírás óta — NEM
azt, hogy a bejegyzések igazak voltak íráskor (N1). A witness-cosignature azt
bizonyítja, hogy független felek UGYANAZT az STH-t látták — az "függetlenség"
annyira valós, amennyire a kulcs-custody az. A demó ezt KIMONDJA: ez a
mechanizmus bemutatása valós adaton, nem igazság-bizonyíték. (Meridian
doktrína: evidence over claims; no overclaiming.)

## Szállítandók

1. `axr-journal-receipts.js` — generátor (journal.jsonl → receipts.jsonl),
   determinisztikus (now injektálható), zero-dep.
2. A teljes 1.0 stack a dev-logon: anchor → trust-root + control(witness_set)
   → witness-cosign → JS+Python verifier + monitor, mind zöld.
3. Teszt: a generált dev-log átmegy a teljes verifikáción (a generátor
   helyességének bizonyítéka).
4. Artefaktum: a generált dev-log (vagy egy reprodukálható `npm run`-lépés) +
   README/landing demó-szekció az őszinte kerettel.

## Nyitott kérdések a review-nak

1. Kulcs-modell: (A) egy-kulcs + actor-adat, vagy (B) witness-alapú multi-fél?
   (Javaslat: B — a witnessek a reviewer-agensek.)
2. A witness-kulcsok custodyja: hogyan legyen GENUINE független (külön gép/
   process), hogy a demó ne legyen önbecsapás?
3. Reprodukálhatóság: a generált logot COMMITOLJUK (statikus artefaktum), vagy
   csak egy `npm run dogfood` build-lépést adunk (a journal változik)?
   (Javaslat: build-lépés + egy fagyasztott pillanatkép a demóhoz.)
4. Van-e túlállítás-kockázat, amit a keret nem fed?
