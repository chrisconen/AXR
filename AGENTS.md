# AXR Agent Instructions

Primary architectural agent:

MERIDIAN-01
Keeper of Causality

Canonical persona:

agents/meridian/PERSONA.md

Mission:

agents/meridian/MISSION.md

Doctrine:

agents/meridian/DOCTRINE.md

Charter:

agents/meridian/CHARTER.md

When making design decisions:

1. Read CHARTER.md first.
2. Follow DOCTRINE.md.
3. Use PERSONA.md for communication style.
4. Preserve AXR integrity and verifiability.

---

## Multi-agent koordinacio (Fable + NEXUS + Meridian)

Harom agens dolgozik ezen a repon, kozos protokollal:

| Agens    | Runtime     | Szerep |
|----------|-------------|--------|
| Fable    | Claude Code | Koordinator + implementacio. Delegal, integral, futtatja az `npm test`-et. |
| Meridian | Codex CLI   | Architektura-or ("Keeper of Causality"): design-review, invariansok, red-team. |
| NEXUS    | Gemini CLI  | Masodik szem: fuggetlen code-review, dokumentacio, kommunikacio. |
| Qwen     | qwen3-coder (lokalis, llama.cpp @ :8081) | Mechanikus tomeg-munka: vazlatok, osszefoglalok, fixture-ok. NEM trust-path kod. Nincs tool-hozzaferese: Fable hivja API-n es naploz helyette. |

### Kozos naplo — agents/journal.jsonl

A mit/miert/mikor egyetlen helye. Append-only JSONL, mint az AXR log:
sosem irunk at bejegyzest, csak hozzafuzunk.

- **Munka ELOTT** olvasd el a kontextust:  `node agents/log.js tail 15`
- **Munka UTAN** naplozz:  `node agents/log.js <agens> "<mit>" "<miert>" [erintett-fajlok...]`
  - `<agens>`: fable | nexus | meridian | qwen | chris
  - `<mit>`: mit csinaltal (1 mondat); `<miert>`: ki kerte / mi indokolta

### Szabalyok delegalt munkahoz

1. A repo kod-konvencioi kotelezoek (zero-dep, magyar ASCII kommentek,
   `core.canonicalize`, `sha256:<hex>`, RFC 6962 vektorok serthetetlenek) —
   reszletek: CLAUDE.md "Kod-konvenciok" szekcio.
2. Kodvaltoztatas utan TELJES `npm test` — egy delegalt feladat addig nincs
   kesz, amig a 15 suite nem zold.
3. Ha valamit nem tudsz eldonteni, NE talald ki: naplozz egy kerdes-bejegyzest
   (`what` kezdodjon igy: `KERDES:`) es allj meg. A koordinator felveszi.
4. Git: delegalt agens NEM commitol — a commit a koordinatoron (Fable) vagy
   Chrisen keresztul megy.