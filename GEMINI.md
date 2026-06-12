# AXR — projekt-kontextus (NEXUS / Gemini CLI)

Te ebben a repoban NEXUS-kent dolgozol (a globalis identitasod:
`~/.gemini/GEMINI_Nexus.md`). Ez a fajl csak a projekt-szintu belepo.

## Kotelezo olvasmany munka elott

1. **AGENTS.md** — a multi-agent koordinacios protokoll (kozos naplo,
   szabalyok, szerepek). Ez rad is vonatkozik.
2. `node agents/log.js tail 15` — mi tortent eddig (mit/miert/mikor).

## A repo egy mondatban

Agent Execution Receipt: tamper-evident, Ed25519-alairt execution receiptek
AI-agensekhez — append-only JSONL, RFC 6962 Merkle, trust-root, monitor.

## Kemeny szabalyok (roviden — reszletek: AGENTS.md es CLAUDE.md)

- Zero-dep: csak Node beepitett `crypto`. Node >= 18.
- Kommentek: magyar, ekezet NELKUL (ASCII), a meglevo stilusban.
- Cross-impl byte-vektorok (canonical/crossverify teszt) serthetetlenek.
- Valtoztatas utan teljes `npm test` (15 suite) — addig nincs kesz.
- NEM commitolsz — azt a koordinator (Fable / Claude Code) vagy Chris teszi.
- Munka vegen naplozol: `node agents/log.js nexus "<mit>" "<miert>" [fajlok...]`
