// ═══════════════════════════════════════════════════════════════════════════════
// Kozos agent-naplo (mit / miert / mikor) - append-only JSONL
// ═══════════════════════════════════════════════════════════════════════════════
// A multi-agent munka kozos memoriaja. Harom agens irja: Fable (Claude Code,
// koordinator), NEXUS (Gemini CLI) es Meridian (Codex CLI). Az elv ugyanaz,
// mint az AXR receipts.jsonl-nel: csak hozzafuzes, soha atiras - igy nincs
// merge-konfliktus es a sorrend maga a tortenet.
//
// Hasznalat:
//   node agents/log.js <agent> <mit> <miert> [hivatkozas ...]
//   node agents/log.js tail [n]          - utolso n bejegyzes (default 10)
//
// Pelda:
//   node agents/log.js meridian "axr-anchor.js review" "Fable delegalta" axr-anchor.js
//
// Nulla kulso fuggoseg. A naplo helye fix (a script konyvtara), igy barmely
// cwd-bol hivva ugyanoda ir.
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');

const JOURNAL = path.join(__dirname, 'journal.jsonl');
const AGENTS = ['fable', 'nexus', 'meridian', 'qwen', 'chris'];

function tail(n) {
  if (!fs.existsSync(JOURNAL)) { console.log('(ures naplo)'); return; }
  const lines = fs.readFileSync(JOURNAL, 'utf8').trim().split('\n').filter(Boolean);
  for (const line of lines.slice(-n)) {
    let e;
    try { e = JSON.parse(line); } catch { console.log('(serult sor) ' + line); continue; }
    const refs = (e.refs && e.refs.length) ? '  [' + e.refs.join(', ') + ']' : '';
    console.log(`${e.ts}  ${String(e.agent).padEnd(8)}  ${e.what}  -- ${e.why}${refs}`);
  }
}

const args = process.argv.slice(2);
if (args[0] === 'tail') {
  tail(parseInt(args[1], 10) || 10);
  process.exit(0);
}

const [agent, what, why, ...refs] = args;
if (!agent || !what || !why) {
  console.error('Hasznalat: node agents/log.js <agent> <mit> <miert> [hivatkozas ...]');
  console.error('           node agents/log.js tail [n]');
  process.exit(2);
}
if (!AGENTS.includes(agent.toLowerCase())) {
  console.error('Ismeretlen agens: ' + agent + ' (varhato: ' + AGENTS.join(' | ') + ')');
  process.exit(2);
}

const entry = {
  ts: new Date().toISOString(),
  agent: agent.toLowerCase(),
  what,
  why,
  refs
};
fs.appendFileSync(JOURNAL, JSON.stringify(entry) + '\n');
console.log('naplozva: ' + entry.ts + ' ' + entry.agent + ' - ' + entry.what);
