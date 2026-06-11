#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# publish-sth.sh - az STH-folyam publikalasa a transparency repoba
# ═══════════════════════════════════════════════════════════════════════════════
# A horgonyzo cron UTAN fut (ugyanabban a cron-sorban, ; utan).
# CSAK a publikus artefaktumokat tolja: sth-hu.jsonl, anchors-hu.jsonl.
# A receipts-hu.jsonl SOHA nem kerul publikalasra (ugyfel-kozeli adatok).
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

AXR_DIR="${AXR_DIR:-/mnt/e/CONEN _DIGITAL/AXR/monitor-export}"
TRANSPARENCY_DIR="${TRANSPARENCY_DIR:-/mnt/e/CONEN _DIGITAL/axr-transparency-log}"

# ── biztonsagi ellenorzesek ─────────────────────────────────────────────────────
[ -f "$AXR_DIR/sth-hu.jsonl" ] || { echo "HIBA: nincs $AXR_DIR/sth-hu.jsonl"; exit 1; }
[ -d "$TRANSPARENCY_DIR/.git" ] || { echo "HIBA: $TRANSPARENCY_DIR nem git-klon"; exit 1; }

# Vedosin: privat kulcs vagy receipts SOHA nem mehet at veletlenul sem.
for forbidden in signing-key.pem sth-key.pem customer-pepper.key receipts-hu.jsonl; do
  if [ -e "$TRANSPARENCY_DIR/$forbidden" ]; then
    echo "HIBA: tiltott fajl a transparency repoban: $forbidden - publikalas leallitva"
    exit 1
  fi
done

# ── append-only masolas ─────────────────────────────────────────────────────────
cp "$AXR_DIR/sth-hu.jsonl" "$TRANSPARENCY_DIR/sth-hu.jsonl"
[ -f "$AXR_DIR/anchors-hu.jsonl" ] && cp "$AXR_DIR/anchors-hu.jsonl" "$TRANSPARENCY_DIR/anchors-hu.jsonl"

cd "$TRANSPARENCY_DIR"

# Friss GitHub token a Windows-os gh CLI-bol (WSL-bol elerheto gh.exe-n keresztul)
CLEAN_URL="https://github.com/chrisconen/axr-transparency-log.git"
if command -v gh.exe &>/dev/null; then
  GH_TOKEN=$(gh.exe auth token 2>/dev/null) || true
  if [ -n "$GH_TOKEN" ]; then
    git remote set-url origin "https://chrisconen:${GH_TOKEN}@github.com/chrisconen/axr-transparency-log.git"
  fi
fi

# cleanup trap: push utan mindig visszaallitjuk a token-mentes URL-t
cleanup() { git remote set-url origin "$CLEAN_URL" 2>/dev/null || true; }
trap cleanup EXIT

git pull --rebase origin main 2>/dev/null || true
git add sth-hu.jsonl anchors-hu.jsonl 2>/dev/null || git add sth-hu.jsonl
if git diff --cached --quiet; then
  echo "$(date -u +%FT%TZ) nincs uj STH - nincs publikalas"
  exit 0
fi
git commit -m "sth: publish $(date -u +%Y-%m-%dT%H:%MZ)"
git push
echo "$(date -u +%FT%TZ) STH-folyam publikalva"
