#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ===============================================================================
# AXR - Fuggetlen Python verifier (cross-implementation bizonyitek)
# ===============================================================================
# A "barki, barmely nyelven, fuggetlenul ellenorizheti" allitas akkor igaz, ha egy
# MASIK, fuggetlen implementacio ugyanazokat a logokat fogadja el / utasitja el,
# mint a Node referencia - es bajtra azonosan kanonizal. Ez a fajl ezt adja:
#
#   - sajat kanonizalo, ami a JS core.canonicalize-t bajtra reprodukalja
#     (UTF-16 code unit kulcs-rendezes, ECMAScript Number->String, JS string-escape);
#   - TISZTA Python Ed25519 ellenorzes (RFC 8032), kulso fuggoseg NELKUL;
#   - RFC 6962 Merkle (level-/csomo-hash, inclusion + consistency proof);
#   - a trust-kritikus mag-ellenorzesek (alairas, lancok, chain_root, step_chain,
#     workflow-lanc, szulo letezes, inclusion proof, STH-lanc + consistency).
#
# Scope: ez a CRYPTOGRAFIAI MAG cross-impl bizonyiteka. A niche 0.3/0.4 ellenorzesek
# (generativ jol-formaltsag, evidence-graph, redactable, side-effect) referencia-
# implementacioja a Node axr-verify.js; ezeket itt szandekosan nem duplikaljuk.
#
# Hasznalat:
#   python3 axr_verify.py <receipts.jsonl> <public-key.pem> [sth.jsonl] [anchors.jsonl]
# Kilepesi kod: 0 ha a mag ervenyes, 1 ha barmi hiba, 2 ha rossz hasznalat.
# ===============================================================================

import sys
import json
import base64
import hashlib
import re

# ------------------------------------------------------------------------------
# Kanonizalas - a JS core.canonicalize bajtra azonos masa
# ------------------------------------------------------------------------------

def _es_number(n):
    # ECMAScript Number->String (amit az RFC 8785 atvesz), a JS JSON.stringify-jal egyezoen.
    if isinstance(n, bool):
        raise ValueError("canonicalize: bool nem szam")
    if isinstance(n, int):
        return str(n)
    f = float(n)
    if f != f or f in (float("inf"), float("-inf")):
        raise ValueError("canonicalize: nem-veges szam (NaN/Infinity)")
    if f == 0:
        return "0"
    r = repr(f)  # Python: legrovidebb round-trip decimalis (mint a JS shortest)
    # repr exponencialis formajanak atalakitasa JS-stilusra (jel megtartva, nincs nulla-padding)
    if "e" in r or "E" in r:
        mant, exp = r.lower().split("e")
        if mant.endswith(".0"):
            mant = mant[:-2]
        ei = int(exp)  # eltavolitja a vezeto nullakat es a "+" jelet
        return "%se%s%d" % (mant, "+" if ei >= 0 else "-", abs(ei))
    if r.endswith(".0"):
        r = r[:-2]
    return r


def _enc_string(s):
    # JS JSON.stringify(string)-gel egyezo escape: ", \, vezerlokarakterek; nem-ASCII nyersen.
    # A Python json.dumps(ensure_ascii=False) ugyanezt a szabalyt koveti.
    return json.dumps(s, ensure_ascii=False, separators=(",", ":"))


def canonicalize(value):
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _enc_string(value)
    if isinstance(value, bool):
        raise ValueError("canonicalize: vart not reachable")
    if isinstance(value, (int, float)):
        return _es_number(value)
    if isinstance(value, list):
        return "[" + ",".join(canonicalize(v) for v in value) + "]"
    if isinstance(value, dict):
        # kulcs-rendezes UTF-16 code unit szerint (a JS String-osszehasonlitassal egyezoen):
        # az utf-16-be bajtsorozat rendezese pontosan a code unit sorrendet adja.
        keys = sorted(value.keys(), key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(_enc_string(k) + ":" + canonicalize(value[k]) for k in keys) + "}"
    raise ValueError("canonicalize: nem tamogatott tipus: %s" % type(value).__name__)


def sha256_str(value):
    return "sha256:" + hashlib.sha256(canonicalize(value).encode("utf-8")).hexdigest()


def _hx(h):
    return bytes.fromhex(h[7:] if h.startswith("sha256:") else h)


def _to_hash(b):
    return "sha256:" + b.hex()


# ------------------------------------------------------------------------------
# Ed25519 ellenorzes - tiszta Python (RFC 8032), kulso fuggoseg nelkul
# ------------------------------------------------------------------------------

_b = 256
_q = 2 ** 255 - 19
_d = (-121665 * pow(121666, _q - 2, _q)) % _q
_I = pow(2, (_q - 1) // 4, _q)


def _xrecover(y):
    xx = (y * y - 1) * pow(_d * y * y + 1, _q - 2, _q)
    x = pow(xx, (_q + 3) // 8, _q)
    if (x * x - xx) % _q != 0:
        x = (x * _I) % _q
    if x % 2 != 0:
        x = _q - x
    return x


_By = (4 * pow(5, _q - 2, _q)) % _q
_Bx = _xrecover(_By)
_B = [_Bx % _q, _By % _q]


def _edwards(P, Q):
    x1, y1 = P
    x2, y2 = Q
    den = pow(1 + _d * x1 * x2 * y1 * y2, _q - 2, _q)
    den2 = pow(1 - _d * x1 * x2 * y1 * y2, _q - 2, _q)
    x3 = (x1 * y2 + x2 * y1) * den
    y3 = (y1 * y2 + x1 * x2) * den2
    return [x3 % _q, y3 % _q]


def _scalarmult(P, e):
    # iterativ double-and-add (nincs melyseges rekurzio)
    Q = [0, 1]
    while e > 0:
        if e & 1:
            Q = _edwards(Q, P)
        P = _edwards(P, P)
        e >>= 1
    return Q


def _isoncurve(P):
    x, y = P
    return (-x * x + y * y - 1 - _d * x * x * y * y) % _q == 0


def _decodepoint(s):
    val = int.from_bytes(s, "little")
    y = val & ((1 << (_b - 1)) - 1)          # also 255 bit a koordinata
    x = _xrecover(y)
    if (x & 1) != ((val >> (_b - 1)) & 1):    # a felso bit az x elojele
        x = _q - x
    P = [x, y]
    if not _isoncurve(P):
        raise ValueError("ed25519: pont nincs a gorben")
    return P


def _encodepoint(P):
    x, y = P
    val = (y & ((1 << (_b - 1)) - 1)) | ((x & 1) << (_b - 1))
    return val.to_bytes(_b // 8, "little")


def ed25519_verify(signature, message, pubkey_raw):
    if len(signature) != 64 or len(pubkey_raw) != 32:
        return False
    try:
        R = _decodepoint(signature[:32])
        A = _decodepoint(pubkey_raw)
        S = int.from_bytes(signature[32:64], "little")          # 256 bit little-endian
        # FONTOS: a hash-skalar a TELJES 512 bites SHA-512 little-endian egesz (RFC 8032 Hint)
        h = int.from_bytes(hashlib.sha512(_encodepoint(R) + pubkey_raw + message).digest(), "little")
        return _scalarmult(_B, S) == _edwards(R, _scalarmult(A, h))
    except Exception:
        return False


def pubkey_from_pem(pem):
    body = "".join(l for l in pem.splitlines() if "-----" not in l)
    der = base64.b64decode(body)
    # SPKI(Ed25519) = 12 bajt fix prefix + 32 bajt kulcs
    return der[-32:]


# ------------------------------------------------------------------------------
# RFC 6962 Merkle
# ------------------------------------------------------------------------------

def _leaf_input_bytes(receipt):
    clone = dict(receipt)
    clone.pop("anchor_ref", None)
    clone.pop("redactable", None)
    return canonicalize(clone).encode("utf-8")


def leaf_hash(receipt):
    return _to_hash(hashlib.sha256(b"\x00" + _leaf_input_bytes(receipt)).digest())


def node_hash(left, right):
    return _to_hash(hashlib.sha256(b"\x01" + _hx(left) + _hx(right)).digest())


def _lpot(n):
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def mth(leaves):
    n = len(leaves)
    if n == 0:
        return "sha256:" + hashlib.sha256(b"").hexdigest()
    if n == 1:
        return leaves[0]
    k = _lpot(n)
    return node_hash(mth(leaves[:k]), mth(leaves[k:]))


def root_from_inclusion(leaf, index, tree_size, proof):
    if index < 0 or index >= tree_size:
        raise ValueError("index a fa hatarain kivul")
    fn, sn = index, tree_size - 1
    r = leaf
    for p in proof:
        if sn == 0:
            raise ValueError("inclusion proof tul hosszu")
        if (fn & 1) == 1 or fn == sn:
            r = node_hash(p, r)
            if (fn & 1) == 0:
                while True:
                    fn >>= 1
                    sn >>= 1
                    if (fn & 1) != 0 or fn == 0:
                        break
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise ValueError("inclusion proof tul rovid")
    return r


def consistency_proof(m, leaves):
    n = len(leaves)
    if m <= 0 or m > n:
        raise ValueError("ervenytelen m")
    if m == n:
        return []

    def sub(mm, lv, on_path):
        nn = len(lv)
        if mm == nn:
            return [] if on_path else [mth(lv)]
        k = _lpot(nn)
        if mm <= k:
            return sub(mm, lv[:k], on_path) + [mth(lv[k:])]
        return sub(mm - k, lv[k:], False) + [mth(lv[:k])]

    return sub(m, list(leaves), True)


def verify_consistency(m, n, old_root, new_root, proof):
    if m < 0 or n < m:
        return False
    if m == n:
        return len(proof) == 0 and old_root == new_root
    if m == 0:
        return len(proof) == 0
    node, last = m - 1, n - 1
    while node & 1:
        node >>= 1
        last >>= 1
    p = 0
    if node:
        if p >= len(proof):
            return False
        old_h = new_h = proof[p]
        p += 1
    else:
        old_h = new_h = old_root
    while node:
        if node & 1:
            if p >= len(proof):
                return False
            h = proof[p]; p += 1
            old_h = node_hash(h, old_h)
            new_h = node_hash(h, new_h)
        elif node < last:
            if p >= len(proof):
                return False
            new_h = node_hash(new_h, proof[p]); p += 1
        node >>= 1
        last >>= 1
    while last:
        if p >= len(proof):
            return False
        new_h = node_hash(new_h, proof[p]); p += 1
        last >>= 1
    return p == len(proof) and old_h == old_root and new_h == new_root


# ------------------------------------------------------------------------------
# Alairas / lanc-hash
# ------------------------------------------------------------------------------

def _version_at_least(v, mn):
    pa = [int(x) for x in str(v or "0").split(".")]
    pb = [int(x) for x in str(mn).split(".")]
    for i in range(max(len(pa), len(pb))):
        a = pa[i] if i < len(pa) else 0
        b = pb[i] if i < len(pb) else 0
        if a > b:
            return True
        if a < b:
            return False
    return True


def signable_part(receipt):
    clone = dict(receipt)
    clone.pop("signature", None)
    # Az anchor_ref MINDEN verzional az alairas UTAN irodik (sidecar
    # write-back), ezert sosem resze az alairt resznek. Jelenlet-alapon
    # vagjuk le (ahogy a chain_hash is), nem verzio-alapon: igy a 0.3-as
    # sidecar altal lehorgonyzott 0.1/0.2-es receiptek is helyesen
    # verifikalnak. (Tukor-fix a JS core.signablePart valtozasahoz.)
    clone.pop("anchor_ref", None)
    clone.pop("redactable", None)
    return clone


def chain_hash(receipt):
    if isinstance(receipt, dict) and ("anchor_ref" in receipt or "redactable" in receipt):
        clone = dict(receipt)
        clone.pop("anchor_ref", None)
        clone.pop("redactable", None)
        return sha256_str(clone)
    return sha256_str(receipt)


def verify_signature(receipt, pub_raw):
    sig = receipt.get("signature")
    if not sig:
        return False
    msg = canonicalize(signable_part(receipt)).encode("utf-8")
    return ed25519_verify(base64.b64decode(sig), msg, pub_raw)


# ------------------------------------------------------------------------------
# Kulcs-utodlas (0.5) - a JS axr-succession.js tukre
# ------------------------------------------------------------------------------
# A trust-root deklaralja a genesis kulcsokat (per log_id, per role); a tovabbi
# kulcsokat root-alairt key_succession rekordok autorizaljak. Az idovonal
# predecessor-lancolt, az autorizacio TRANZITIV (tort szem utan nincs
# "ongyogyulas" - tukor a JS buildKeyTimeline-hoz).

def key_fingerprint(pem):
    # A JS keyFingerprint-tel BYTE-AZONOS: PEM-fejlec nelkuli, whitespace-mentes
    # torzs sha256-ja.
    body = re.sub(r"\s+", "", re.sub(r"-----[^-]+-----", "", str(pem)))
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


def trust_root_mode(tr):
    # -> ("single"|"quorum", kulcs-PEM-ek, threshold) vagy None ha ervenytelen.
    # Pontosan EGY mod lehet ervenyes (tukor a JS trustRootMode-hoz).
    has_single = bool(tr.get("root_public_key"))
    has_quorum = isinstance(tr.get("root_keys"), list) or tr.get("threshold") is not None
    if has_single and has_quorum:
        return None
    if has_quorum:
        keys = tr.get("root_keys")
        m = tr.get("threshold")
        n = len(keys) if isinstance(keys, list) else 0
        if not n or not isinstance(m, int) or isinstance(m, bool) or m < 1 or m > n:
            return None
        return ("quorum", keys, m)
    if has_single:
        return ("single", [tr["root_public_key"]], 1)
    return None


def verify_quorum_signed(record, declared_pems, threshold):
    # M-of-N multi-alairas ellenorzes - SZIGORU fail-closed (tukor a JS
    # verifyQuorumSigned-hoz): barmely anomalia (duplikalt/nem-deklaralt
    # alairo, ervenytelen alairas, rendezetlen sorrend) -> elutasitas.
    sigs = record.get("signatures")
    if not isinstance(sigs, list) or not sigs:
        return False
    by_fp = {key_fingerprint(p): pubkey_from_pem(p) for p in declared_pems}
    body = {k: v for k, v in record.items() if k != "signatures"}
    msg = canonicalize(body).encode("utf-8")
    valid = 0
    prev = None
    for part in sigs:
        if not isinstance(part, dict):
            return False
        fp = part.get("key_fingerprint")
        sig = part.get("signature")
        if not fp or not sig:
            return False
        if prev is not None and not (fp > prev):
            return False  # rendezes (determinizmus) kenyszeritve; duplat is fog
        prev = fp
        raw = by_fp.get(fp)
        if raw is None:
            return False  # nem-deklaralt alairo
        if not ed25519_verify(base64.b64decode(sig), msg, raw):
            return False  # ervenytelen alairas deklaralt alairotol
        valid += 1
    return valid >= threshold


def verify_trust_root(tr):
    if not isinstance(tr, dict) or tr.get("record_type") != "trust_root":
        return False
    mode = trust_root_mode(tr)
    if mode is None:
        return False
    if mode[0] == "quorum":
        return verify_quorum_signed(tr, mode[1], mode[2])
    if not tr.get("signature"):
        return False
    body = {k: v for k, v in tr.items() if k != "signature"}
    return ed25519_verify(base64.b64decode(tr["signature"]),
                          canonicalize(body).encode("utf-8"),
                          pubkey_from_pem(tr["root_public_key"]))


def verify_key_succession(s, root_anchor):
    # root_anchor: nyers publikus kulcs (bytes, 0.5 egykulcsos ut) VAGY
    # trust-root dict (0.6: a modja dont - single vagy kvorum).
    if not isinstance(s, dict) or s.get("record_type") != "key_succession":
        return False
    if s.get("role") not in ("sth", "receipt"):
        return False
    if not s.get("predecessor_fingerprint") or not s.get("successor_public_key"):
        return False
    ef = s.get("effective_from_tree_size")
    if not isinstance(ef, int) or isinstance(ef, bool) or ef < 1:
        return False
    if s.get("successor_fingerprint") != key_fingerprint(s["successor_public_key"]):
        return False
    if isinstance(root_anchor, dict):
        mode = trust_root_mode(root_anchor)
        if mode is None:
            return False
        if mode[0] == "quorum":
            return verify_quorum_signed(s, mode[1], mode[2])
        root_raw = pubkey_from_pem(mode[1][0])
    else:
        root_raw = root_anchor
    if not s.get("signature"):
        return False
    body = {k: v for k, v in s.items() if k != "signature"}
    return ed25519_verify(base64.b64decode(s["signature"]),
                          canonicalize(body).encode("utf-8"), root_raw)


def genesis_key(tr, log_id, role):
    for l in tr.get("logs") or []:
        if isinstance(l, dict) and l.get("log_id") == log_id:
            return (l.get("genesis") or {}).get(role)
    return None


def build_key_timeline(genesis_pem, successions, role, root_pub_raw, problems):
    # -> idovonal: [{from, raw (nyers pubkey), fingerprint, authorized}]
    if not genesis_pem:
        return None
    timeline = [{"from": 0, "raw": pubkey_from_pem(genesis_pem),
                 "fingerprint": key_fingerprint(genesis_pem), "authorized": True}]
    valid = [s for s in successions
             if isinstance(s, dict) and s.get("role") == role]
    valid.sort(key=lambda s: s.get("effective_from_tree_size", 0))
    active_fp = timeline[0]["fingerprint"]
    chain_ok = True
    # csoportositas effective_from szerint: tobb rekord ugyanarra a hatarra = FORK
    groups = []
    for s in valid:
        if groups and groups[-1][0]["effective_from_tree_size"] == s["effective_from_tree_size"]:
            groups[-1].append(s)
        else:
            groups.append([s])
    for g in groups:
        ef = g[0]["effective_from_tree_size"]
        if len(g) > 1:
            # FORK: fail-closed - NEM "first-wins": egyik ag sem autorizalt, es a
            # lanc innentol vegleg mergezett (tukor a JS buildKeyTimeline-hoz)
            problems.append("kulcs-idovonal (%s): utkozes (FORK) effective_from=%s - fail-closed" % (role, ef))
            for s in g:
                timeline.append({"from": ef, "raw": pubkey_from_pem(s["successor_public_key"]),
                                 "fingerprint": s["successor_fingerprint"], "authorized": False})
            active_fp = None
            chain_ok = False
            continue
        s = g[0]
        link_ok = active_fp is not None and s.get("predecessor_fingerprint") == active_fp
        if not link_ok and active_fp is not None:
            problems.append("kulcs-idovonal (%s): tort lanc effective_from=%s" % (role, ef))
        authorized = link_ok and chain_ok
        timeline.append({"from": ef, "raw": pubkey_from_pem(s["successor_public_key"]),
                         "fingerprint": s["successor_fingerprint"], "authorized": authorized})
        active_fp = s["successor_fingerprint"]
        chain_ok = authorized
    return timeline


def key_at_tree_size(timeline, tree_size):
    chosen = None
    for e in timeline:
        if e["from"] <= tree_size:
            chosen = e
        else:
            break
    return chosen


# ------------------------------------------------------------------------------
# Fo verifier
# ------------------------------------------------------------------------------

def read_jsonl(path):
    with open(path, "r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def verify(receipts, sths, anchors, pub_raw, sth_pub_raw=None,
           trust_root=None, successions=None, log_id=None):
    # sth_pub_raw: ha adott, az STH-alairasokat KIZAROLAG ezzel ellenorizzuk
    sth_key = sth_pub_raw if sth_pub_raw is not None else pub_raw
    problems = []
    P = problems.append

    workflows = [r for r in receipts if r.get("receipt_type") == "workflow"]
    steps = [r for r in receipts if r.get("receipt_type") == "step"]
    wf_ids = set(w["receipt_id"] for w in workflows)

    # ── 15. kulcs-utodlas (0.5): idovonalak a trust-rootbol + successionokbol ──
    # SORREND-INVARIANS: minden succession ELOBB a root-kulccsal verifikalodik;
    # a hatar-szabaly a JS-sel byte-azonos (receipt: levelpozicio, STH: tree_size).
    receipt_tl = sth_tl = None
    if trust_root is not None:
        if not verify_trust_root(trust_root):
            P("a trust-root NEM verifikal (a sajat root-kulcsaval/kvorumaval)")
        else:
            eff_log = log_id or (sths[0].get("log_id") if sths else None)
            if not eff_log and len(trust_root.get("logs") or []) == 1:
                eff_log = trust_root["logs"][0].get("log_id")
            pool = []
            seen = set()
            for src, rec in ([("successions", s) for s in (successions or [])] +
                             [("embedded", s.get("embedded_succession")) for s in sths
                              if s.get("embedded_succession")]):
                if not isinstance(rec, dict) or rec.get("record_type") != "key_succession":
                    continue
                h = sha256_str(rec)
                if h in seen:
                    continue
                seen.add(h)
                if not verify_key_succession(rec, trust_root):
                    P("%s: key_succession NEM verifikal a root-kulcsra (role=%s, effective_from=%s)"
                      % (src, rec.get("role"), rec.get("effective_from_tree_size")))
                    continue
                if rec.get("log_id") != eff_log:
                    P("%s: key_succession idegen loghoz tartozik (%s != %s)"
                      % (src, rec.get("log_id"), eff_log))
                    continue
                pool.append(rec)
            if eff_log:
                # a pool mar root-verifikalt; az idovonal-epitonek horgony nem kell
                receipt_tl = build_key_timeline(genesis_key(trust_root, eff_log, "receipt"),
                                                pool, "receipt", None, problems)
                sth_tl = build_key_timeline(genesis_key(trust_root, eff_log, "sth"),
                                            pool, "sth", None, problems)

    # 1. alairasok - idovonallal a receipt a levelpozicioja (leaf_index+1)
    # szerinti kulccsal verifikal; idovonal nelkul a regi egykulcsos ut
    leaf_types = ("step", "workflow", "identity")
    leaf_pos = {}
    pos = 0
    for r in receipts:
        if r.get("receipt_type") in leaf_types:
            pos += 1
            leaf_pos[id(r)] = pos
    for r in receipts:
        key = pub_raw
        if receipt_tl is not None and id(r) in leaf_pos:
            e = key_at_tree_size(receipt_tl, leaf_pos[id(r)])
            if not e["authorized"]:
                P("receipt %s (pozicio %d): KEY_CHANGED_UNAUTHORIZED - a kulcsvaltas nem root-autorizalt"
                  % (r.get("receipt_id"), leaf_pos[id(r)]))
            key = e["raw"]
        if not verify_signature(r, key):
            P("ervenytelen alairas: %s (%s)" % (r.get("receipt_id"), r.get("receipt_type")))

    # 2-4. workflow-nkenti step-lanc, chain_root, step_chain
    for wf in workflows:
        wsteps = sorted([s for s in steps if s.get("workflow_receipt_id") == wf["receipt_id"]],
                        key=lambda s: s.get("sequence", 0))
        prev = None
        for i, s in enumerate(wsteps):
            expected = None if i == 0 else chain_hash(wsteps[i - 1])
            if s.get("previous_receipt_hash") != expected:
                P("workflow %s: %d. lepes previous_receipt_hash nem egyezik" % (wf["receipt_id"], i + 1))
            prev = s
        if wsteps:
            if wf.get("chain_root_hash") != chain_hash(wsteps[-1]):
                P("workflow %s: chain_root_hash nem egyezik az utolso lepessel" % wf["receipt_id"])
        actual_ids = [s["receipt_id"] for s in wsteps]
        if list(wf.get("step_chain", [])) != actual_ids:
            P("workflow %s: step_chain nem egyezik a tenyleges lepesekkel" % wf["receipt_id"])

    # 5. workflow-receiptek osszelancolasa (fajlbeli sorrend)
    for i, wf in enumerate(workflows):
        expected = None if i == 0 else chain_hash(workflows[i - 1])
        if wf.get("previous_receipt_hash") != expected:
            P("workflow %s: previous_receipt_hash (kereszt-futas) nem egyezik" % wf["receipt_id"])

    # 6. szulo letezes
    for s in steps:
        if s.get("workflow_receipt_id") not in wf_ids:
            P("step %s: hianyzo szulo workflow-receipt" % s.get("receipt_id"))

    # Merkle-levelek (fajlbeli sorrend)
    leaf_types = ("step", "workflow", "identity")
    leaf_receipts = [r for r in receipts if r.get("receipt_type") in leaf_types]
    leaves = [leaf_hash(r) for r in leaf_receipts]
    sth_index = {(s.get("root_hash"), s.get("tree_size")): s for s in sths}

    # 11. STH-lanc + consistency - idovonallal az STH a tree_size-anal ervenyes
    # kulccsal verifikal (tukor a JS 15. ellenorzesehez)
    if sths:
        for s in sths:
            k = sth_key
            if sth_tl is not None:
                e = key_at_tree_size(sth_tl, s.get("tree_size", 0))
                if not e["authorized"]:
                    P("STH (tree_size=%s): KEY_CHANGED_UNAUTHORIZED - a kulcsvaltas nem root-autorizalt"
                      % s.get("tree_size"))
                k = e["raw"]
            if not verify_signature(s, k):
                P("STH (tree_size=%s): ervenytelen alairas" % s.get("tree_size"))
            ts = s.get("tree_size", 0)
            if ts <= len(leaves) and mth(leaves[:ts]) != s.get("root_hash"):
                P("STH (tree_size=%s): root_hash nem egyezik az elso %s level gyokerevel" % (ts, ts))
        ordered = sorted(sths, key=lambda s: s.get("tree_size", 0))
        for i in range(1, len(ordered)):
            if ordered[i].get("previous_sth_hash") != chain_hash(ordered[i - 1]):
                P("STH %s: previous_sth_hash nem az elozore mutat" % ordered[i].get("tree_size"))
            m, n = ordered[i - 1]["tree_size"], ordered[i]["tree_size"]
            if n <= len(leaves):
                proof = consistency_proof(m, leaves[:n])
                if not verify_consistency(m, n, ordered[i - 1]["root_hash"], ordered[i]["root_hash"], proof):
                    P("STH %s -> %s: consistency proof MEGBUKOTT" % (m, n))

    # 10. inclusion proof minden horgonyzott receiptre
    anchored = 0
    for r in leaf_receipts:
        ar = r.get("anchor_ref")
        if not ar:
            continue
        anchored += 1
        try:
            got = root_from_inclusion(leaf_hash(r), ar["leaf_index"], ar["tree_size"], ar.get("inclusion_proof", []))
        except Exception as e:
            P("receipt %s: inclusion proof ervenytelen (%s)" % (r.get("receipt_id"), e))
            continue
        if got != ar.get("sth_root_hash"):
            P("receipt %s: az inclusion proof gyokere nem egyezik az anchor_ref.sth_root_hash-sel" % r.get("receipt_id"))
        if sths and (ar.get("sth_root_hash"), ar.get("tree_size")) not in sth_index:
            P("receipt %s: az anchor_ref olyan STH-ra hivatkozik, ami nincs az STH-fajlban" % r.get("receipt_id"))

    return problems, {"receipts": len(receipts), "workflows": len(workflows),
                      "steps": len(steps), "sths": len(sths), "anchored": anchored}


def main(argv):
    # --sth-key <pem>: kulcs-szerep szetvalasztas (0.4) - az STH-kat ezzel
    # (es CSAK ezzel) verifikaljuk, a receipteket tovabbra is a fo kulccsal.
    # --trust-root / --successions / --log-id (0.5): kulcs-utodlas, tukor a JS
    # verifier kapcsoloihoz.
    sth_key_path = None
    trust_root_path = None
    successions_path = None
    log_id = None
    args = []
    i = 1
    while i < len(argv):
        if argv[i] in ("--sth-key", "--trust-root", "--successions", "--log-id"):
            if i + 1 >= len(argv):
                sys.stderr.write("HIBA: %s utan hianyzik az ertek\n" % argv[i])
                return 2
            if argv[i] == "--sth-key":
                sth_key_path = argv[i + 1]
            elif argv[i] == "--trust-root":
                trust_root_path = argv[i + 1]
            elif argv[i] == "--successions":
                successions_path = argv[i + 1]
            else:
                log_id = argv[i + 1]
            i += 2
        else:
            args.append(argv[i])
            i += 1
    if len(args) < 2:
        sys.stderr.write("Hasznalat: python3 axr_verify.py <receipts.jsonl> <public-key.pem> "
                         "[sth.jsonl] [anchors.jsonl] [--sth-key sth-public.pem]\n"
                         "           [--trust-root tr.json] [--successions s.jsonl] [--log-id id]\n")
        return 2
    receipts = read_jsonl(args[0])
    with open(args[1], "r", encoding="utf-8") as f:
        pub_raw = pubkey_from_pem(f.read())
    sth_pub_raw = None
    if sth_key_path is not None:
        with open(sth_key_path, "r", encoding="utf-8") as f:
            sth_pub_raw = pubkey_from_pem(f.read())
    sths = read_jsonl(args[2]) if len(args) > 2 else []
    anchors = read_jsonl(args[3]) if len(args) > 3 else []
    sths = [r for r in sths if r.get("record_type") == "sth"]
    trust_root = None
    if trust_root_path is not None:
        with open(trust_root_path, "r", encoding="utf-8") as f:
            trust_root = json.load(f)
    successions = read_jsonl(successions_path) if successions_path else None

    problems, stats = verify(receipts, sths, anchors, pub_raw, sth_pub_raw,
                             trust_root=trust_root, successions=successions, log_id=log_id)
    print("-" * 72)
    print("Python verifier (cross-impl mag)")
    print("Receiptek: %d  (%d workflow, %d lepes)  |  %d STH, %d horgonyzott"
          % (stats["receipts"], stats["workflows"], stats["steps"], stats["sths"], stats["anchored"]))
    print("-" * 72)
    if problems:
        for p in problems:
            print("  [HIBA] " + p)
        print("EREDMENY: %d PROBLEMA. A mag ervenytelen vagy manipulalt." % len(problems))
        return 1
    print("EREDMENY: A MAG ERVENYES. Alairasok, lancok, Merkle-bizonyitekok rendben.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
