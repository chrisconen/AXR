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
    if _version_at_least(receipt.get("axr_version"), "0.3"):
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
# Fo verifier
# ------------------------------------------------------------------------------

def read_jsonl(path):
    with open(path, "r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def verify(receipts, sths, anchors, pub_raw):
    problems = []
    P = problems.append

    workflows = [r for r in receipts if r.get("receipt_type") == "workflow"]
    steps = [r for r in receipts if r.get("receipt_type") == "step"]
    wf_ids = set(w["receipt_id"] for w in workflows)

    # 1. alairasok
    for r in receipts:
        if not verify_signature(r, pub_raw):
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

    # 11. STH-lanc + consistency
    if sths:
        for s in sths:
            if not verify_signature(s, pub_raw):
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
    if len(argv) < 3:
        sys.stderr.write("Hasznalat: python3 axr_verify.py <receipts.jsonl> <public-key.pem> "
                         "[sth.jsonl] [anchors.jsonl]\n")
        return 2
    receipts = read_jsonl(argv[1])
    with open(argv[2], "r", encoding="utf-8") as f:
        pub_raw = pubkey_from_pem(f.read())
    sths = read_jsonl(argv[3]) if len(argv) > 3 else []
    anchors = read_jsonl(argv[4]) if len(argv) > 4 else []
    sths = [r for r in sths if r.get("record_type") == "sth"]

    problems, stats = verify(receipts, sths, anchors, pub_raw)
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
