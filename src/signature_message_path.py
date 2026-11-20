"""
Message-driven FIPS 205 SLH-DSA address-PRF capture helper.

This module adds the part that the previous signing-order helper deliberately
left out: it generates a message, evaluates the FIPS 205 SHA2 PRF_msg and H_msg
functions, extracts md / idx_tree / idx_leaf from that digest, derives the FORS
indices from md, and only then builds the exact FIPS 205 PRF-address call
sequence.

The target still executes one isolated address PRF per trace.  The host derives
exactly the same public path-selection values that a pure SLH-DSA signer would
use for the generated message, and then sends the corresponding WOTS_PRF and
FORS_PRF addresses to the target in FIPS 205 pseudocode order.

For a self-consistent signing key, PK.root is derived from the same SK.seed and
PK.seed (or loaded from a cache) before H_msg is evaluated.

This is an experimental/reproducible capture helper, not production signing
code.  The default "hedged" additional randomness is deterministically derived
from a user seed so the same experiment can be replayed across compiler builds.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

import numpy as np

import prf_capture_core as live
import signature_prf_sequence as seq

MESSAGE_CAPTURE_HELPER_VERSION = "2026-11-10-fips205-random-message-append-safe-uint64-v5"


def _require_sha2(mode: int | str) -> int:
    mode_i = live.normalize_mode(mode)
    if mode_i != live.MODE_SHA2:
        raise ValueError("message-driven helper currently supports SHA2 parameter sets only")
    return mode_i


def _ceil_div(x: int, y: int) -> int:
    return (int(x) + int(y) - 1) // int(y)


def _deterministic_bytes(
    *,
    seed: int,
    signature_id: int,
    length: int,
    purpose: str,
    parameter_set: Optional[str] = None,
) -> bytes:
    """Deterministic pseudorandom bytes for reproducible experiments."""
    n = int(length)
    if n < 0:
        raise ValueError("length must be non-negative")
    param = live.ACTIVE_PARAM_SET if parameter_set is None else str(parameter_set)
    material = (
        f"SLH-DSA|{param}|{purpose}|seed={int(seed)}|sig={int(signature_id)}"
    ).encode("utf-8")
    return hashlib.shake_256(material).digest(n)


def random_message_for_signature(
    signature_id: int,
    *,
    message_seed: int = 20260917,
    message_length: int = 32,
) -> bytes:
    """Return a reproducible random-looking message for one signature."""
    if int(message_length) <= 0:
        raise ValueError("message_length must be positive")
    return _deterministic_bytes(
        seed=int(message_seed),
        signature_id=int(signature_id),
        length=int(message_length),
        purpose="message",
    )


def hedged_addrnd_for_signature(
    signature_id: int,
    *,
    addrnd_seed: int = 20260918,
    n: Optional[int] = None,
) -> bytes:
    width = live.SLH_N if n is None else int(n)
    return _deterministic_bytes(
        seed=int(addrnd_seed),
        signature_id=int(signature_id),
        length=width,
        purpose="addrnd",
    )


def pure_internal_message(message: bytes, context: bytes = b"") -> bytes:
    """Algorithm 22 input M' = 0x00 || len(ctx) || ctx || M."""
    msg = bytes(message)
    ctx = bytes(context)
    if len(ctx) > 255:
        raise ValueError("SLH-DSA context must be at most 255 bytes")
    return b"\x00" + bytes([len(ctx)]) + ctx + msg


def _mgf1(seed: bytes, out_len: int, hash_name: str) -> bytes:
    """MGF1 with a four-byte big-endian counter (RFC 8017)."""
    out_len = int(out_len)
    if out_len < 0:
        raise ValueError("out_len must be non-negative")
    hlen = hashlib.new(hash_name).digest_size
    blocks = _ceil_div(out_len, hlen)
    out = bytearray()
    for counter in range(blocks):
        c = int(counter).to_bytes(4, "big")
        h = hashlib.new(hash_name)
        h.update(bytes(seed))
        h.update(c)
        out.extend(h.digest())
    return bytes(out[:out_len])


def fips205_prf_msg_sha2(
    sk_prf: bytes,
    opt_rand: bytes,
    internal_message: bytes,
    *,
    n: Optional[int] = None,
) -> bytes:
    """FIPS 205 SHA2 PRF_msg for n=16/24/32."""
    width = live.SLH_N if n is None else int(n)
    if len(sk_prf) != width:
        raise ValueError(f"SK.prf must be {width} bytes")
    if len(opt_rand) != width:
        raise ValueError(f"opt_rand must be {width} bytes")
    digestmod = hashlib.sha256 if width == 16 else hashlib.sha512
    return hmac.new(bytes(sk_prf), bytes(opt_rand) + bytes(internal_message), digestmod).digest()[:width]


def hmsg_output_length_bytes(params=None) -> int:
    p = live.PARAMS if params is None else params
    h_prime = p.tree_height
    return (
        _ceil_div(p.fors_trees * p.fors_height, 8)
        + _ceil_div(p.full_height - h_prime, 8)
        + _ceil_div(h_prime, 8)
    )


def fips205_h_msg_sha2(
    R: bytes,
    pk_seed: bytes,
    pk_root: bytes,
    internal_message: bytes,
    *,
    params=None,
) -> bytes:
    """FIPS 205 SHA2 H_msg for all six SHA2 parameter sets."""
    p = live.PARAMS if params is None else params
    n = int(p.n)
    for name, value in (("R", R), ("PK.seed", pk_seed), ("PK.root", pk_root)):
        if len(value) != n:
            raise ValueError(f"{name} must be {n} bytes")

    if n == 16:
        inner = hashlib.sha256(bytes(R) + bytes(pk_seed) + bytes(pk_root) + bytes(internal_message)).digest()
        mgf_seed = bytes(R) + bytes(pk_seed) + inner
        return _mgf1(mgf_seed, hmsg_output_length_bytes(p), "sha256")

    inner = hashlib.sha512(bytes(R) + bytes(pk_seed) + bytes(pk_root) + bytes(internal_message)).digest()
    mgf_seed = bytes(R) + bytes(pk_seed) + inner
    return _mgf1(mgf_seed, hmsg_output_length_bytes(p), "sha512")


def base_2b(data: bytes, b: int, out_len: int) -> Tuple[int, ...]:
    """Algorithm 4 (base_2b), returned as a tuple of integers."""
    X = bytes(data)
    b = int(b)
    out_len = int(out_len)
    if b <= 0:
        raise ValueError("b must be positive")
    if len(X) * 8 < out_len * b:
        raise ValueError("input does not contain enough bits")

    in_index = 0
    bits = 0
    total = 0
    out = []
    for _ in range(out_len):
        while bits < b:
            total = (total << 8) + X[in_index]
            in_index += 1
            bits += 8
        bits -= b
        out.append((total >> bits) & ((1 << b) - 1))
    return tuple(out)


def signature_path_from_hmsg_digest(digest: bytes, *, params=None) -> Tuple[seq.SignaturePath, Dict[str, Any]]:
    """Extract md, idx_tree, idx_leaf, and FORS indices as in Algorithm 19."""
    p = live.PARAMS if params is None else params
    h_prime = int(p.tree_height)
    md_bytes = _ceil_div(p.fors_trees * p.fors_height, 8)
    tree_bytes = _ceil_div(p.full_height - h_prime, 8)
    leaf_bytes = _ceil_div(h_prime, 8)
    expected = md_bytes + tree_bytes + leaf_bytes
    if len(digest) != expected:
        raise ValueError(f"H_msg digest must be {expected} bytes, got {len(digest)}")

    md = bytes(digest[:md_bytes])
    tree_raw = bytes(digest[md_bytes:md_bytes + tree_bytes])
    leaf_raw = bytes(digest[md_bytes + tree_bytes:])

    tree_bits = int(p.full_height - h_prime)
    idx_tree = int.from_bytes(tree_raw, "big") % (1 << tree_bits) if tree_bits else 0
    idx_leaf = int.from_bytes(leaf_raw, "big") % (1 << h_prime)
    fors_indices = base_2b(md, p.fors_height, p.fors_trees)

    path = seq.SignaturePath(
        tree=int(idx_tree),
        leaf=int(idx_leaf),
        fors_indices=tuple(int(v) for v in fors_indices),
    )
    seq.validate_signature_path(path, param_set=p.name)
    return path, {
        "md_hex": md.hex(),
        "idx_tree_bytes_hex": tree_raw.hex(),
        "idx_leaf_bytes_hex": leaf_raw.hex(),
        "idx_tree": int(idx_tree),
        "idx_leaf": int(idx_leaf),
        "fors_indices": [int(v) for v in fors_indices],
    }


# ---------------------------------------------------------------------------
# SHA2 public-root derivation for a self-consistent key pair
# ---------------------------------------------------------------------------

def _adrs_c(addr: bytes | bytearray) -> bytes:
    return live.compress_adrs_for_sha2(addr)


def _sha2_prf(pk_seed: bytes, sk_seed: bytes, addr: bytes) -> bytes:
    n = live.SLH_N
    return hashlib.sha256(
        bytes(pk_seed) + bytes(64 - n) + _adrs_c(addr) + bytes(sk_seed)
    ).digest()[:n]


def _sha2_f(pk_seed: bytes, addr: bytes, m1: bytes) -> bytes:
    n = live.SLH_N
    if len(m1) != n:
        raise ValueError(f"F input must be {n} bytes")
    return hashlib.sha256(
        bytes(pk_seed) + bytes(64 - n) + _adrs_c(addr) + bytes(m1)
    ).digest()[:n]


def _sha2_h(pk_seed: bytes, addr: bytes, m2: bytes) -> bytes:
    n = live.SLH_N
    if len(m2) != 2 * n:
        raise ValueError(f"H input must be {2*n} bytes")
    if n == 16:
        return hashlib.sha256(
            bytes(pk_seed) + bytes(64 - n) + _adrs_c(addr) + bytes(m2)
        ).digest()[:n]
    return hashlib.sha512(
        bytes(pk_seed) + bytes(128 - n) + _adrs_c(addr) + bytes(m2)
    ).digest()[:n]


def _sha2_tl(pk_seed: bytes, addr: bytes, ml: bytes) -> bytes:
    n = live.SLH_N
    if n == 16:
        return hashlib.sha256(
            bytes(pk_seed) + bytes(64 - n) + _adrs_c(addr) + bytes(ml)
        ).digest()[:n]
    return hashlib.sha512(
        bytes(pk_seed) + bytes(128 - n) + _adrs_c(addr) + bytes(ml)
    ).digest()[:n]


def _make_addr(
    *,
    layer: int,
    tree: int,
    typ: int,
    keypair: Optional[int] = None,
    chain: Optional[int] = None,
    hash_: Optional[int] = None,
    tree_height: Optional[int] = None,
    tree_index: Optional[int] = None,
) -> bytes:
    addr = live.addr_new()
    live.set_layer_addr(addr, int(layer), "sha2")
    live.set_tree_addr(addr, int(tree), "sha2")
    live.set_type(addr, int(typ), "sha2")
    if keypair is not None:
        live.set_keypair_addr(addr, int(keypair), "sha2")
    if chain is not None:
        live.set_chain_addr(addr, int(chain), "sha2")
    if hash_ is not None:
        live.set_hash_addr(addr, int(hash_), "sha2")
    if tree_height is not None:
        live.set_tree_height(addr, int(tree_height), "sha2")
    if tree_index is not None:
        live.set_tree_index(addr, int(tree_index), "sha2")
    return bytes(addr)


def _wots_pk_gen_sha2(sk_seed: bytes, pk_seed: bytes, *, layer: int, tree: int, keypair: int) -> bytes:
    p = live.PARAMS
    values = []
    for chain in range(p.wots_len):
        sk_addr = live.build_wots_prf_addr(
            layer=layer,
            tree=tree,
            keypair=keypair,
            chain=chain,
            hash_=0,
            mode="sha2",
        )
        tmp = _sha2_prf(pk_seed, sk_seed, sk_addr)
        for hash_index in range(p.wots_w - 1):
            hash_addr = _make_addr(
                layer=layer,
                tree=tree,
                typ=live.SLH_ADDR_TYPE_WOTS,
                keypair=keypair,
                chain=chain,
                hash_=hash_index,
            )
            tmp = _sha2_f(pk_seed, hash_addr, tmp)
        values.append(tmp)

    wotspk_addr = _make_addr(
        layer=layer,
        tree=tree,
        typ=live.SLH_ADDR_TYPE_WOTSPK,
        keypair=keypair,
    )
    return _sha2_tl(pk_seed, wotspk_addr, b"".join(values))


def derive_pk_root_sha2(sk_seed: bytes, pk_seed: bytes) -> bytes:
    """Derive PK.root exactly as Algorithm 18 -> xmss_node(top layer)."""
    _require_sha2("sha2")
    n = live.SLH_N
    if len(sk_seed) != n or len(pk_seed) != n:
        raise ValueError(f"SK.seed and PK.seed must both be {n} bytes")

    p = live.PARAMS
    layer = int(p.d - 1)
    tree = 0
    nodes = [
        _wots_pk_gen_sha2(sk_seed, pk_seed, layer=layer, tree=tree, keypair=i)
        for i in range(1 << p.tree_height)
    ]

    for height in range(1, p.tree_height + 1):
        next_nodes = []
        for index in range(len(nodes) // 2):
            tree_addr = _make_addr(
                layer=layer,
                tree=tree,
                typ=live.SLH_ADDR_TYPE_HASHTREE,
                tree_height=height,
                tree_index=index,
            )
            next_nodes.append(
                _sha2_h(pk_seed, tree_addr, nodes[2 * index] + nodes[2 * index + 1])
            )
        nodes = next_nodes
    if len(nodes) != 1:
        raise AssertionError("XMSS root derivation did not end in one node")
    return bytes(nodes[0])


def load_or_derive_pk_root_sha2(
    cache_path: str | os.PathLike,
    *,
    sk_seed: bytes,
    pk_seed: bytes,
    force_recompute: bool = False,
) -> Tuple[bytes, Dict[str, Any]]:
    """Cache PK.root so compiler-option sweeps do not recompute it."""
    path = Path(live.windows_to_wsl_path(cache_path))
    path.parent.mkdir(parents=True, exist_ok=True)
    sk_hash = hashlib.sha256(bytes(sk_seed)).hexdigest()
    pk_hash = hashlib.sha256(bytes(pk_seed)).hexdigest()

    if path.is_file() and not bool(force_recompute):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if (
                data.get("format") == "slh-dsa-derived-pk-root-sha2-v1"
                and data.get("parameter_set") == live.ACTIVE_PARAM_SET
                and data.get("sk_seed_sha256") == sk_hash
                and data.get("pk_seed_sha256") == pk_hash
            ):
                root = bytes.fromhex(data["pk_root_hex"])
                if len(root) == live.SLH_N:
                    data["cache_hit"] = True
                    return root, data
        except Exception:
            pass

    root = derive_pk_root_sha2(bytes(sk_seed), bytes(pk_seed))
    data = {
        "format": "slh-dsa-derived-pk-root-sha2-v1",
        "helper_version": MESSAGE_CAPTURE_HELPER_VERSION,
        "parameter_set": live.ACTIVE_PARAM_SET,
        "n": int(live.SLH_N),
        "sk_seed_sha256": sk_hash,
        "pk_seed_sha256": pk_hash,
        "pk_root_hex": root.hex(),
        "cache_hit": False,
    }
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return root, data


# ---------------------------------------------------------------------------
# Message -> H_msg path -> FIPS 205 address-PRF sequence
# ---------------------------------------------------------------------------

def derive_message_driven_path(
    *,
    signature_id: int,
    sk_prf: bytes,
    pk_seed: bytes,
    pk_root: bytes,
    message_seed: int = 20260917,
    message_length: int = 32,
    signing_variant: str = "hedged",
    addrnd_seed: int = 20260918,
    context: bytes = b"",
    message: Optional[bytes] = None,
) -> Tuple[seq.SignaturePath, Dict[str, Any]]:
    """Generate/accept M and derive the exact FIPS 205 signing path."""
    p = live.PARAMS
    n = p.n
    if len(sk_prf) != n or len(pk_seed) != n or len(pk_root) != n:
        raise ValueError("SK.prf, PK.seed, and PK.root must match the active n")

    content = (
        random_message_for_signature(
            int(signature_id),
            message_seed=int(message_seed),
            message_length=int(message_length),
        )
        if message is None
        else bytes(message)
    )
    internal_message = pure_internal_message(content, context=bytes(context))

    variant = str(signing_variant).strip().lower()
    if variant in ("hedged", "randomized", "random"):
        addrnd = hedged_addrnd_for_signature(
            int(signature_id), addrnd_seed=int(addrnd_seed), n=n
        )
        opt_rand = addrnd
        variant = "hedged"
    elif variant in ("deterministic", "det", "pkseed"):
        addrnd = b""
        opt_rand = bytes(pk_seed)
        variant = "deterministic"
    else:
        raise ValueError("signing_variant must be 'hedged' or 'deterministic'")

    R = fips205_prf_msg_sha2(bytes(sk_prf), opt_rand, internal_message, n=n)
    digest = fips205_h_msg_sha2(
        R, bytes(pk_seed), bytes(pk_root), internal_message, params=p
    )
    path, split = signature_path_from_hmsg_digest(digest, params=p)

    info = {
        "path_source": "random_message_prfmsg_hmsg",
        "signature_id": int(signature_id),
        "parameter_set": p.name,
        "signing_variant": variant,
        "message_seed": int(message_seed),
        "message_length": len(content),
        "message_hex": content.hex(),
        "message_sha256": hashlib.sha256(content).hexdigest(),
        "context_hex": bytes(context).hex(),
        "internal_message_hex": internal_message.hex(),
        "addrnd_seed": int(addrnd_seed),
        "addrnd_hex": addrnd.hex() if addrnd else None,
        "opt_rand_hex": opt_rand.hex(),
        "R_hex": R.hex(),
        "hmsg_digest_hex": digest.hex(),
        "hmsg_digest_length": len(digest),
        "pk_root_hex": bytes(pk_root).hex(),
        **split,
        "signature_path": path.to_dict(),
    }
    return path, info


def build_random_message_signing_prf_sequence(
    *,
    signature_id: int,
    sk_prf: bytes,
    pk_seed: bytes,
    pk_root: bytes,
    message_seed: int = 20260917,
    message_length: int = 32,
    signing_variant: str = "hedged",
    addrnd_seed: int = 20260918,
    context: bytes = b"",
    capture_phases: Optional[Sequence[str]] = None,
    mode: int | str = "sha2",
    message: Optional[bytes] = None,
):
    _require_sha2(mode)
    path, msg_info = derive_message_driven_path(
        signature_id=int(signature_id),
        sk_prf=bytes(sk_prf),
        pk_seed=bytes(pk_seed),
        pk_root=bytes(pk_root),
        message_seed=int(message_seed),
        message_length=int(message_length),
        signing_variant=signing_variant,
        addrnd_seed=int(addrnd_seed),
        context=bytes(context),
        message=message,
    )
    calls, seq_info = seq.build_signing_prf_call_sequence(
        signature_id=int(signature_id),
        index_seed=0,
        mode=mode,
        signature_path=path,
        capture_phases=capture_phases,
    )
    info = dict(seq_info)
    info.update(msg_info)
    info["format"] = "slh-dsa-fips205-random-message-signing-prf-address-sequence-v3"
    info["message_helper_version"] = MESSAGE_CAPTURE_HELPER_VERSION
    return calls, info


def _save_message_sequence_metadata(
    prefix: str,
    calls,
    info: Dict[str, Any],
    *,
    encoded_rows: Optional[np.ndarray] = None,
) -> None:
    # Reuse the same uint64 encoder as the non-message FIPS 205 sequence.
    # Optional -1 fields use UINT64_MAX; the tree field stays lossless.
    rows = seq.encode_signature_metadata_rows_uint64(calls) if encoded_rows is None else encoded_rows
    np.save(prefix + "_signature_sequence_meta.npy", rows)
    np.save(prefix + "_signature_sequence_meta_columns.npy", seq.SIGNATURE_META_COLUMNS)
    with open(prefix + "_signature_sequence.json", "w", encoding="utf-8") as f:
        json.dump(seq.describe_signature_metadata_encoding(info), f, ensure_ascii=False, indent=2)


def _message_signature_capture_complete(prefix: str, expected_rows: int, expected_info: Dict[str, Any]) -> bool:
    """Check old/new completed captures without requiring identical helper versions.

    Legacy signed int64 metadata is accepted only if representable/nonnegative
    where required. This allows preserving previously captured 128/192/s data.
    An unsafe/incomplete capture is NEVER overwritten by the resume workflow.
    """
    required = [
        prefix + "_traces_random.npy",
        prefix + "_addrs_random.npy",
        prefix + "_params_random.npy",
        prefix + "_capture_config.json",
        prefix + "_signature_sequence_meta.npy",
        prefix + "_signature_sequence.json",
    ]
    if not all(os.path.isfile(path) for path in required):
        return False
    try:
        data = json.loads(Path(prefix + "_signature_sequence.json").read_text(encoding="utf-8"))
        if data.get("format") != "slh-dsa-fips205-random-message-signing-prf-address-sequence-v3":
            return False
        # Version changes alone are NOT grounds to recapture or overwrite data.
        for field in (
            "parameter_set", "signature_id", "message_seed", "message_length",
            "signing_variant", "addrnd_seed", "context_hex", "message_sha256",
            "pk_root_hex", "capture_phases", "signature_path",
        ):
            if data.get(field) != expected_info.get(field):
                return False
        if int(data.get("captured_total_calls", -1)) != int(expected_rows):
            return False
        cfg = json.loads(Path(prefix + "_capture_config.json").read_text(encoding="utf-8"))
        if cfg.get("parameter_set") != expected_info["parameter_set"]:
            return False
        # If provenance was recorded, ensure it identifies the same secret seed.
        build = cfg.get("build") or {}
        expected_seed_id = expected_info.get("secret_seed_id")
        if expected_seed_id is not None and build.get("secret_seed_id") is not None:
            if int(build["secret_seed_id"]) != int(expected_seed_id):
                return False
        expected_seed_hash = expected_info.get("sk_seed_sha256")
        if expected_seed_hash and build.get("sk_seed_sha256") is not None:
            if build["sk_seed_sha256"] != expected_seed_hash:
                return False
        traces = np.load(prefix + "_traces_random.npy", mmap_mode="r", allow_pickle=False)
        addrs = np.load(prefix + "_addrs_random.npy", mmap_mode="r", allow_pickle=False)
        params = np.load(prefix + "_params_random.npy", mmap_mode="r", allow_pickle=False)
        meta = np.load(prefix + "_signature_sequence_meta.npy", mmap_mode="r", allow_pickle=False)
        if not (
            traces.ndim == 2 and traces.shape[0] == expected_rows
            and addrs.shape == (expected_rows, live.ADRS_FULL_BYTES)
            and params.ndim == 2 and params.shape[0] == expected_rows
            and meta.ndim == 2 and meta.shape == (expected_rows, len(seq.SIGNATURE_META_COLUMNS))
        ):
            return False
        if meta.dtype == np.dtype("uint64"):
            return data.get("signature_meta_dtype", "uint64") == "uint64"
        if meta.dtype == np.dtype("int64"):
            # A signed tree column can silently corrupt a 256f 64-bit tree;
            # disallow it for 256f rather than treating it as a safe completed set.
            if expected_info.get("parameter_set") == "256f":
                return False
            # Column 10/11 may legitimately encode optional fields as -1.
            return bool(np.all(meta[:, :10] >= 0))
        return False
    except Exception:
        return False


def _has_signature_capture_files(prefix: str) -> bool:
    """Even a partial/legacy capture must never be silently overwritten."""
    p = Path(prefix)
    return p.parent.is_dir() and any(p.parent.glob(p.name + "_*"))


def _expected_message_signature_info(
    *,
    signature_id: int,
    sk_prf: bytes,
    pk_seed: bytes,
    pk_root: bytes,
    message_seed: int,
    message_length: int,
    signing_variant: str,
    addrnd_seed: int,
    context: bytes,
    phases: Sequence[str],
    secret_seed_id: Optional[int] = None,
    sk_seed_sha256: Optional[str] = None,
) -> Dict[str, Any]:
    """Fast preflight: derive message/path without building huge PRF call arrays."""
    _, info = derive_message_driven_path(
        signature_id=signature_id,
        sk_prf=bytes(sk_prf),
        pk_seed=bytes(pk_seed),
        pk_root=bytes(pk_root),
        message_seed=int(message_seed),
        message_length=int(message_length),
        signing_variant=signing_variant,
        addrnd_seed=int(addrnd_seed),
        context=bytes(context),
    )
    counts = seq.signature_prf_call_counts()
    info["captured_total_calls"] = sum(int(counts[p]) for p in phases)
    info["capture_phases"] = list(phases)
    info["secret_seed_id"] = secret_seed_id
    info["sk_seed_sha256"] = sk_seed_sha256
    return info


def inspect_random_message_signature_resume(
    output_dir: str | os.PathLike,
    *,
    num_signatures: int,
    sk_prf: bytes,
    pk_seed: bytes,
    pk_root: bytes,
    sk_seed: Optional[bytes] = None,
    secret_seed_id: Optional[int] = None,
    message_seed: int = 20260917,
    message_length: int = 32,
    signing_variant: str = "hedged",
    addrnd_seed: int = 20260918,
    context: bytes = b"",
    capture_phases: Optional[Sequence[str]] = None,
    mode: int | str = "sha2",
) -> Dict[str, Any]:
    """Read-only, strict preflight. Never edits an existing file.

    If any expected signature has partial or mismatched capture files, abort
    instead of potentially overwriting the user's prior measurements.
    """
    _require_sha2(mode)
    count = int(num_signatures)
    if count <= 0:
        raise ValueError("num_signatures must be positive")
    phases = seq._normalize_phases(capture_phases)
    root = Path(live.windows_to_wsl_path(output_dir))
    manifest_path = root / "signature_sequence_capture_manifest.json"
    existing_manifest: Dict[str, Any] = {}
    if manifest_path.exists():
        try:
            existing_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise ValueError(f"Cannot read existing manifest without risk of overwrite: {manifest_path}") from exc
        comparable = {
            "parameter_set": live.ACTIVE_PARAM_SET,
            "mode": live.mode_name(mode),
            "message_seed": int(message_seed),
            "message_length": int(message_length),
            "signing_variant": str(signing_variant).strip().lower(),
            "addrnd_seed": int(addrnd_seed),
            "context_hex": bytes(context).hex(),
            "pk_root_hex": bytes(pk_root).hex(),
            "capture_phases": list(phases),
        }
        if existing_manifest.get("format") != "slh-dsa-fips205-random-message-signing-prf-capture-v3":
            raise ValueError(f"Unknown existing signing manifest format; refusing to overwrite: {manifest_path}")
        for field, expected in comparable.items():
            if existing_manifest.get(field) != expected:
                raise ValueError(
                    f"Existing {manifest_path} has incompatible {field}: "
                    f"saved={existing_manifest.get(field)!r}, expected={expected!r}; "
                    "existing measurements are untouched"
                )
    old_rows = {
        int(row["signature_id"]): row
        for row in existing_manifest.get("completed", [])
        if "signature_id" in row
    }
    completed: Dict[int, Dict[str, Any]] = dict(old_rows)
    missing = []
    for signature_id in range(count):
        sig_dir = root / f"signature_{signature_id:03d}"
        prefix = str(sig_dir / "capture")
        expected_info = _expected_message_signature_info(
            signature_id=signature_id,
            sk_prf=sk_prf,
            pk_seed=pk_seed,
            pk_root=pk_root,
            message_seed=message_seed,
            message_length=message_length,
            signing_variant=signing_variant,
            addrnd_seed=addrnd_seed,
            context=context,
            phases=phases,
            secret_seed_id=secret_seed_id,
            sk_seed_sha256=(None if sk_seed is None else hashlib.sha256(bytes(sk_seed)).hexdigest()),
        )
        expected_rows = int(expected_info["captured_total_calls"])
        if _message_signature_capture_complete(prefix, expected_rows, expected_info):
            previous = old_rows.get(signature_id, {})
            completed[signature_id] = {
                **previous,
                "signature_id": signature_id,
                "status": "completed-reused-disk",
                "capture_prefix": prefix,
                "captured_calls": expected_rows,
                "message_sha256": expected_info["message_sha256"],
                "signature_path": expected_info["signature_path"],
            }
            continue
        if _has_signature_capture_files(prefix) or (
            sig_dir.is_dir() and any(sig_dir.iterdir())
        ):
            raise FileExistsError(
                f"Signature {signature_id:03d} has existing incomplete/incompatible "
                f"files in {sig_dir}; refusing to overwrite. "
                "Please inspect or back up these files manually."
            )
        missing.append(signature_id)
    return {
        "root": str(root),
        "manifest_path": str(manifest_path),
        "old_manifest": existing_manifest,
        "completed": completed,
        "reused_signature_ids": sorted(s for s in completed if 0 <= s < count),
        "missing_signature_ids": missing,
        "requested_signatures": count,
        "capture_phases": list(phases),
    }


def capture_one_random_message_signing_prf_sequence(
    scope,
    target,
    output_dir: str | os.PathLike,
    *,
    platform: str,
    signature_id: int,
    sk_prf: bytes,
    pk_seed: bytes,
    pk_root: bytes,
    sk_seed: Optional[bytes] = None,
    message_seed: int = 20260917,
    message_length: int = 32,
    signing_variant: str = "hedged",
    addrnd_seed: int = 20260918,
    context: bytes = b"",
    capture_phases: Optional[Sequence[str]] = None,
    mode: int | str = "sha2",
    timeout: int = 250,
    verify_addr_each_time: bool = False,
    verify_result: bool = True,
    verify_first_n: int = 5,
    flush_every: int = 1000,
    prefix_name: str = "capture",
) -> Tuple[str, Dict[str, Any]]:
    calls, info = build_random_message_signing_prf_sequence(
        signature_id=int(signature_id),
        sk_prf=bytes(sk_prf),
        pk_seed=bytes(pk_seed),
        pk_root=bytes(pk_root),
        message_seed=int(message_seed),
        message_length=int(message_length),
        signing_variant=signing_variant,
        addrnd_seed=int(addrnd_seed),
        context=bytes(context),
        capture_phases=capture_phases,
        mode=mode,
    )
    root = Path(live.windows_to_wsl_path(output_dir))
    prefix = str(root / prefix_name)
    if _has_signature_capture_files(prefix):
        raise FileExistsError(
            f"Refusing to overwrite existing PRF capture files at {prefix}. "
            "Move an incomplete capture manually if recapture is required."
        )
    root.mkdir(parents=True, exist_ok=True)

    # Validate all metadata BEFORE measuring thousands of PRF traces.
    encoded_meta = seq.encode_signature_metadata_rows_uint64(calls)
    live.capture_case_sequence_streaming(
        scope,
        target,
        prefix,
        [call.case for call in calls],
        split_name="random",
        desc=f"message_signing_sequence_{int(signature_id):03d}",
        mode=mode,
        pk_seed=bytes(pk_seed),
        sk_seed=sk_seed,
        sk_prf=bytes(sk_prf),
        timeout=int(timeout),
        verify_addr_each_time=bool(verify_addr_each_time),
        verify_result=bool(verify_result),
        verify_first_n=int(verify_first_n),
        flush_every=int(flush_every),
    )
    _save_message_sequence_metadata(prefix, calls, info, encoded_rows=encoded_meta)
    return prefix, info


def capture_random_message_signing_prf_sequences(
    scope,
    target,
    output_dir: str | os.PathLike,
    *,
    platform: str,
    num_signatures: int,
    sk_prf: bytes,
    pk_seed: bytes,
    pk_root: bytes,
    sk_seed: Optional[bytes] = None,
    secret_seed_id: Optional[int] = None,
    message_seed: int = 20260917,
    message_length: int = 32,
    signing_variant: str = "hedged",
    addrnd_seed: int = 20260918,
    context: bytes = b"",
    capture_phases: Optional[Sequence[str]] = None,
    mode: int | str = "sha2",
    timeout: int = 250,
    verify_addr_each_time: bool = False,
    verify_result: bool = True,
    verify_first_n: int = 5,
    flush_every: int = 1000,
    resume: bool = True,
) -> Dict[str, Any]:
    """Append missing signature IDs; never overwrite previously stored traces.

    Existing 0..2 + requested 0..4 -> capture only 3 and 4. A mismatch, partial
    capture, or changed input configuration causes a hard error before any file
    is changed. Works with earlier complete metadata/helper versions.
    """
    if not resume:
        root = Path(live.windows_to_wsl_path(output_dir))
        if root.exists() and any(root.iterdir()):
            raise FileExistsError(
                "resume=False is unsafe with preexisting signature data: "
                f"{root}; use resume=True or an empty output directory"
            )
    scan = inspect_random_message_signature_resume(
        output_dir,
        num_signatures=num_signatures,
        sk_prf=sk_prf,
        pk_seed=pk_seed,
        pk_root=pk_root,
        sk_seed=sk_seed,
        secret_seed_id=secret_seed_id,
        message_seed=message_seed,
        message_length=message_length,
        signing_variant=signing_variant,
        addrnd_seed=addrnd_seed,
        context=context,
        capture_phases=capture_phases,
        mode=mode,
    )
    count = int(num_signatures)
    phases = tuple(scan["capture_phases"])
    root = Path(scan["root"])
    manifest_path = Path(scan["manifest_path"])
    old = scan["old_manifest"]
    completed = scan["completed"]
    missing = scan["missing_signature_ids"]

    if not missing:
        print(f"[{root.name}] all {count} signatures already on disk -> no writes")
        return old or {"num_signatures": count, "completed": [completed[k] for k in sorted(completed)]}

    # Keep the exact original manifest for audit, once. Never alter old .npy files.
    if manifest_path.is_file():
        backup = root / "signature_sequence_capture_manifest.before_multiseed.json"
        if not backup.exists():
            import shutil
            shutil.copy2(manifest_path, backup)
    root.mkdir(parents=True, exist_ok=True)
    manifest: Dict[str, Any] = {
        **old,
        "format": "slh-dsa-fips205-random-message-signing-prf-capture-v3",
        "helper_version": MESSAGE_CAPTURE_HELPER_VERSION,
        "sequence_helper_version": seq.SIGNATURE_SEQUENCE_HELPER_VERSION,
        "parameter_set": live.ACTIVE_PARAM_SET,
        "profile": live.PARAMS.profile_name,
        "mode": live.mode_name(mode),
        "num_signatures": count,
        "message_seed": int(message_seed),
        "message_length": int(message_length),
        "signing_variant": str(signing_variant).strip().lower(),
        "addrnd_seed": int(addrnd_seed),
        "context_hex": bytes(context).hex(),
        "pk_root_hex": bytes(pk_root).hex(),
        "capture_phases": list(phases),
        "call_counts_per_full_signature": seq.signature_prf_call_counts(),
        "build": live.get_capture_build_metadata(),
        "completed": [],
    }
    if sk_seed is not None:
        manifest["sk_seed_sha256"] = hashlib.sha256(bytes(sk_seed)).hexdigest()
    if secret_seed_id is not None:
        manifest["secret_seed_id"] = int(secret_seed_id)

    def write_manifest() -> None:
        manifest["completed"] = [completed[k] for k in sorted(completed)]
        tmp = manifest_path.with_suffix(manifest_path.suffix + ".tmp")
        tmp.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, manifest_path)

    print(
        f"[{root.name}] existing={len(scan['reused_signature_ids'])}, "
        f"missing={len(missing)}: {missing}"
    )
    write_manifest()
    for signature_id in missing:
        sig_dir = root / f"signature_{signature_id:03d}"
        print()
        print("=" * 72)
        print(f"Adding signature {signature_id:03d} / requested total {count}")
        print("=" * 72)
        actual_prefix, info = capture_one_random_message_signing_prf_sequence(
            scope,
            target,
            sig_dir,
            platform=platform,
            signature_id=signature_id,
            sk_prf=bytes(sk_prf),
            pk_seed=bytes(pk_seed),
            pk_root=bytes(pk_root),
            sk_seed=sk_seed,
            message_seed=int(message_seed),
            message_length=int(message_length),
            signing_variant=signing_variant,
            addrnd_seed=int(addrnd_seed),
            context=bytes(context),
            capture_phases=phases,
            mode=mode,
            timeout=int(timeout),
            verify_addr_each_time=bool(verify_addr_each_time),
            verify_result=bool(verify_result),
            verify_first_n=int(verify_first_n),
            flush_every=int(flush_every),
            prefix_name="capture",
        )
        completed[signature_id] = {
            "signature_id": int(signature_id),
            "status": "completed-new-request",
            "capture_prefix": actual_prefix,
            "captured_calls": int(info["captured_total_calls"]),
            "algorithm_total_calls": int(info["algorithm_total_calls"]),
            "message_sha256": info["message_sha256"],
            "idx_tree": int(info["idx_tree"]),
            "idx_leaf": int(info["idx_leaf"]),
            "signature_path": info["signature_path"],
        }
        write_manifest()
    return manifest


def preview_message_paths(
    *,
    num_signatures: int,
    sk_prf: bytes,
    pk_seed: bytes,
    pk_root: bytes,
    message_seed: int = 20260917,
    message_length: int = 32,
    signing_variant: str = "hedged",
    addrnd_seed: int = 20260918,
    context: bytes = b"",
) -> list[Dict[str, Any]]:
    rows = []
    for signature_id in range(int(num_signatures)):
        path, info = derive_message_driven_path(
            signature_id=signature_id,
            sk_prf=sk_prf,
            pk_seed=pk_seed,
            pk_root=pk_root,
            message_seed=message_seed,
            message_length=message_length,
            signing_variant=signing_variant,
            addrnd_seed=addrnd_seed,
            context=context,
        )
        rows.append({
            "signature_id": signature_id,
            "message_sha256": info["message_sha256"],
            "idx_tree": path.tree,
            "idx_leaf": path.leaf,
            "fors_indices": list(path.fors_indices),
        })
    return rows
