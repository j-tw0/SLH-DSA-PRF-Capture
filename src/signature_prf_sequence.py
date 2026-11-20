"""
SLH-DSA address-PRF capture in the FIPS 205 signing pseudocode order.

This module reuses the existing ChipWhisperer PRF capture helper
``prf_capture_core`` but changes how
public ADRS values are generated.

The sequence follows the secret-dependent PRF calls that occur in the FIPS 205
signing pseudocode (Algorithms 10, 12, 14--16, and 19).  Only
``PRF(PK.seed, SK.seed, ADRS)`` calls are counted/captured; ``PRF_msg`` is not.

For one complete signature:

  FORS selected secrets        : k calls
  FORS auth-path subtrees      : k * (2^a - 1) calls
  WOTS+ signature values       : d * len calls
  XMSS auth-path subtrees      : d * (2^h' - 1) * len calls

Therefore the total number of SK.seed-based address-PRF calls is

  k * 2^a + d * 2^h' * len.

The ordering is also FIPS-205 faithful:

* Algorithm 16 (fors_sign): for each FORS tree, generate the selected secret
  first, then compute authentication-path sibling subtrees from height 0 to
  a-1.
* Algorithm 10 (xmss_sign): compute authentication-path sibling subtrees from
  height 0 to h'-1 first, then call wots_sign for the selected WOTS+ key.
* Algorithm 12 (ht_sign): repeat the XMSS sequence from layer 0 to layer d-1.

The SimpleSerial target still executes one isolated address PRF per host
command.  Thus this module reproduces the FIPS 205 PRF-address call sequence on
the host and sends those addresses to the target one by one; it does not run a
complete signer on the target.

By default, the message-dependent indices (FORS indices, bottom tree, and
bottom leaf) are sampled from their FIPS-valid ranges.  If indices extracted
from a concrete FIPS 205 signer are available, pass them through
``signature_paths`` to replay those exact signing paths.
"""

from __future__ import annotations

import json
import os
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

import numpy as np

import prf_capture_core as live

SIGNATURE_SEQUENCE_HELPER_VERSION = "2026-11-05-fips205-signing-order-prf-uint64-v3"

PHASE_FORS_SIGNATURE = 1
PHASE_FORS_TREEHASH = 2
PHASE_WOTS_SIGNATURE = 3
PHASE_XMSS_TREEHASH = 4

PHASE_NAME_TO_CODE = {
    "fors_signature": PHASE_FORS_SIGNATURE,
    "fors_treehash": PHASE_FORS_TREEHASH,
    "wots_signature": PHASE_WOTS_SIGNATURE,
    "xmss_treehash": PHASE_XMSS_TREEHASH,
}
PHASE_CODE_TO_NAME = {v: k for k, v in PHASE_NAME_TO_CODE.items()}
ALL_PHASES = tuple(PHASE_NAME_TO_CODE)

SIGNATURE_META_COLUMNS = np.asarray([
    "signature_id",
    "algorithm_call_index",
    "phase_code",
    "kind",
    "layer",
    "tree",
    "keypair",
    "chain",
    "tree_height",
    "tree_index",
    "tree_number",
    "selected_index",
], dtype=object)

# PRF tree indices can span the full unsigned 64-bit range for SLH-DSA-256f.
# Only the optional tree_number/selected_index fields can contain -1 in memory.
# Store -1 as UINT64_MAX in those two columns; never signed-cast tree values.
SIGNATURE_META_DTYPE = np.dtype(np.uint64)
SIGNATURE_META_UINT64_MAX = (1 << 64) - 1
SIGNATURE_META_MISSING_COLUMNS = frozenset(("tree_number", "selected_index"))



@dataclass(frozen=True)
class SignaturePath:
    """Message-dependent indices that determine one SLH-DSA signing path."""
    tree: int
    leaf: int
    fors_indices: Tuple[int, ...]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tree": int(self.tree),
            "leaf": int(self.leaf),
            "fors_indices": [int(v) for v in self.fors_indices],
        }


@dataclass(frozen=True)
class SignaturePRFCall:
    case: live.Case
    signature_id: int
    algorithm_call_index: int
    phase_code: int
    tree_number: int = -1
    selected_index: int = -1

    @property
    def phase(self) -> str:
        return PHASE_CODE_TO_NAME[int(self.phase_code)]

    def meta_row(self) -> List[int]:
        c = self.case
        return [
            int(self.signature_id),
            int(self.algorithm_call_index),
            int(self.phase_code),
            int(c.kind),
            int(c.layer),
            int(c.tree),
            int(c.keypair),
            int(c.chain),
            int(c.tree_height),
            int(c.tree_index),
            int(self.tree_number),
            int(self.selected_index),
        ]


def encode_signature_metadata_rows_uint64(calls: Sequence[SignaturePRFCall]) -> np.ndarray:
    """Encode the signing-call metadata without overflowing on 256f trees.

    Schema remains the original 12-column numeric matrix, but dtype is uint64.
    In optional columns ``tree_number`` and ``selected_index`` ONLY, -1 is
    encoded as UINT64_MAX. Values in the ``tree`` column may legitimately be
    UINT64_MAX, so decode missing values by COLUMN, not across the whole array.
    """
    rows = np.empty((len(calls), len(SIGNATURE_META_COLUMNS)), dtype=SIGNATURE_META_DTYPE)
    for row_index, call in enumerate(calls):
        values = call.meta_row()
        if len(values) != len(SIGNATURE_META_COLUMNS):
            raise ValueError(f"signature metadata row {row_index}: column count mismatch")
        for col_index, (column, raw) in enumerate(zip(SIGNATURE_META_COLUMNS, values)):
            value = int(raw)
            if value == -1 and str(column) in SIGNATURE_META_MISSING_COLUMNS:
                value = SIGNATURE_META_UINT64_MAX
            if not 0 <= value <= SIGNATURE_META_UINT64_MAX:
                raise OverflowError(
                    f"signature metadata row={row_index}, column={column}: "
                    f"value={value} is outside uint64 range"
                )
            rows[row_index, col_index] = value
    return rows


def describe_signature_metadata_encoding(info: Dict[str, Any]) -> Dict[str, Any]:
    """Add an explicit, stable decode contract to per-signature JSON."""
    data = dict(info)
    data["signature_meta_dtype"] = "uint64"
    data["signature_meta_missing_columns"] = sorted(SIGNATURE_META_MISSING_COLUMNS)
    data["signature_meta_missing_sentinel_hex"] = "0xffffffffffffffff"
    return data


def _normalize_phases(phases: Optional[Sequence[str]]) -> Tuple[str, ...]:
    if phases is None:
        return ALL_PHASES
    out: List[str] = []
    for value in phases:
        p = str(value).strip().lower()
        aliases = {
            "fors_sig": "fors_signature",
            "fors_signature": "fors_signature",
            "fors_tree": "fors_treehash",
            "fors_treehash": "fors_treehash",
            "wots_sig": "wots_signature",
            "wots_signature": "wots_signature",
            "xmss_tree": "xmss_treehash",
            "xmss_treehash": "xmss_treehash",
        }
        if p not in aliases:
            raise ValueError(
                f"unknown capture phase {value!r}; choose from {ALL_PHASES}"
            )
        p = aliases[p]
        if p not in out:
            out.append(p)
    if not out:
        raise ValueError("capture_phases is empty")
    return tuple(out)


def signature_prf_call_counts(param_set: Optional[str] = None) -> Dict[str, int]:
    """Return FIPS 205 SK.seed-based address-PRF calls per signature.

    The phase split is based on the literal signing pseudocode:
      * FORS signature: k selected secrets (Algorithm 16 line 4)
      * FORS treehash: authentication-path sibling subtrees only, totaling
        k*(2^a-1) leaf-secret generations
      * WOTS signature: d*len selected WOTS+ secret values
      * XMSS treehash: sibling subtrees only, totaling
        d*(2^h'-1)*len WOTS+ secret values

    Hence the total is k*2^a + d*2^h'*len.
    """
    params = live.PARAMS if param_set is None else live.get_parameter_set(param_set)
    h_prime = params.tree_height
    counts = {
        "fors_signature": int(params.fors_trees),
        "fors_treehash": int(params.fors_trees * ((1 << params.fors_height) - 1)),
        "wots_signature": int(params.d * params.wots_len),
        "xmss_treehash": int(params.d * ((1 << h_prime) - 1) * params.wots_len),
    }
    counts["fors_total"] = int(params.fors_trees * (1 << params.fors_height))
    counts["wots_total"] = int(params.d * (1 << h_prime) * params.wots_len)
    counts["total"] = counts["fors_total"] + counts["wots_total"]
    return counts


def sampled_signature_path(
    *,
    signature_id: int,
    index_seed: int = 20260917,
    param_set: Optional[str] = None,
) -> SignaturePath:
    """Sample signing indices from the exact ranges parsed from H_msg.

    This samples the *indices*, not independent ADRS fields.  All addresses in
    the sequence are then derived from this single path, preserving the signing
    dependencies between layers.
    """
    if param_set is not None:
        params = live.get_parameter_set(param_set)
    else:
        params = live.PARAMS

    rng = random.Random(int(index_seed) + int(signature_id))
    h_prime = params.tree_height
    tree_bits = max(params.full_height - h_prime, 0)
    tree_max = (1 << tree_bits) - 1 if tree_bits else 0
    tree = rng.randint(0, tree_max)
    leaf = rng.randint(0, (1 << h_prime) - 1)
    fors_indices = tuple(
        rng.randint(0, (1 << params.fors_height) - 1)
        for _ in range(params.fors_trees)
    )
    return SignaturePath(tree=int(tree), leaf=int(leaf), fors_indices=fors_indices)


def validate_signature_path(path: SignaturePath, *, param_set: Optional[str] = None) -> None:
    params = live.PARAMS if param_set is None else live.get_parameter_set(param_set)
    if len(path.fors_indices) != params.fors_trees:
        raise ValueError(
            f"FORS index count={len(path.fors_indices)}, expected {params.fors_trees}"
        )
    h_prime = params.tree_height
    tree_bits = max(params.full_height - h_prime, 0)
    tree_max = (1 << tree_bits) - 1 if tree_bits else 0
    if not 0 <= int(path.tree) <= tree_max:
        raise ValueError(f"tree={path.tree} is outside 0..{tree_max}")
    leaf_max = (1 << h_prime) - 1
    if not 0 <= int(path.leaf) <= leaf_max:
        raise ValueError(f"leaf={path.leaf} is outside 0..{leaf_max}")
    fors_max = (1 << params.fors_height) - 1
    for i, value in enumerate(path.fors_indices):
        if not 0 <= int(value) <= fors_max:
            raise ValueError(f"fors_indices[{i}]={value} is outside 0..{fors_max}")


def path_from_mapping(value: Mapping[str, Any], *, param_set: Optional[str] = None) -> SignaturePath:
    path = SignaturePath(
        tree=int(value["tree"]),
        leaf=int(value["leaf"]),
        fors_indices=tuple(int(v) for v in value["fors_indices"]),
    )
    validate_signature_path(path, param_set=param_set)
    return path


def build_signing_prf_call_sequence(
    *,
    signature_id: int,
    index_seed: int = 20260917,
    mode: int | str = "sha2",
    signature_path: Optional[SignaturePath | Mapping[str, Any]] = None,
    capture_phases: Optional[Sequence[str]] = None,
) -> Tuple[List[SignaturePRFCall], Dict[str, Any]]:
    """Build the FIPS 205 signing-order address-PRF sequence.

    Only calls to PRF(PK.seed, SK.seed, ADRS) are represented.

    FORS (Algorithm 16)
    -------------------
    For FORS tree i:
      1. Generate the selected secret value with fors_skGen.
      2. For j=0..a-1, compute the sibling subtree used for AUTH[j].
         A sibling subtree of height j contains 2^j leaves, and recursive
         fors_node evaluates them left-to-right.  These sibling subtrees are
         disjoint and together cover every leaf except the selected leaf.

    XMSS (Algorithm 10)
    -------------------
    At each hypertree layer:
      1. For j=0..h'-1, compute the sibling subtree used for AUTH[j].
         Each leaf invokes wots_pkGen, which performs len address-PRF calls.
      2. Generate the selected WOTS+ signature with wots_sign, which performs
         len address-PRF calls.

    Consequently every FORS leaf secret in the selected FORS key and every
    WOTS+ secret element in the selected XMSS trees is generated exactly once.
    """
    mode_i = live.normalize_mode(mode)
    params = live.PARAMS
    phases = _normalize_phases(capture_phases)
    enabled = set(phases)

    if signature_path is None:
        path = sampled_signature_path(
            signature_id=int(signature_id),
            index_seed=int(index_seed),
            param_set=params.name,
        )
        path_source = "sampled_hmsg_ranges"
    elif isinstance(signature_path, SignaturePath):
        path = signature_path
        validate_signature_path(path, param_set=params.name)
        path_source = "provided_exact_indices"
    else:
        path = path_from_mapping(signature_path, param_set=params.name)
        path_source = "provided_exact_indices"

    calls: List[SignaturePRFCall] = []
    algorithm_index = 0

    def add_call(
        case: live.Case,
        phase: str,
        *,
        tree_number: int = -1,
        selected_index: int = -1,
    ) -> None:
        nonlocal algorithm_index
        if phase in enabled:
            calls.append(SignaturePRFCall(
                case=case,
                signature_id=int(signature_id),
                algorithm_call_index=int(algorithm_index),
                phase_code=PHASE_NAME_TO_CODE[phase],
                tree_number=int(tree_number),
                selected_index=int(selected_index),
            ))
        algorithm_index += 1

    # ------------------------------------------------------------------
    # FIPS 205 Algorithm 16: fors_sign.
    # For each tree, selected SK first; then AUTH[0], AUTH[1], ..., AUTH[a-1].
    # Each AUTH[j] calls fors_node on the sibling subtree at height j.
    # ------------------------------------------------------------------
    for tree_number, selected_leaf in enumerate(path.fors_indices):
        selected_leaf = int(selected_leaf)
        base_leaf = int(tree_number) << params.fors_height
        selected_tree_index = base_leaf + selected_leaf

        # Algorithm 16 line 4 -> fors_skGen -> one address PRF.
        selected_addr = live.build_fors_prf_addr(
            layer=0,
            tree=int(path.tree),
            keypair=int(path.leaf),
            tree_height=0,
            tree_index=selected_tree_index,
            mode=mode_i,
        )
        add_call(
            live.Case(
                live.KIND_FORS, 0, int(path.tree), int(path.leaf),
                0, 0, 0, selected_tree_index, selected_addr,
            ),
            "fors_signature",
            tree_number=tree_number,
            selected_index=selected_leaf,
        )

        # Algorithm 16 lines 5--8.
        # At height j, node_index is the sibling of the on-path node.
        # A node of height j covers leaf indices
        #   node_index*2^j .. (node_index+1)*2^j - 1.
        for j in range(params.fors_height):
            node_index = (
                int(tree_number) * (1 << (params.fors_height - j))
                + ((selected_leaf >> j) ^ 1)
            )
            leaf_start = node_index << j
            leaf_stop = (node_index + 1) << j

            # Recursive fors_node visits leaves left-to-right.
            for tree_index in range(leaf_start, leaf_stop):
                addr = live.build_fors_prf_addr(
                    layer=0,
                    tree=int(path.tree),
                    keypair=int(path.leaf),
                    tree_height=0,
                    tree_index=int(tree_index),
                    mode=mode_i,
                )
                add_call(
                    live.Case(
                        live.KIND_FORS, 0, int(path.tree), int(path.leaf),
                        0, 0, 0, int(tree_index), addr,
                    ),
                    "fors_treehash",
                    tree_number=tree_number,
                    selected_index=selected_leaf,
                )

    # ------------------------------------------------------------------
    # FIPS 205 Algorithms 10 and 12: XMSS/HT signing.
    # Algorithm 10 computes AUTH first, then performs wots_sign.
    # ------------------------------------------------------------------
    current_tree = int(path.tree)
    current_leaf = int(path.leaf)
    leaf_mask = (1 << params.tree_height) - 1

    for layer in range(params.d):
        selected_leaf = int(current_leaf)

        # Algorithm 10 lines 1--4: authentication path.
        for j in range(params.tree_height):
            node_index = (selected_leaf >> j) ^ 1
            leaf_start = node_index << j
            leaf_stop = (node_index + 1) << j

            # Recursive xmss_node visits WOTS+ leaves left-to-right.
            # Each wots_pkGen invokes PRF once for every chain 0..len-1.
            for leaf in range(leaf_start, leaf_stop):
                for chain in range(params.wots_len):
                    addr = live.build_wots_prf_addr(
                        layer=layer,
                        tree=current_tree,
                        keypair=int(leaf),
                        chain=chain,
                        hash_=0,
                        mode=mode_i,
                    )
                    add_call(
                        live.Case(
                            live.KIND_WOTS, layer, current_tree, int(leaf),
                            chain, 0, 0, 0, addr,
                        ),
                        "xmss_treehash",
                        selected_index=selected_leaf,
                    )

        # Algorithm 10 lines 5--7 -> Algorithm 7 wots_sign.
        for chain in range(params.wots_len):
            addr = live.build_wots_prf_addr(
                layer=layer,
                tree=current_tree,
                keypair=selected_leaf,
                chain=chain,
                hash_=0,
                mode=mode_i,
            )
            add_call(
                live.Case(
                    live.KIND_WOTS, layer, current_tree, selected_leaf,
                    chain, 0, 0, 0, addr,
                ),
                "wots_signature",
                selected_index=selected_leaf,
            )

        # Algorithm 12 lines 7--8 for the next hypertree layer.
        current_leaf = current_tree & leaf_mask
        current_tree >>= params.tree_height

    full_counts = signature_prf_call_counts(params.name)
    captured_counts = {
        phase: sum(1 for c in calls if c.phase == phase)
        for phase in ALL_PHASES
    }

    if algorithm_index != int(full_counts["total"]):
        raise AssertionError(
            f"FIPS 205 PRF-call count mismatch: built={algorithm_index}, "
            f"expected={full_counts['total']}"
        )
    for phase in ALL_PHASES:
        if phase in enabled and captured_counts[phase] != int(full_counts[phase]):
            raise AssertionError(
                f"phase {phase} count mismatch: built={captured_counts[phase]}, "
                f"expected={full_counts[phase]}"
            )

    info = {
        "format": "slh-dsa-fips205-signing-prf-address-sequence-v2",
        "helper_version": SIGNATURE_SEQUENCE_HELPER_VERSION,
        "parameter_set": params.name,
        "profile": params.profile_name,
        "mode": live.mode_name(mode_i),
        "signature_id": int(signature_id),
        "path_source": path_source,
        "index_seed": int(index_seed),
        "signature_path": path.to_dict(),
        "capture_phases": list(phases),
        "full_call_counts": full_counts,
        "captured_call_counts": captured_counts,
        "algorithm_total_calls": int(full_counts["total"]),
        "captured_total_calls": int(len(calls)),
        "fips205_order": {
            "fors": "Algorithm 16: selected secret, then AUTH sibling subtrees j=0..a-1",
            "xmss": "Algorithm 10: AUTH sibling subtrees j=0..h_prime-1, then wots_sign",
            "hypertree": "Algorithm 12: XMSS signatures from layer 0 to d-1",
        },
    }
    return calls, info


def _save_signature_metadata(
    prefix: str,
    calls: Sequence[SignaturePRFCall],
    info: Dict[str, Any],
    *,
    encoded_rows: Optional[np.ndarray] = None,
) -> None:
    rows = encode_signature_metadata_rows_uint64(calls) if encoded_rows is None else encoded_rows
    np.save(prefix + "_signature_sequence_meta.npy", rows)
    np.save(prefix + "_signature_sequence_meta_columns.npy", SIGNATURE_META_COLUMNS)
    with open(prefix + "_signature_sequence.json", "w", encoding="utf-8") as f:
        json.dump(describe_signature_metadata_encoding(info), f, ensure_ascii=False, indent=2)


def capture_one_signing_prf_sequence(
    scope,
    target,
    output_dir: str | os.PathLike,
    *,
    platform: str,
    signature_id: int,
    index_seed: int = 20260917,
    mode: int | str = "sha2",
    signature_path: Optional[SignaturePath | Mapping[str, Any]] = None,
    capture_phases: Optional[Sequence[str]] = None,
    pk_seed: Optional[bytes] = None,
    sk_seed: Optional[bytes] = None,
    sk_prf: Optional[bytes] = None,
    timeout: int = 250,
    verify_addr_each_time: bool = False,
    verify_result: bool = True,
    verify_first_n: int = 5,
    flush_every: int = 1000,
    prefix_name: str = "capture",
) -> Tuple[str, Dict[str, Any]]:
    """Capture all selected PRF calls belonging to one signing sequence."""
    calls, info = build_signing_prf_call_sequence(
        signature_id=int(signature_id),
        index_seed=int(index_seed),
        mode=mode,
        signature_path=signature_path,
        capture_phases=capture_phases,
    )
    root = Path(live.windows_to_wsl_path(output_dir))
    root.mkdir(parents=True, exist_ok=True)
    prefix = str(root / prefix_name)

    # Pre-encode BEFORE acquisition: metadata conversion cannot fail after a
    # long capture simply because a valid 256f idx_tree exceeds signed int64.
    encoded_meta = encode_signature_metadata_rows_uint64(calls)
    cases = [call.case for call in calls]
    live.capture_case_sequence_streaming(
        scope,
        target,
        prefix,
        cases,
        split_name="random",
        desc=f"signing_sequence_{int(signature_id):03d}",
        mode=mode,
        pk_seed=pk_seed,
        sk_seed=sk_seed,
        sk_prf=sk_prf,
        timeout=timeout,
        verify_addr_each_time=verify_addr_each_time,
        verify_result=verify_result,
        verify_first_n=verify_first_n,
        flush_every=flush_every,
    )
    _save_signature_metadata(prefix, calls, info, encoded_rows=encoded_meta)
    return prefix, info


def _signature_capture_complete(prefix: str, expected_rows: int) -> bool:
    """Validate a completed capture from this corrected FIPS 205 helper."""
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
        with open(prefix + "_signature_sequence.json", "r", encoding="utf-8") as f:
            info = json.load(f)
        if info.get("format") != "slh-dsa-fips205-signing-prf-address-sequence-v2":
            return False
        if info.get("helper_version") != SIGNATURE_SEQUENCE_HELPER_VERSION:
            return False
        if int(info.get("captured_total_calls", -1)) != int(expected_rows):
            return False

        traces = np.load(prefix + "_traces_random.npy", mmap_mode="r")
        addrs = np.load(prefix + "_addrs_random.npy", mmap_mode="r")
        meta = np.load(prefix + "_signature_sequence_meta.npy", mmap_mode="r")
    except Exception:
        return False
    return (
        traces.ndim == 2
        and addrs.ndim == 2
        and meta.ndim == 2
        and meta.dtype == SIGNATURE_META_DTYPE
        and meta.shape[1] == len(SIGNATURE_META_COLUMNS)
        and info.get("signature_meta_dtype") == "uint64"
        and traces.shape[0] == addrs.shape[0] == meta.shape[0] == int(expected_rows)
    )


def capture_signing_prf_sequences(
    scope,
    target,
    output_dir: str | os.PathLike,
    *,
    platform: str,
    num_signatures: int,
    index_seed: int = 20260917,
    mode: int | str = "sha2",
    signature_paths: Optional[Sequence[Mapping[str, Any] | SignaturePath]] = None,
    capture_phases: Optional[Sequence[str]] = None,
    pk_seed: Optional[bytes] = None,
    sk_seed: Optional[bytes] = None,
    sk_prf: Optional[bytes] = None,
    timeout: int = 250,
    verify_addr_each_time: bool = False,
    verify_result: bool = True,
    verify_first_n: int = 5,
    flush_every: int = 1000,
    resume: bool = True,
) -> Dict[str, Any]:
    """Capture ``num_signatures`` signing-order PRF address sequences.

    A separate directory is used for each signature so a long capture can be
    resumed at signature boundaries.
    """
    count = int(num_signatures)
    if count <= 0:
        raise ValueError("num_signatures must be positive")
    phases = _normalize_phases(capture_phases)
    root = Path(live.windows_to_wsl_path(output_dir))
    root.mkdir(parents=True, exist_ok=True)

    if signature_paths is not None and len(signature_paths) < count:
        raise ValueError(
            f"signature_paths contains {len(signature_paths)} paths but {count} signatures were requested"
        )

    manifest_path = root / "signature_sequence_capture_manifest.json"
    manifest: Dict[str, Any] = {
        "format": "slh-dsa-fips205-signing-prf-capture-v2",
        "helper_version": SIGNATURE_SEQUENCE_HELPER_VERSION,
        "parameter_set": live.ACTIVE_PARAM_SET,
        "profile": live.PARAMS.profile_name,
        "mode": live.mode_name(mode),
        "num_signatures": count,
        "index_seed": int(index_seed),
        "capture_phases": list(phases),
        "call_counts_per_full_signature": signature_prf_call_counts(),
        "build": live.get_capture_build_metadata(),
        "completed": [],
    }

    completed: Dict[int, Dict[str, Any]] = {}
    if bool(resume) and manifest_path.is_file():
        try:
            old = json.loads(manifest_path.read_text(encoding="utf-8"))
            comparable = ("parameter_set", "mode", "index_seed", "capture_phases")
            version_ok = (
                old.get("format") == "slh-dsa-fips205-signing-prf-capture-v2"
                and old.get("helper_version") == SIGNATURE_SEQUENCE_HELPER_VERSION
            )
            if version_ok and all(old.get(k) == manifest.get(k) for k in comparable):
                for row in old.get("completed", []):
                    completed[int(row["signature_id"])] = dict(row)
        except Exception:
            pass

    def write_manifest() -> None:
        manifest["completed"] = [completed[k] for k in sorted(completed)]
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    write_manifest()

    for signature_id in range(count):
        provided_path = None if signature_paths is None else signature_paths[signature_id]
        calls, preview_info = build_signing_prf_call_sequence(
            signature_id=signature_id,
            index_seed=index_seed,
            mode=mode,
            signature_path=provided_path,
            capture_phases=phases,
        )
        sig_dir = root / f"signature_{signature_id:03d}"
        prefix = str(sig_dir / "capture")
        expected_rows = len(calls)

        if bool(resume) and _signature_capture_complete(prefix, expected_rows):
            completed[signature_id] = {
                "signature_id": signature_id,
                "status": "completed-reused-disk",
                "capture_prefix": prefix,
                "captured_calls": expected_rows,
                "signature_path": preview_info["signature_path"],
            }
            write_manifest()
            print(f"[signature {signature_id:03d}] reuse existing -> skip")
            continue

        sig_dir.mkdir(parents=True, exist_ok=True)
        print()
        print("=" * 72)
        print(f"Signature {signature_id + 1}/{count} (id={signature_id:03d})")
        print("path source     :", preview_info["path_source"])
        print("captured calls  :", f"{expected_rows:,}")
        print("full sign calls :", f"{preview_info['algorithm_total_calls']:,}")
        print("=" * 72)

        actual_prefix, info = capture_one_signing_prf_sequence(
            scope,
            target,
            sig_dir,
            platform=platform,
            signature_id=signature_id,
            index_seed=index_seed,
            mode=mode,
            signature_path=provided_path,
            capture_phases=phases,
            pk_seed=pk_seed,
            sk_seed=sk_seed,
            sk_prf=sk_prf,
            timeout=timeout,
            verify_addr_each_time=verify_addr_each_time,
            verify_result=verify_result,
            verify_first_n=verify_first_n,
            flush_every=flush_every,
            prefix_name="capture",
        )
        completed[signature_id] = {
            "signature_id": signature_id,
            "status": "completed-new-request",
            "capture_prefix": actual_prefix,
            "captured_calls": int(info["captured_total_calls"]),
            "algorithm_total_calls": int(info["algorithm_total_calls"]),
            "signature_path": info["signature_path"],
        }
        write_manifest()

    return manifest


def preview_signatures(
    param_sets: Sequence[str] = ("128f", "128s", "192f", "192s", "256f", "256s"),
    *,
    signatures_per_param_set: Mapping[str, int] | int = 1,
    capture_phases: Optional[Sequence[str]] = None,
) -> List[Dict[str, Any]]:
    phases = _normalize_phases(capture_phases)
    rows: List[Dict[str, Any]] = []
    for p in param_sets:
        counts = signature_prf_call_counts(p)
        n_sig = (
            int(signatures_per_param_set)
            if isinstance(signatures_per_param_set, int)
            else int(signatures_per_param_set.get(p, 0))
        )
        per_sig = sum(counts[phase] for phase in phases)
        rows.append({
            "parameter_set": p,
            "signatures": n_sig,
            "calls_per_signature": int(per_sig),
            "full_calls_per_signature": int(counts["total"]),
            "total_captured_calls": int(n_sig * per_sig),
            **{f"calls_{phase}": int(counts[phase]) for phase in ALL_PHASES},
        })
    return rows
