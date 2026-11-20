"""Offline consistency checks for public SLH-DSA PRF capture modules."""
from __future__ import annotations

import inspect
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import prf_capture_core as live
import random_address_capture as batch
import signature_prf_sequence as seq
import signature_message_path as message


def test_parameter_set_counts():
    for parameter_set in ("128f", "128s", "192f", "192s", "256f", "256s"):
        p = live.select_parameter_set(parameter_set)
        counts = seq.signature_prf_call_counts(parameter_set)
        assert counts["total"] == p.fors_trees * (1 << p.fors_height) + p.d * (1 << p.tree_height) * p.wots_len
        assert counts["total"] == sum(counts[name] for name in seq.ALL_PHASES)
        assert len(live.SK_SEED) == p.n
        assert len(live.SK_PRF) == p.n
        assert len(live.PUB_SEED) == p.n


def test_random_capture_batch_helper_keywords():
    supported = inspect.signature(live.capture_multi_seed_fixed_random_experiment).parameters
    used = {
        "platform", "seeds", "kind", "tvla_fixed_traces", "tvla_random_traces",
        "cpa_random_traces", "mode", "capture_rng_seed", "pk_seed", "sk_prf",
        "timeout", "shuffle_sequence", "verify_addr_each_time", "verify_result",
        "verify_first_n", "flush_every", "resume", "compatible_resume",
        "fixed_seed_policy", "fixed_seed_index", "ignore_existing_fixed_nonprimary",
    }
    assert not (used - set(supported))
    assert "seed_ids" not in inspect.signature(batch.run_all_parameter_compiler_captures).parameters


def test_uint64_metadata_with_large_tree():
    live.select_parameter_set("256f")
    max_tree = (1 << 64) - 1
    case = live.Case(live.KIND_WOTS, 0, max_tree, 0, 0, 0, 0, 0, bytes(32))
    call = seq.SignaturePRFCall(case, 0, 0, seq.PHASE_XMSS_TREEHASH)
    encoded = seq.encode_signature_metadata_rows_uint64([call])
    assert int(encoded[0, 5]) == max_tree
    assert int(encoded[0, 10]) == max_tree


def test_message_path_and_determinism():
    live.select_parameter_set("128f")
    sk_seed = live.SK_SEED
    pk_seed = live.PUB_SEED
    sk_prf = live.SK_PRF
    # The root is derived from matching key material, not a hardcoded demo root.
    pk_root = message.derive_pk_root_sha2(sk_seed, pk_seed)
    path1, info1 = message.derive_message_driven_path(
        signature_id=0, sk_prf=sk_prf, pk_seed=pk_seed, pk_root=pk_root,
        message_seed=7, addrnd_seed=8,
    )
    path2, info2 = message.derive_message_driven_path(
        signature_id=0, sk_prf=sk_prf, pk_seed=pk_seed, pk_root=pk_root,
        message_seed=7, addrnd_seed=8,
    )
    assert path1 == path2
    assert info1["hmsg_digest_hex"] == info2["hmsg_digest_hex"]
    seq.validate_signature_path(path1, param_set="128f")


if __name__ == "__main__":
    test_parameter_set_counts()
    test_random_capture_batch_helper_keywords()
    test_uint64_metadata_with_large_tree()
    test_message_path_and_determinism()
    print("All offline capture smoke tests passed.")
