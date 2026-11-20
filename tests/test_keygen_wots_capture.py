"""Hardware-free consistency tests for the SLH-DSA keygen WOTS_PRF capture.

Run from repository root: python tests/test_keygen_wots_capture.py
"""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import prf_capture_core as live
import keygen_wots_sequence_capture as keycap


def test_all_parameter_counts() -> None:
    totals = {"128f": 280, "128s": 17920, "192f": 408,
              "192s": 26112, "256f": 1072, "256s": 17152}
    for p, expected in totals.items():
        params = live.select_parameter_set(p)
        info = keycap.params_info(p)
        assert info["wots_prf_calls"] == expected
        assert info["top_layer"] == params.d - 1
        assert info["wots_keypairs"] * info["wots_len"] == expected
        for idx in (0, params.wots_len - 1, params.wots_len, expected - 1):
            case = keycap.keygen_case(p, idx)
            keypair, chain = divmod(idx, params.wots_len)
            assert (case.kind, case.layer, case.tree, case.keypair, case.chain) == (
                live.KIND_WOTS, params.d-1, 0, keypair, chain)
            assert case.addr == live.build_wots_prf_addr(
                layer=params.d-1, tree=0, keypair=keypair, chain=chain,
                hash_=0, mode="sha2")
            assert case.addr[9] == 5
    preview = keycap.preview_keygen_plan(["128f"], ["Os", "O0"], 2, samples=100)
    assert len(preview) == 2 and all(x["total_prf_calls"] == 560 for x in preview)
    print("PASS: key-generation address/phase/count tests for all six parameter sets")


def test_capture_resume_and_mismatch() -> None:
    live.select_parameter_set("128f")
    secret = bytes(range(16))  # public synthetic test data only
    public = live.PUB_SEED
    scope = SimpleNamespace(adc=SimpleNamespace(samples=11))
    ctx = {"addr": None, "captured": 0, "interrupt_at": 40}

    def reset(*args, **kwargs):
        return None

    def send_addr(_target, address, **kwargs):
        ctx["addr"] = bytes(address)

    def capture(_scope, _target, **kwargs):
        if ctx["interrupt_at"] is not None and ctx["captured"] >= ctx["interrupt_at"]:
            raise RuntimeError("mock interrupted")
        ctx["captured"] += 1
        digest = live.reference_digest("sha2", public, secret, ctx["addr"])
        return digest, np.full((11,), ctx["captured"], dtype=np.float32)

    def do_capture(folder: Path, sk_seed: bytes = secret):
        return keycap.capture_one_seed(
            scope, None, folder, parameter_set="128f", compiler_opt="Os",
            platform="CW308_STM32F3", seed_id=0,
            sk_seed=sk_seed, pk_seed=public, sk_prf=live.SK_PRF,
            firmware_sha256="mock-firmware-digest", resume=True,
            flush_every_leaves=1, verify_result=True, verify_first_n=5,
        )

    with tempfile.TemporaryDirectory() as tempdir:
        folder = Path(tempdir) / "seed_000"
        with patch.object(live, "reset_and_configure", reset), \
                patch.object(live, "send_addr", send_addr), \
                patch.object(live, "capture_trace", capture):
            try:
                do_capture(folder)
            except RuntimeError as e:
                assert str(e) == "mock interrupted"
            else:
                raise AssertionError("Expected test interruption")
            manifest = json.loads((folder / "keygen_capture_manifest.json").read_text())
            assert manifest["status"] == "in_progress"
            assert manifest["committed_rows"] == 35
            traces_file = folder / "capture_traces_random.npy"
            committed_before = np.load(traces_file, mmap_mode="r")[:35].copy()
            ctx["interrupt_at"] = None
            result = do_capture(folder)
            assert result["status"] == "completed" and result["committed_rows"] == 280
            assert np.array_equal(np.load(traces_file, mmap_mode="r")[:35], committed_before)
            snap = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in folder.iterdir() if p.is_file()}
            n_before = ctx["captured"]
            again = do_capture(folder)
            assert again["status"] == "completed" and ctx["captured"] == n_before
            assert snap == {p.name:hashlib.sha256(p.read_bytes()).hexdigest()
                            for p in folder.iterdir() if p.is_file()}
            traces = np.load(traces_file, mmap_mode="r")
            addrs = np.load(folder / "capture_addrs_random.npy", mmap_mode="r")
            meta = np.load(folder / "capture_params_random.npy", mmap_mode="r")
            assert traces.shape == (280, 11)
            assert addrs.shape == (280, 32)
            assert meta.shape == (280, len(live.META_COLUMNS))
            assert meta.dtype == np.dtype('uint64')
            assert all(np.array_equal(addrs[i], np.frombuffer(keycap.keygen_case('128f',i).addr,np.uint8))
                       for i in range(280))
            try:
                do_capture(folder, secret[::-1])
            except ValueError as e:
                assert 'sk_seed_sha256' in str(e)
            else:
                raise AssertionError("Mismatched secret pool accepted")
    print("PASS: mock capture, leaf-boundary resume, idempotence, address data and key mismatch rejection")


if __name__ == "__main__":
    test_all_parameter_counts()
    test_capture_resume_and_mismatch()
    print("All offline keygen WOTS_PRF tests passed")
