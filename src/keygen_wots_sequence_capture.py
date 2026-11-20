#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FIPS 205 SLH-DSA SHA2 key-generation WOTS_PRF *sequence* acquisition.

Experimental scope: one individually triggered/verified WOTS_PRF per waveform,
with public addresses in exactly the logical order encountered by
slh_keygen_internal -> xmss_node(top layer, tree 0) -> wots_PKgen.
This is NOT a continuous waveform of a complete key-generation operation.

Uses the existing ChipWhisperer SimpleSerial PRF firmware and capture helpers.
All six SHA2 parameter sets; multiple fixed SK.seed values; optional GCC opts.
Partial key-generation acquisitions safely resume at WOTS keypair (leaf) bounds.
Completed captures are never overwritten.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence

import numpy as np
from numpy.lib.format import open_memmap

import prf_capture_core as live
import random_address_capture as batch

VERSION = "2026-11-13-keygen-wots-prf-sequence-v1"
# Public demo master seed 424242 is NOT suitable for real cryptographic keys.
ALL_PARAMS = ("128f", "128s", "192f", "192s", "256f", "256s")
ALL_OPTS = ("Os", "O0", "O1", "O2", "O3")
REQUIRED_CAPTURE_SUFFIXES = (
    "_traces_random.npy", "_addrs_random.npy", "_params_random.npy",
    "_meta_columns.npy", "_capture_config.json", "_keygen_sequence.json",
)


def native_path(path: str | os.PathLike) -> Path:
    return Path(live.windows_to_wsl_path(path)).expanduser()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        value = json.load(f)
    if not isinstance(value, dict):
        raise ValueError(f"Not a JSON object: {path}")
    return value


def write_json_atomic(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".partial")
    with temp.open("w", encoding="utf-8") as f:
        json.dump(dict(value), f, indent=2, ensure_ascii=False)
    os.replace(temp, path)


def params_info(param_set: str) -> dict:
    p = live.get_parameter_set(param_set)
    nkeys = 1 << p.tree_height
    return {
        "parameter_set": p.name,
        "n": int(p.n), "d": int(p.d), "h_prime": int(p.tree_height),
        "top_layer": int(p.d - 1), "tree": 0,
        "wots_len": int(p.wots_len), "wots_keypairs": int(nkeys),
        "wots_prf_calls": int(nkeys * p.wots_len),
        "address_type": int(live.KIND_WOTS), "hash_addr": 0,
        "fips205_keygen_path": "slh_keygen_internal -> xmss_node(0,h_prime,top layer) -> wots_PKgen",
        "measurements_are_individual_prf_calls": True,
    }


def preview_keygen_plan(
    param_sets: Sequence[str] = ALL_PARAMS,
    compiler_opts: Sequence[str] = ("Os",),
    num_secret_seeds: int = 1,
    samples: Optional[int] = None,
) -> list[dict]:
    """No board required. Estimates wave *storage*, not actual execution time."""
    rows = []
    for param in param_sets:
        spec = params_info(param)
        for opt in compiler_opts:
            label, _ = batch.normalize_compiler_opt(opt)
            row = {**spec, "compiler_opt": label, "num_secret_seeds": int(num_secret_seeds)}
            row["total_prf_calls"] = spec["wots_prf_calls"] * int(num_secret_seeds)
            if samples is not None:
                row["estimated_trace_gib"] = row["total_prf_calls"] * int(samples) * 4 / (1024**3)
            rows.append(row)
    return rows


def keygen_case(param_set: str, index: int) -> live.Case:
    """Address order: leaf/keypair 0..2^h'-1; chain 0..len-1.

    FIPS205 compressed 22-byte address is the first 22 bytes of the returned
    32-byte ADRS. Layer=d-1, tree=0, type=5, keypair, chain, hash=0.
    """
    p = live.get_parameter_set(param_set)
    count = (1 << p.tree_height) * p.wots_len
    if not 0 <= int(index) < count:
        raise IndexError(f"keygen PRF call {index} out of range 0..{count-1}")
    kp, chain = divmod(int(index), p.wots_len)
    address = live.build_wots_prf_addr(
        layer=p.d - 1, tree=0, keypair=kp, chain=chain, hash_=0, mode="sha2")
    return live.Case(live.KIND_WOTS, p.d - 1, 0, kp, chain, 0, 0, 0, address)


def capture_condition_dir(root: str | os.PathLike, p: str, opt: str) -> Path:
    opt_label, _ = batch.normalize_compiler_opt(opt)
    return native_path(root) / f"SLH_DSA_{live.normalize_param_set(p)}_sha2_keygen_prf_sequence" / opt_label


def _validate_completed(prefix: Path, expected_rows: int, points: int, param: str) -> bool:
    """True only if full output, metadata, address ordering, and shapes agree."""
    try:
        if not all(Path(str(prefix) + suffix).is_file() for suffix in REQUIRED_CAPTURE_SUFFIXES):
            return False
        t = np.load(str(prefix) + "_traces_random.npy", mmap_mode="r")
        a = np.load(str(prefix) + "_addrs_random.npy", mmap_mode="r")
        m = np.load(str(prefix) + "_params_random.npy", mmap_mode="r")
        cfg = read_json(Path(str(prefix) + "_capture_config.json"))
        seq = read_json(Path(str(prefix) + "_keygen_sequence.json"))
        if (t.shape != (expected_rows, points) or a.shape != (expected_rows, 32)
                or m.shape != (expected_rows, len(live.META_COLUMNS))
                or a.dtype != np.uint8 or t.dtype != np.float32
                or m.dtype != np.uint64 or cfg.get("parameter_set") != param
                or seq.get("format") != VERSION or seq.get("calls") != expected_rows):
            return False
        # Verify every address against the exact deterministic keygen sequence.
        for row in range(expected_rows):
            if not np.array_equal(a[row], np.frombuffer(keygen_case(param, row).addr, np.uint8)):
                return False
        return True
    except (ValueError, KeyError, OSError, TypeError):
        return False


def _capture_spec(
    p: str, opt: str, platform: str, seed_id: int,
    sk_seed: bytes, pk_seed: bytes, samples: int, firmware_sha256: str,
) -> dict:
    return {
        "version": VERSION,
        "parameter_set": p, "compiler_opt": opt, "platform": platform,
        "seed_id": int(seed_id), "sk_seed_sha256": sha256(sk_seed),
        "pk_seed_sha256": sha256(pk_seed), "pk_seed_hex": pk_seed.hex(),
        "samples": int(samples), "firmware_sha256": str(firmware_sha256),
        "sequence": params_info(p),
    }


def _capture_spec_fingerprint(spec: Mapping[str, Any]) -> str:
    return sha256(json.dumps(dict(spec), sort_keys=True).encode("utf-8"))


def _check_no_orphan_files(prefix: Path) -> None:
    for suffix in REQUIRED_CAPTURE_SUFFIXES:
        if Path(str(prefix) + suffix).exists():
            raise FileExistsError(
                f"Capture arrays exist but no valid per-seed manifest was found; "
                f"refusing overwrite: {prefix}. Back up or select a new output root.")


def existing_seed_status(seed_dir: Path, p: str, opt: str, seed_id: int, seed: bytes,
                         pk_seed: bytes, platform: str, firmware_sha256: str | None = None):
    """Return saved progress or None. No writes. Compares completed files on disk."""
    progress_path = seed_dir / "keygen_capture_manifest.json"
    if not progress_path.is_file():
        return None
    row = read_json(progress_path)
    spec = row.get("capture_spec")
    if not isinstance(spec, dict):
        raise ValueError(f"Invalid capture manifest (no capture_spec): {progress_path}")
    for name, expected in (
        ("parameter_set", p), ("compiler_opt", opt), ("platform", platform),
        ("seed_id", int(seed_id)), ("sk_seed_sha256", sha256(seed)),
        ("pk_seed_sha256", sha256(pk_seed)),
    ):
        if spec.get(name) != expected:
            raise ValueError(f"Existing capture mismatch {name}: {progress_path}; "
                             f"saved={spec.get(name)!r}, requested={expected!r}")
    if firmware_sha256 is not None and spec.get("firmware_sha256") != firmware_sha256:
        raise ValueError(f"Firmware SHA-256 mismatch: {progress_path}. Refusing to reuse mixed builds.")
    return row


def capture_one_seed(
    scope, target, seed_dir: str | os.PathLike, *,
    parameter_set: str, compiler_opt: str, platform: str,
    seed_id: int, sk_seed: bytes, pk_seed: bytes,
    sk_prf: Optional[bytes] = None,
    firmware_sha256: str = "not-recorded",
    verify_result: bool = True, verify_first_n: int = 5,
    timeout: int = 250, verify_addr_each_time: bool = False,
    flush_every_leaves: int = 1, resume: bool = True,
) -> dict:
    """Stream WOTS_PRF traces and resume safely from a *committed leaf boundary*.

    Individual PRFs are measured, not the whole keygen. A completed capture is
    returned without touching its arrays. An in-progress capture may only reuse
    the same seed, PK.seed, build, platform, trace length and public sequence.
    """
    p = live.normalize_param_set(parameter_set)
    opt, _ = batch.normalize_compiler_opt(compiler_opt)
    live.select_parameter_set(p)
    spec = params_info(p)
    sk_seed, pk_seed = bytes(sk_seed), bytes(pk_seed)
    if len(sk_seed) != spec["n"] or len(pk_seed) != spec["n"]:
        raise ValueError(f"{p}: seed length must be {spec['n']} bytes")
    prf = None if sk_prf is None else bytes(sk_prf)
    if prf is not None and len(prf) != spec["n"]:
        raise ValueError("SK.prf length mismatch")
    seed_dir = native_path(seed_dir)
    seed_dir.mkdir(parents=True, exist_ok=True)
    prefix = seed_dir / "capture"
    manifest_path = seed_dir / "keygen_capture_manifest.json"
    total, n_chain = spec["wots_prf_calls"], spec["wots_len"]
    current_samples = int(scope.adc.samples)
    if current_samples < 2:
        raise ValueError("scope.adc.samples must be at least 2")
    if flush_every_leaves < 1:
        raise ValueError("flush_every_leaves must be positive")

    old = existing_seed_status(seed_dir, p, opt, seed_id, sk_seed, pk_seed,
                               platform, firmware_sha256)
    if old is not None:
        if not resume:
            raise FileExistsError(f"Existing capture found; resume=False forbids overwrite: {seed_dir}")
        saved = old["capture_spec"]
        points = int(saved["samples"])
        if old.get("status") == "completed":
            if not _validate_completed(prefix, total, points, p):
                raise ValueError(f"Completed capture files failed validation: {seed_dir}")
            print(f"[KEYGEN REUSE] {p}/{opt}/seed_{seed_id:03d}, {total:,} PRFs")
            return old
        if old.get("status") != "in_progress":
            raise ValueError(f"Unknown capture status in {manifest_path}")
        committed = int(old.get("committed_rows", 0))
        if not 0 <= committed <= total or committed % n_chain != 0:
            raise ValueError("Corrupt committed_rows: expected a complete WOTS leaf boundary")
        for suffix in REQUIRED_CAPTURE_SUFFIXES:
            if not Path(str(prefix) + suffix).is_file():
                raise FileNotFoundError(f"Incomplete partial capture; refusing unsafe resume: {prefix}{suffix}")
        # Require exact array sizes and all *committed* address rows.
        waves = np.load(str(prefix) + "_traces_random.npy", mmap_mode="r+")
        addrs = np.load(str(prefix) + "_addrs_random.npy", mmap_mode="r+")
        metas = np.load(str(prefix) + "_params_random.npy", mmap_mode="r+")
        if (waves.shape != (total, points) or addrs.shape != (total, 32)
                or metas.shape != (total, len(live.META_COLUMNS))):
            raise ValueError("Partial capture shapes differ from committed manifest")
        for row in range(committed):
            if not np.array_equal(addrs[row], np.frombuffer(keygen_case(p, row).addr, np.uint8)):
                raise ValueError(f"Committed address mismatches expected sequence at row={row}")
        if int(scope.adc.samples) != points:
            print(f"[KEYGEN RESUME] restoring ADC samples to existing {points} (was {scope.adc.samples})")
            scope.adc.samples = points
        current = dict(old)
    else:
        _check_no_orphan_files(prefix)
        points = current_samples
        estimated_bytes = total * (points * np.dtype(np.float32).itemsize
                                   + 32 * np.dtype(np.uint8).itemsize
                                   + len(live.META_COLUMNS) * np.dtype(np.uint64).itemsize)
        free_bytes = shutil.disk_usage(seed_dir).free
        if estimated_bytes > 0.90 * free_bytes:
            raise OSError(
                f"Insufficient space for keygen PRF capture ({p}/seed_{seed_id:03d}): "
                f"approximately {estimated_bytes / (1024**3):.2f} GiB needed; "
                f"{free_bytes / (1024**3):.2f} GiB free. Change output disk or ADC samples.")
        spec_capture = _capture_spec(p, opt, platform, seed_id, sk_seed, pk_seed,
                                     points, firmware_sha256)
        current = {
            "format": VERSION, "status": "in_progress", "capture_spec": spec_capture,
            "capture_fingerprint": _capture_spec_fingerprint(spec_capture),
            "capture_prefix": str(prefix), "committed_rows": 0,
            "expected_rows": total, "expected_keypairs": spec["wots_keypairs"],
            "estimated_capture_bytes": int(estimated_bytes),
            "created_at": datetime.now().isoformat(timespec="seconds"),
        }
        # Mark in_progress BEFORE opening any (potentially truncating) memmaps.
        write_json_atomic(manifest_path, current)
        waves = open_memmap(str(prefix) + "_traces_random.npy", mode="w+",
                            dtype=np.float32, shape=(total, points))
        addrs = open_memmap(str(prefix) + "_addrs_random.npy", mode="w+",
                            dtype=np.uint8, shape=(total, 32))
        metas = open_memmap(str(prefix) + "_params_random.npy", mode="w+",
                            dtype=np.uint64, shape=(total, len(live.META_COLUMNS)))
        np.save(str(prefix) + "_meta_columns.npy", live.META_COLUMNS)
        write_json_atomic(Path(str(prefix) + "_capture_config.json"), {
            "parameter_set": p, "n": spec["n"], "mode": "sha2",
            "keygen_sequence": True, "capture_format": VERSION,
            "pk_seed_hex": pk_seed.hex(),
            "build": {
                "compiler_optimization": opt, "platform": platform,
                "seed_id": int(seed_id), "sk_seed_sha256": sha256(sk_seed),
                "firmware_sha256": firmware_sha256,
                **live.get_capture_build_metadata(),
            },
        })
        write_json_atomic(Path(str(prefix) + "_keygen_sequence.json"), {
            "format": VERSION, **spec, "calls": total,
            "address_order": "keypair ascending; within each keypair chain ascending",
            "adrs_c_bytes": 22, "note": "One isolated PRF waveform per logical keygen invocation",
        })
        committed = 0

    # Device state MUST be re-established for each secret-seed capture/resume.
    live.reset_and_configure(scope, target, mode="sha2", pk_seed=pk_seed,
                             sk_seed=sk_seed, sk_prf=prf, timeout=timeout)
    print(f"[KEYGEN CAPTURE] {p}/{opt}/seed_{seed_id:03d}: "
          f"{committed:,}/{total:,} already committed, samples={points}", flush=True)
    started = time.perf_counter()
    try:
        for row in range(committed, total):
            case = keygen_case(p, row)
            live.send_addr(target, case.addr, timeout=timeout,
                           verify=bool(verify_addr_each_time))
            result, wave = live.capture_trace(scope, target, timeout=timeout)
            if verify_result and (int(verify_first_n) < 0 or row < int(verify_first_n)):
                expected = live.reference_digest("sha2", pk_seed, sk_seed, case.addr)
                if result != expected:
                    raise RuntimeError(f"PRF output mismatch at call {row}: "
                                       f"got {result.hex()} expected {expected.hex()}")
            waveform = np.asarray(wave, dtype=np.float32).reshape(-1)
            if waveform.size < points:
                raise ValueError(f"row {row}: captured {waveform.size} points; need {points}")
            waves[row] = waveform[:points]
            addrs[row] = np.frombuffer(case.addr, np.uint8)
            metas[row] = np.asarray(case.meta_row(is_fixed=0, mode=live.MODE_SHA2), np.uint64)
            # Only whole, flushed WOTS keypairs become reusable checkpoints.
            if ((row + 1) % n_chain == 0 and
                    (((row + 1) // n_chain) % int(flush_every_leaves) == 0 or row + 1 == total)):
                for a in (waves, addrs, metas):
                    a.flush()
                current["committed_rows"] = int(row + 1)
                current["committed_keypairs"] = int((row + 1) // n_chain)
                current["last_committed_at"] = datetime.now().isoformat(timespec="seconds")
                current.pop("last_error", None)
                write_json_atomic(manifest_path, current)
                print(f"  leaf {(row+1)//n_chain}/{spec['wots_keypairs']} "
                      f"({row+1:,}/{total:,} PRFs)", flush=True)
    except BaseException as exc:
        current["last_error"] = f"{type(exc).__name__}: {exc}"
        write_json_atomic(manifest_path, current)
        raise
    finally:
        for a in (waves, addrs, metas):
            a.flush()

    current["status"] = "completed"
    current["committed_rows"] = total
    current["committed_keypairs"] = spec["wots_keypairs"]
    current["elapsed_capture_seconds"] = round(time.perf_counter() - started, 3)
    current["finished_at"] = datetime.now().isoformat(timespec="seconds")
    current.pop("last_error", None)
    write_json_atomic(manifest_path, current)
    return current


def _firmware_hash(firmware_dir: Path, platform: str) -> str:
    hex_path = firmware_dir / f"simpleserial-SLH-DSA-{platform}.hex"
    if not hex_path.is_file():
        raise FileNotFoundError(f"Firmware HEX missing: {hex_path}")
    h = hashlib.sha256()
    with hex_path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run_keygen_capture_batch(
    scope, target, *,
    firmware_dir: str | os.PathLike,
    results_base_dir: str | os.PathLike,
    param_sets: Sequence[str] = ALL_PARAMS,
    compiler_opts: Sequence[str] = ("Os",),
    num_secret_seeds: int = 3,
    secret_seed_master: int = 424242,
    platform: str = "CW308_STM32F3",
    crypto_target: str = "MBEDTLS",
    build_firmware: bool = True,
    program_target: bool = True,
    max_samples: int = 131124,
    auto_calibrate_points: bool = True,
    number_of_points: int = -1,
    calibration_margin: int = 0,
    calibration_kind: str = "wots",
    timeout: int = 250,
    verify_result: bool = True,
    verify_first_n: int = 5,
    verify_addr_each_time: bool = False,
    flush_every_leaves: int = 1,
    resume: bool = True,
    continue_on_error: bool = False,
    shared_seed_source_base: str | os.PathLike | None = None,
) -> dict:
    """Rebuild/program/calibrate per parameter + GCC opt; capture all seeds.

    If shared_seed_source_base is set, reads the existing *signing* secret-seed
    manifest per parameter and uses those exact SK.seed values. No modifications
    are made to that source; local manifest is written separately.
    """
    import chipwhisperer as cw
    fwdir = native_path(firmware_dir)
    out = native_path(results_base_dir)
    out.mkdir(parents=True, exist_ok=True)
    count = int(num_secret_seeds)
    if count < 1:
        raise ValueError("num_secret_seeds must be >= 1")
    report: Dict[str, Any] = {"version": VERSION, "conditions": []}
    for raw_param in param_sets:
        p = live.normalize_param_set(raw_param)
        live.select_parameter_set(p)
        parameter_root = out / f"SLH_DSA_{p}_sha2_keygen_prf_sequence"
        parameter_root.mkdir(parents=True, exist_ok=True)
        if shared_seed_source_base is not None:
            source_file = native_path(shared_seed_source_base) / f"SLH_DSA_{p}_sha2_message_signature_sequence" / "shared_secret_seeds.json"
            if not source_file.is_file():
                raise FileNotFoundError(f"Signing seed manifest absent: {source_file}")
            origin = read_json(source_file)
            if (origin.get("parameter_set") != p or int(origin.get("n", -1)) != live.SLH_N):
                raise ValueError(f"Signing seed manifest mismatch: {source_file}")
            src_pool = {int(r.get("seed_id", i)): bytes.fromhex(r["sk_seed_hex"])
                        for i, r in enumerate(origin.get("seeds", []))}
            if not all(i in src_pool for i in range(count)):
                raise ValueError(f"Signing seed manifest has fewer than {count} seed IDs: {source_file}")
            sk_pool = [src_pool[i] for i in range(count)]
            if len(set(sk_pool)) != count or any(len(s) != live.SLH_N for s in sk_pool):
                raise ValueError("Signing seed pool has invalid lengths/duplicates")
            local_manifest = parameter_root / "shared_secret_seeds.json"
            new_pool = {
                "format": "slh-dsa-keygen-imported-secret-seeds-v1",
                "parameter_set": p, "n": live.SLH_N,
                "num_seeds": count, "source_manifest": str(source_file),
                "seeds": [dict(seed_id=i, sk_seed_hex=s.hex(), sha256=sha256(s))
                          for i, s in enumerate(sk_pool)],
            }
            if local_manifest.exists():
                older = read_json(local_manifest)
                for i in range(count):
                    matches = [r for z, r in enumerate(older.get("seeds", []))
                               if int(r.get("seed_id", z)) == i]
                    if len(matches) != 1 or bytes.fromhex(matches[0]["sk_seed_hex"]) != sk_pool[i]:
                        raise ValueError(f"Local and imported secret pools disagree: {local_manifest}")
            else:
                write_json_atomic(local_manifest, new_pool)
        else:
            sk_pool, _ = live.load_or_create_secret_seed_manifest(
                parameter_root / "shared_secret_seeds.json", num_seeds=count,
                master_seed=int(secret_seed_master), parameter_set=p, overwrite=False)
        pk_seed, sk_prf = bytes(live.PUB_SEED), bytes(live.SK_PRF)

        for raw_opt in compiler_opts:
            opt, opt_make = batch.normalize_compiler_opt(raw_opt)
            condition_dir = capture_condition_dir(out, p, opt)
            condition_dir.mkdir(parents=True, exist_ok=True)
            try:
                # Do not rebuild/program completed conditions unnecessarily.
                done_preflight = True
                for sid, secret in enumerate(sk_pool):
                    seed_dir = condition_dir / f"seed_{sid:03d}"
                    try:
                        prior = existing_seed_status(seed_dir, p, opt, sid, secret,
                                                     pk_seed, platform)
                        if prior is None or prior.get("status") != "completed" or not _validate_completed(
                            seed_dir / "capture", params_info(p)["wots_prf_calls"],
                            int(prior["capture_spec"]["samples"]), p):
                            done_preflight = False
                            break
                    except (ValueError, KeyError):
                        raise
                if done_preflight and resume:
                    print(f"[KEYGEN SKIP CONDITION] {p}/{opt}: all {count} seeds complete")
                    report["conditions"].append({"parameter_set": p, "compiler_opt": opt,
                                                  "status": "reused", "seed_count": count})
                    continue
                batch._write_parameter_header(live=live, param_set=p, firmware_dir=fwdir)
                live.set_capture_build_metadata(
                    parameter_set=p, hash_mode="sha2", compiler_optimization=opt,
                    make_opt=opt_make, platform=platform, crypto_target=crypto_target,
                    capture_mode="keygen_wots_prf_sequence", num_secret_seeds=count,
                    secret_seed_master=int(secret_seed_master))
                if build_firmware:
                    batch._build_firmware(
                        live=live, firmware_dir=fwdir, result_dir=condition_dir,
                        param_set=p, hash_mode="sha2", platform=platform,
                        crypto_target=crypto_target, compiler_opt=opt)
                fw_hash = _firmware_hash(fwdir, platform)
                if program_target:
                    cw.program_target(scope, batch._programmer_for_platform(cw, platform),
                                      str(fwdir / f"simpleserial-SLH-DSA-{platform}.hex"))

                initial = int(number_of_points) if int(number_of_points) > 0 else int(max_samples)
                scope.adc.samples = min(initial, int(max_samples))
                live.reset_and_configure(scope, target, mode="sha2", pk_seed=pk_seed,
                                         sk_seed=sk_pool[0], sk_prf=sk_prf, timeout=timeout)
                calibration = live.calibrate_and_set_samples(
                    scope, target, calibration_kind=calibration_kind, mode="sha2",
                    pk_seed=pk_seed, sk_seed=sk_pool[0], sk_prf=sk_prf,
                    timeout=timeout, auto_calibrate=bool(auto_calibrate_points),
                    margin=int(calibration_margin), max_samples=int(max_samples),
                    manual_samples=int(number_of_points), verify_addr=True)
                print(f"[KEYGEN] {p}/{opt}: {params_info(p)['wots_prf_calls']:,} "
                      f"PRFs/seed, ADC points={int(scope.adc.samples)}")
                for sid, secret in enumerate(sk_pool):
                    capture_one_seed(
                        scope, target, condition_dir / f"seed_{sid:03d}",
                        parameter_set=p, compiler_opt=opt, platform=platform,
                        seed_id=sid, sk_seed=secret, pk_seed=pk_seed, sk_prf=sk_prf,
                        firmware_sha256=fw_hash, verify_result=verify_result,
                        verify_first_n=verify_first_n, timeout=timeout,
                        verify_addr_each_time=verify_addr_each_time,
                        flush_every_leaves=flush_every_leaves, resume=resume)
                report["conditions"].append({"parameter_set": p, "compiler_opt": opt,
                                              "status": "completed", "seed_count": count,
                                              "adc_samples": int(scope.adc.samples),
                                              "firmware_sha256": fw_hash})
            except Exception as exc:
                report["conditions"].append({"parameter_set": p, "compiler_opt": opt,
                                              "status": "failed", "error": f"{type(exc).__name__}: {exc}"})
                write_json_atomic(out / "keygen_batch_summary.json", report)
                if not continue_on_error:
                    raise
            write_json_atomic(out / "keygen_batch_summary.json", report)
    return report


def _parser() -> argparse.ArgumentParser:
    a = argparse.ArgumentParser(description=__doc__)
    a.add_argument("--firmware-dir", required=False, default="")
    a.add_argument("--base", default="./SLH_DSA_Keygen_Captures")
    a.add_argument("--params", default=",".join(ALL_PARAMS))
    a.add_argument("--opts", default="Os")
    a.add_argument("--num-seeds", type=int, default=3)
    a.add_argument("--master-seed", type=int, default=424242)
    a.add_argument("--seed-source-base", default="")
    a.add_argument("--platform", default="CW308_STM32F3")
    a.add_argument("--crypto-target", default="MBEDTLS")
    a.add_argument("--gain", type=float, default=15.0)
    a.add_argument("--max-samples", type=int, default=131124)
    a.add_argument("--manual-samples", type=int, default=-1)
    a.add_argument("--margin", type=int, default=0)
    a.add_argument("--timeout", type=int, default=250)
    a.add_argument("--verify-all", action="store_true")
    a.add_argument("--flush-leaves", type=int, default=1)
    a.add_argument("--skip-build", action="store_true")
    a.add_argument("--skip-program", action="store_true")
    a.add_argument("--dry-run", action="store_true")
    return a


def main(argv: Optional[Sequence[str]] = None):
    args = _parser().parse_args(argv)
    params = [live.normalize_param_set(x.strip()) for x in args.params.split(",") if x.strip()]
    opts = [batch.normalize_compiler_opt(x.strip())[0] for x in args.opts.split(",") if x.strip()]
    plan = preview_keygen_plan(params, opts, args.num_seeds, args.manual_samples if args.manual_samples > 0 else None)
    for item in plan:
        print(f"{item['parameter_set']:4s}/{item['compiler_opt']:2s}: "
              f"{item['wots_keypairs']:,} keypairs x {item['wots_len']} chains "
              f"= {item['wots_prf_calls']:,} PRFs/seed, "
              f"{item['total_prf_calls']:,} PRFs total")
    if args.dry_run:
        return {"dry_run": True, "plan": plan}
    if not args.firmware_dir:
        raise ValueError("--firmware-dir is required unless --dry-run")
    import chipwhisperer as cw
    scope = cw.scope()
    target = None
    try:
        scope.default_setup()
        scope.gain.db = float(args.gain)
        scope.adc.samples = int(args.max_samples)
        scope.adc.presamples = 0
        target = cw.target(scope, cw.targets.SimpleSerial)
        return run_keygen_capture_batch(
            scope, target, firmware_dir=args.firmware_dir, results_base_dir=args.base,
            param_sets=params, compiler_opts=opts, num_secret_seeds=args.num_seeds,
            secret_seed_master=args.master_seed, platform=args.platform,
            crypto_target=args.crypto_target, build_firmware=not args.skip_build,
            program_target=not args.skip_program,
            max_samples=args.max_samples, number_of_points=args.manual_samples,
            auto_calibrate_points=args.manual_samples < 1,
            calibration_margin=args.margin, timeout=args.timeout,
            verify_first_n=-1 if args.verify_all else 5,
            flush_every_leaves=args.flush_leaves,
            shared_seed_source_base=args.seed_source_base or None)
    finally:
        if target is not None:
            try: target.dis()
            except Exception: pass
        try: scope.dis()
        except Exception: pass


if __name__ == "__main__":
    main()
