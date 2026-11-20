"""
Automatic all-parameter SLH-DSA SHA2 capture using random-message-derived
FIPS 205 signing paths.

For each selected parameter set / compiler option:
  1. select/build/program the firmware,
  2. load one reproducible SK.seed,
  3. derive/cache PK.root from that SK.seed and PK.seed,
  4. generate a random message for every requested signature,
  5. evaluate PRF_msg and H_msg on the host,
  6. extract md, idx_tree, idx_leaf and FORS indices,
  7. capture the WOTS_PRF / FORS_PRF calls in FIPS 205 signing order.

The user controls the number of signatures independently for each parameter set.
"""

from __future__ import annotations

import json
import math
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence

import random_address_capture as basebatch
import signature_prf_sequence as seqcap
import signature_message_path as msgcap

MESSAGE_SIGNATURE_BATCH_VERSION = "2026-09-17-random-message-fips205-all-params-v3"
DEFAULT_PARAM_SETS = ("128f", "128s", "192f", "192s", "256f", "256s")
DEFAULT_COMPILER_OPTS = ("Os",)


def _fmt_seconds(seconds: Optional[float]) -> str:
    if seconds is None or not math.isfinite(float(seconds)) or float(seconds) < 0:
        return "estimating"
    seconds = int(round(float(seconds)))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days:
        return f"{days}d {hours:02d}:{minutes:02d}:{secs:02d}"
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def _signatures_for_param(value: Mapping[str, int] | int, param: str) -> int:
    if isinstance(value, int):
        return int(value)
    if param not in value:
        raise KeyError(f"signatures_per_param_set has no entry for {param}")
    return int(value[param])


def signature_condition_output_dir(
    results_base_dir: str | os.PathLike,
    *,
    param_set: str,
    hash_mode: str,
    compiler_opt: str,
) -> Path:
    return (
        Path(str(results_base_dir))
        / f"SLH_DSA_{param_set}_{hash_mode}_message_signature_sequence"
        / compiler_opt
    )


def preview_capture_plan(
    *,
    live,
    param_sets: Sequence[str] = DEFAULT_PARAM_SETS,
    compiler_opts: Sequence[str] = DEFAULT_COMPILER_OPTS,
    signatures_per_param_set: Mapping[str, int] | int = 1,
    capture_phases: Optional[Sequence[str]] = None,
) -> list[Dict[str, Any]]:
    params = [live.normalize_param_set(p) for p in param_sets]
    opts = [basebatch.normalize_compiler_opt(o)[0] for o in compiler_opts]
    phases = seqcap._normalize_phases(capture_phases)
    rows: list[Dict[str, Any]] = []
    for p in params:
        counts = seqcap.signature_prf_call_counts(p)
        n_sig = _signatures_for_param(signatures_per_param_set, p)
        per_sig = sum(int(counts[phase]) for phase in phases)
        for opt in opts:
            rows.append({
                "parameter_set": p,
                "compiler_opt": opt,
                "signatures": int(n_sig),
                "calls_per_signature": int(per_sig),
                "full_calls_per_signature": int(counts["total"]),
                "total_captured_calls": int(n_sig * per_sig),
                **{f"calls_{phase}": int(counts[phase]) for phase in seqcap.ALL_PHASES},
            })
    return rows


def _sequence_manifest_complete(
    seed_dir: Path,
    *,
    parameter_set: str,
    num_signatures: int,
    message_seed: int,
    message_length: int,
    signing_variant: str,
    addrnd_seed: int,
    context: bytes,
    capture_phases: Sequence[str],
    pk_root: bytes,
) -> bool:
    path = seed_dir / "signature_sequence_capture_manifest.json"
    if not path.is_file():
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("format") != "slh-dsa-fips205-random-message-signing-prf-capture-v3":
            return False
        if data.get("helper_version") != msgcap.MESSAGE_CAPTURE_HELPER_VERSION:
            return False
        expected = {
            "parameter_set": str(parameter_set),
            "message_seed": int(message_seed),
            "message_length": int(message_length),
            "signing_variant": str(signing_variant).strip().lower(),
            "addrnd_seed": int(addrnd_seed),
            "context_hex": bytes(context).hex(),
            "pk_root_hex": bytes(pk_root).hex(),
            "capture_phases": list(capture_phases),
        }
        for k, v in expected.items():
            if data.get(k) != v:
                return False
        rows = {int(r["signature_id"]): r for r in data.get("completed", [])}
        return all(
            sid in rows and str(rows[sid].get("status", "")).startswith("completed")
            for sid in range(int(num_signatures))
        )
    except Exception:
        return False


def run_all_parameter_random_message_signature_captures(
    scope,
    target,
    live,
    *,
    firmware_dir: str | os.PathLike,
    results_base_dir: str | os.PathLike,
    platform: str = "CW308_STM32F3",
    crypto_target: str = "MBEDTLS",
    hash_mode: str = "sha2",
    param_sets: Sequence[str] = DEFAULT_PARAM_SETS,
    compiler_opts: Sequence[str] = DEFAULT_COMPILER_OPTS,
    signatures_per_param_set: Mapping[str, int] | int = 1,
    capture_phases: Optional[Sequence[str]] = None,
    # Message/path generation
    message_seed: int = 20260917,
    message_length: int = 32,
    signing_variant: str = "hedged",
    addrnd_seed: int = 20260918,
    context: bytes = b"",
    # Key selection
    secret_seed_master: int = 424242,
    secret_seed_id: int = 0,
    regenerate_shared_seed_manifest: bool = False,
    force_recompute_pk_root: bool = False,
    # Build/program/capture
    build_firmware: bool = True,
    program_target: bool = True,
    calibration_kind: str = "wots",
    number_of_points: int = -1,
    max_samples: int = 131124,
    auto_calibrate_points: bool = True,
    calibration_margin: int = 0,
    timeout: int = 250,
    verify_addr_each_time: bool = False,
    verify_result: bool = True,
    verify_first_n: int = 5,
    flush_every: int = 1000,
    resume: bool = True,
    continue_on_error: bool = False,
    progress_json_name: str = "random_message_signature_capture_progress.json",
) -> Dict[str, Any]:
    import chipwhisperer as cw

    if str(hash_mode).lower() != "sha2":
        raise ValueError("this batch is for the six SHA2 parameter sets")
    if int(message_length) <= 0:
        raise ValueError("message_length must be positive")
    if len(bytes(context)) > 255:
        raise ValueError("context must be at most 255 bytes")

    firmware_dir = Path(firmware_dir)
    results_base_dir = Path(str(results_base_dir))
    results_base_dir.mkdir(parents=True, exist_ok=True)
    for required in (
        firmware_dir,
        firmware_dir / "slh_dsa_prf_target.c",
        firmware_dir / "Makefile",
    ):
        if not required.exists():
            raise FileNotFoundError(str(required))

    params = [live.normalize_param_set(p) for p in param_sets]
    opts = [basebatch.normalize_compiler_opt(o)[0] for o in compiler_opts]
    phases = seqcap._normalize_phases(capture_phases)

    plan = preview_capture_plan(
        live=live,
        param_sets=params,
        compiler_opts=opts,
        signatures_per_param_set=signatures_per_param_set,
        capture_phases=phases,
    )
    total_calls = sum(int(row["total_captured_calls"]) for row in plan)

    progress_path = results_base_dir / progress_json_name
    state: Dict[str, Any] = {
        "format": "slh-dsa-random-message-signature-auto-capture-v3",
        "batch_version": MESSAGE_SIGNATURE_BATCH_VERSION,
        "param_sets": params,
        "compiler_opts": opts,
        "hash_mode": hash_mode,
        "capture_phases": list(phases),
        "message_seed": int(message_seed),
        "message_length": int(message_length),
        "signing_variant": str(signing_variant).strip().lower(),
        "addrnd_seed": int(addrnd_seed),
        "context_hex": bytes(context).hex(),
        "secret_seed_id": int(secret_seed_id),
        "conditions": {},
    }
    if bool(resume) and progress_path.is_file():
        try:
            old = json.loads(progress_path.read_text(encoding="utf-8"))
            if old.get("format") == state["format"]:
                state["conditions"] = old.get("conditions", {})
        except Exception:
            pass

    def save_state() -> None:
        tmp = progress_path.with_suffix(progress_path.suffix + ".tmp")
        tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, progress_path)

    print("===== SLH-DSA random-message FIPS 205 PRF capture =====")
    print("parameter sets  :", ", ".join(params))
    print("compiler opts   :", ", ".join(opts))
    print("phases          :", ", ".join(phases))
    print("message bytes   :", int(message_length))
    print("message seed    :", int(message_seed))
    print("signing variant :", str(signing_variant).strip().lower())
    print("addrnd seed     :", int(addrnd_seed))
    print("planned traces  :", f"{total_calls:,}")
    print("progress file   :", progress_path)
    print()

    total_conditions = len(params) * len(opts)
    condition_index = 0

    for p in params:
        n_signatures = _signatures_for_param(signatures_per_param_set, p)
        if n_signatures <= 0:
            print(f"[SKIP] {p}: requested signatures={n_signatures}")
            continue

        # Select parameter and key material once. The same public root/path
        # inputs are then reused across compiler options for a fair comparison.
        live.select_parameter_set(p)
        parameter_root = (
            results_base_dir / f"SLH_DSA_{p}_{hash_mode}_message_signature_sequence"
        )
        parameter_root.mkdir(parents=True, exist_ok=True)
        seed_manifest = parameter_root / "shared_secret_seeds.json"
        seeds, _ = live.load_or_create_secret_seed_manifest(
            seed_manifest,
            num_seeds=max(int(secret_seed_id) + 1, 1),
            master_seed=int(secret_seed_master),
            parameter_set=p,
            overwrite=bool(regenerate_shared_seed_manifest),
        )
        sk_seed = bytes(seeds[int(secret_seed_id)])
        pk_seed = bytes(live.PUB_SEED)
        sk_prf = bytes(live.SK_PRF)

        root_cache = parameter_root / f"derived_pk_root_seed_{int(secret_seed_id):03d}.json"
        print(f"[{p}] deriving/loading PK.root for message-path selection...")
        pk_root, root_info = msgcap.load_or_derive_pk_root_sha2(
            root_cache,
            sk_seed=sk_seed,
            pk_seed=pk_seed,
            force_recompute=bool(force_recompute_pk_root),
        )
        print(
            f"[{p}] PK.root = {pk_root.hex()} "
            f"({'cache' if root_info.get('cache_hit') else 'computed'})"
        )

        for opt in opts:
            condition_index += 1
            key = f"{p}|{opt}"
            out_dir = signature_condition_output_dir(
                results_base_dir,
                param_set=p,
                hash_mode=hash_mode,
                compiler_opt=opt,
            )
            out_dir.mkdir(parents=True, exist_ok=True)
            seed_dir = out_dir / f"seed_{int(secret_seed_id):03d}"

            if bool(resume) and _sequence_manifest_complete(
                seed_dir,
                parameter_set=p,
                num_signatures=n_signatures,
                message_seed=message_seed,
                message_length=message_length,
                signing_variant=signing_variant,
                addrnd_seed=addrnd_seed,
                context=bytes(context),
                capture_phases=phases,
                pk_root=pk_root,
            ):
                state["conditions"][key] = {
                    "parameter_set": p,
                    "compiler_opt": opt,
                    "num_signatures": int(n_signatures),
                    "status": "completed",
                    "completion_source": "disk-discovery",
                    "output_dir": str(out_dir),
                }
                save_state()
                print(f"[SKIP {condition_index:02d}/{total_conditions}] {p}/{opt}: complete")
                continue

            started = time.perf_counter()
            print(
                f"[RUN  {condition_index:02d}/{total_conditions}] "
                f"{p}/{opt} | signatures={n_signatures}"
            )

            try:
                # Restore active parameter before every build/condition.
                live.select_parameter_set(p)
                basebatch._write_parameter_header(
                    live=live,
                    param_set=p,
                    firmware_dir=firmware_dir,
                )

                opt_label, make_opt = basebatch.normalize_compiler_opt(opt)
                live.set_capture_build_metadata(
                    compiler_optimization=opt_label,
                    make_opt=make_opt,
                    platform=platform,
                    crypto_target=crypto_target,
                    parameter_set=p,
                    hash_mode=hash_mode,
                    capture_mode="fips205_random_message_signing_prf_sequence",
                    num_signatures=int(n_signatures),
                    message_seed=int(message_seed),
                    message_length=int(message_length),
                    signing_variant=str(signing_variant).strip().lower(),
                    addrnd_seed=int(addrnd_seed),
                    context_hex=bytes(context).hex(),
                    capture_phases=",".join(phases),
                    shared_seed_manifest=str(seed_manifest),
                    secret_seed_id=int(secret_seed_id),
                    pk_root_hex=pk_root.hex(),
                    pk_root_cache=str(root_cache),
                )

                if build_firmware:
                    build_config = basebatch._build_firmware(
                        live=live,
                        firmware_dir=firmware_dir,
                        result_dir=out_dir,
                        param_set=p,
                        hash_mode=hash_mode,
                        platform=platform,
                        crypto_target=crypto_target,
                        compiler_opt=opt_label,
                    )
                    metadata = live.get_capture_build_metadata()
                    metadata.update({
                        "build_log": build_config["build_log"],
                        "build_config": build_config["build_config"],
                        "optimization_flag_seen_in_build_log": bool(
                            build_config["optimization_flag_seen_in_build_log"]
                        ),
                    })
                    live.set_capture_build_metadata(metadata)

                fw_path = firmware_dir / f"simpleserial-SLH-DSA-{platform}.hex"
                if not fw_path.is_file():
                    raise FileNotFoundError(f"Built firmware not found: {fw_path}")
                if program_target:
                    prog = basebatch._programmer_for_platform(cw, platform)
                    cw.program_target(scope, prog, str(fw_path))

                initial_samples = (
                    min(int(number_of_points), int(max_samples))
                    if int(number_of_points) > 0
                    else int(max_samples)
                )
                scope.adc.samples = int(initial_samples)

                live.reset_and_configure(
                    scope,
                    target,
                    mode=hash_mode,
                    pk_seed=pk_seed,
                    sk_seed=sk_seed,
                    sk_prf=sk_prf,
                    timeout=int(timeout),
                )
                calibration = live.calibrate_and_set_samples(
                    scope,
                    target,
                    calibration_kind=calibration_kind,
                    mode=hash_mode,
                    pk_seed=pk_seed,
                    sk_seed=sk_seed,
                    sk_prf=sk_prf,
                    timeout=int(timeout),
                    auto_calibrate=bool(auto_calibrate_points),
                    margin=int(calibration_margin),
                    max_samples=int(max_samples),
                    manual_samples=int(number_of_points),
                    verify_addr=True,
                )

                result = msgcap.capture_random_message_signing_prf_sequences(
                    scope,
                    target,
                    seed_dir,
                    platform=platform,
                    num_signatures=int(n_signatures),
                    sk_prf=sk_prf,
                    pk_seed=pk_seed,
                    pk_root=pk_root,
                    sk_seed=sk_seed,
                    message_seed=int(message_seed),
                    message_length=int(message_length),
                    signing_variant=signing_variant,
                    addrnd_seed=int(addrnd_seed),
                    context=bytes(context),
                    capture_phases=phases,
                    mode=hash_mode,
                    timeout=int(timeout),
                    verify_addr_each_time=bool(verify_addr_each_time),
                    verify_result=bool(verify_result),
                    verify_first_n=int(verify_first_n),
                    flush_every=int(flush_every),
                    resume=bool(resume),
                )

                duration = time.perf_counter() - started
                state["conditions"][key] = {
                    "parameter_set": p,
                    "compiler_opt": opt_label,
                    "num_signatures": int(n_signatures),
                    "status": "completed",
                    "completed_at": datetime.now().isoformat(timespec="seconds"),
                    "duration_s": float(duration),
                    "output_dir": str(out_dir),
                    "scope_samples": int(calibration["scope_samples"]),
                    "trig_count": int(calibration["trig_count"]),
                    "pk_root_hex": pk_root.hex(),
                    "sequence_manifest": str(seed_dir / "signature_sequence_capture_manifest.json"),
                    "completed_signatures": len(result.get("completed", [])),
                }
                save_state()
                print(f"[DONE] {p}/{opt_label} | {_fmt_seconds(duration)}")

            except Exception as exc:
                duration = time.perf_counter() - started
                state["conditions"][key] = {
                    "parameter_set": p,
                    "compiler_opt": opt,
                    "num_signatures": int(n_signatures),
                    "status": "failed",
                    "failed_at": datetime.now().isoformat(timespec="seconds"),
                    "duration_s": float(duration),
                    "output_dir": str(out_dir),
                    "error": f"{type(exc).__name__}: {exc}",
                }
                save_state()
                print(f"[FAIL] {p}/{opt}: {type(exc).__name__}: {exc}")
                if not continue_on_error:
                    raise

    print()
    print("===== Random-message signature capture finished =====")
    print("progress:", progress_path)
    return state

# =============================================================================
# 2026-11-10: Additive multi-secret-seed / per-signature resume
# =============================================================================

def preview_incremental_multiseed_capture_plan(
    *,
    live,
    results_base_dir: str | os.PathLike,
    param_sets: Sequence[str] = DEFAULT_PARAM_SETS,
    compiler_opts: Sequence[str] = DEFAULT_COMPILER_OPTS,
    signatures_per_param_set: Mapping[str, int] | int = 5,
    num_secret_seeds: int = 5,
    capture_phases: Optional[Sequence[str]] = None,
    hash_mode: str = "sha2",
) -> list[Dict[str, Any]]:
    """Read-only count preview (actual run strictly validates files/secret roots)."""
    from pathlib import Path
    if int(num_secret_seeds) <= 0:
        raise ValueError("num_secret_seeds must be positive")
    phases = seqcap._normalize_phases(capture_phases)
    rows = []
    for param in param_sets:
        p = live.normalize_param_set(param)
        target = _signatures_for_param(signatures_per_param_set, p)
        call_counts = seqcap.signature_prf_call_counts(p)
        per_signature = sum(call_counts[phase] for phase in phases)
        for compiler_opt in compiler_opts:
            opt = basebatch.normalize_compiler_opt(compiler_opt)[0]
            out = signature_condition_output_dir(
                results_base_dir, param_set=p, hash_mode=hash_mode, compiler_opt=opt
            )
            for seed_id in range(int(num_secret_seeds)):
                seed_dir = out / f"seed_{seed_id:03d}"
                complete_candidates = []
                partial_candidates = []
                for sid in range(max(0, target)):
                    sig_dir = seed_dir / f"signature_{sid:03d}"
                    prefix = sig_dir / "capture"
                    required = [
                        Path(str(prefix) + "_traces_random.npy"),
                        Path(str(prefix) + "_addrs_random.npy"),
                        Path(str(prefix) + "_params_random.npy"),
                        Path(str(prefix) + "_signature_sequence_meta.npy"),
                        Path(str(prefix) + "_signature_sequence.json"),
                    ]
                    if all(f.is_file() for f in required):
                        complete_candidates.append(sid)
                    elif sig_dir.exists() and any(sig_dir.iterdir()):
                        partial_candidates.append(sid)
                rows.append({
                    "parameter_set": p,
                    "compiler_opt": opt,
                    "seed_id": seed_id,
                    "requested_signatures": target,
                    "existing_candidates": len(complete_candidates),
                    "additional_if_valid": max(0, target - len(complete_candidates)),
                    "partial_or_incompatible_candidate_ids": partial_candidates,
                    "calls_per_signature": int(per_signature),
                    "additional_prf_calls_if_valid": (
                        max(0, target - len(complete_candidates)) * int(per_signature)
                    ),
                })
    return rows


def run_all_parameter_random_message_signature_captures_multiseed(
    scope,
    target,
    live,
    *,
    firmware_dir: str | os.PathLike,
    results_base_dir: str | os.PathLike,
    platform: str = "CW308_STM32F3",
    crypto_target: str = "MBEDTLS",
    hash_mode: str = "sha2",
    param_sets: Sequence[str] = DEFAULT_PARAM_SETS,
    compiler_opts: Sequence[str] = DEFAULT_COMPILER_OPTS,
    signatures_per_param_set: Mapping[str, int] | int = 5,
    num_secret_seeds: int = 5,
    capture_phases: Optional[Sequence[str]] = None,
    message_seed: int = 20260917,
    message_length: int = 32,
    signing_variant: str = "hedged",
    addrnd_seed: int = 20260918,
    context: bytes = b"",
    secret_seed_master: int = 424242,
    regenerate_shared_seed_manifest: bool = False,
    force_recompute_pk_root: bool = False,
    build_firmware: bool = True,
    program_target: bool = True,
    calibration_kind: str = "wots",
    number_of_points: int = -1,
    max_samples: int = 131124,
    auto_calibrate_points: bool = True,
    calibration_margin: int = 0,
    timeout: int = 250,
    verify_addr_each_time: bool = False,
    verify_result: bool = True,
    verify_first_n: int = 5,
    flush_every: int = 1000,
    resume: bool = True,
    continue_on_error: bool = False,
    progress_json_name: str = "random_message_signature_multiseed_capture_progress.json",
) -> Dict[str, Any]:
    """Capture only missing signature IDs for each SK.seed, without overwrites.

    For example, num_secret_seeds=5 and target=5: previously captured
    seed_000/signature_000..002 are reused; only 003 and 004 are measured.
    seed_001..004 receive signature_000..004. Original binary captures and
    the original single-seed batch-progress JSON remain unchanged.
    """
    import hashlib
    import shutil
    import chipwhisperer as cw

    if str(hash_mode).lower() != "sha2":
        raise ValueError("Only SHA2 signing-message sequences are supported")
    if not resume:
        raise ValueError("Append-safe multi-seed collection requires resume=True")
    if regenerate_shared_seed_manifest:
        raise ValueError(
            "Refusing regenerate_shared_seed_manifest=True: it may change existing keys"
        )
    if int(num_secret_seeds) <= 0:
        raise ValueError("num_secret_seeds must be positive")
    if int(message_length) <= 0 or len(bytes(context)) > 255:
        raise ValueError("Invalid message length or context")
    firmware_dir = Path(firmware_dir)
    results_base_dir = Path(str(results_base_dir))
    for required in (firmware_dir, firmware_dir / "slh_dsa_prf_target.c", firmware_dir / "Makefile"):
        if not required.exists():
            raise FileNotFoundError(required)
    results_base_dir.mkdir(parents=True, exist_ok=True)
    params = [live.normalize_param_set(p) for p in param_sets]
    opts = [basebatch.normalize_compiler_opt(o)[0] for o in compiler_opts]
    phases = seqcap._normalize_phases(capture_phases)
    progress_path = results_base_dir / progress_json_name
    if progress_path.name == "random_message_signature_capture_progress.json":
        raise ValueError("Use a different progress filename to preserve the old single-seed log")
    state = {
        "format": "slh-dsa-random-message-signature-multiseed-append-v1",
        "param_sets": params,
        "compiler_opts": opts,
        "num_secret_seeds": int(num_secret_seeds),
        "target_signatures_per_param_set": (
            int(signatures_per_param_set)
            if isinstance(signatures_per_param_set, int)
            else dict(signatures_per_param_set)
        ),
        "message_seed": int(message_seed),
        "message_length": int(message_length),
        "signing_variant": str(signing_variant).lower(),
        "addrnd_seed": int(addrnd_seed),
        "capture_phases": list(phases),
        "conditions": {},
    }
    if progress_path.exists():
        old = json.loads(progress_path.read_text(encoding="utf-8"))
        if old.get("format") != state["format"]:
            raise ValueError(f"Unrecognized existing multi-seed progress file: {progress_path}")
        state["conditions"] = old.get("conditions", {})

    def save_state() -> None:
        tmp = progress_path.with_suffix(progress_path.suffix + ".tmp")
        tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, progress_path)

    total_needed = 0
    for p in params:
        target_count = _signatures_for_param(signatures_per_param_set, p)
        if target_count > 0:
            total_needed += target_count * int(num_secret_seeds) * len(opts)
    print("===== Append-safe multi-SK.seed message signing capture =====")
    print("total secret seeds       :", num_secret_seeds)
    print("target signatures (max)  :", total_needed)
    print("message/path seed        :", message_seed, "/", addrnd_seed)
    print("progress JSON (new file):", progress_path)

    for p in params:
        n_signatures = _signatures_for_param(signatures_per_param_set, p)
        if n_signatures <= 0:
            print(f"[SKIP] {p}: requested signatures={n_signatures}")
            continue
        live.select_parameter_set(p)
        param_root = results_base_dir / f"SLH_DSA_{p}_{hash_mode}_message_signature_sequence"
        param_root.mkdir(parents=True, exist_ok=True)
        seed_manifest = param_root / "shared_secret_seeds.json"
        # Existing manifest is extended deterministically. Back up its original
        # content once, in case the researcher wants to inspect the old pool.
        if seed_manifest.exists():
            old_pool = json.loads(seed_manifest.read_text(encoding="utf-8"))
            if int(old_pool.get("num_seeds", -1)) < int(num_secret_seeds):
                backup = param_root / "shared_secret_seeds.before_multiseed.json"
                if not backup.exists():
                    shutil.copy2(seed_manifest, backup)
        seeds, _ = live.load_or_create_secret_seed_manifest(
            seed_manifest,
            num_seeds=int(num_secret_seeds),
            master_seed=int(secret_seed_master),
            parameter_set=p,
            overwrite=False,
        )
        pk_seed = bytes(live.PUB_SEED)
        sk_prf = bytes(live.SK_PRF)

        # Derive the proper PK.root separately for each SK.seed. The old
        # derived_pk_root_seed_000.json is reused, never re-keyed in place.
        roots: Dict[int, bytes] = {}
        for seed_id, sk_seed in enumerate(seeds):
            root_cache = param_root / f"derived_pk_root_seed_{seed_id:03d}.json"
            if force_recompute_pk_root and root_cache.exists():
                raise ValueError(
                    f"force_recompute_pk_root=True would modify existing {root_cache}; "
                    "use False to preserve old files"
                )
            if root_cache.exists():
                cached = json.loads(root_cache.read_text(encoding="utf-8"))
                if (
                    cached.get("sk_seed_sha256") != hashlib.sha256(sk_seed).hexdigest()
                    or cached.get("pk_seed_sha256") != hashlib.sha256(pk_seed).hexdigest()
                    or cached.get("parameter_set") != p
                ):
                    raise ValueError(
                        f"Incompatible existing PK.root cache {root_cache}; "
                        "refusing to replace it"
                    )
            root, _ = msgcap.load_or_derive_pk_root_sha2(
                root_cache,
                sk_seed=sk_seed,
                pk_seed=pk_seed,
                force_recompute=bool(force_recompute_pk_root),
            )
            roots[seed_id] = bytes(root)

        for opt in opts:
            live.select_parameter_set(p)
            opt_label, make_opt = basebatch.normalize_compiler_opt(opt)
            out_dir = signature_condition_output_dir(
                results_base_dir, param_set=p, hash_mode=hash_mode, compiler_opt=opt
            )
            out_dir.mkdir(parents=True, exist_ok=True)
            scans: Dict[int, Dict[str, Any]] = {}
            existing_trace_lengths = set()
            for seed_id, sk_seed in enumerate(seeds):
                seed_dir = out_dir / f"seed_{seed_id:03d}"
                scan = msgcap.inspect_random_message_signature_resume(
                    seed_dir,
                    num_signatures=n_signatures,
                    sk_prf=sk_prf,
                    pk_seed=pk_seed,
                    pk_root=roots[seed_id],
                    sk_seed=sk_seed,
                    secret_seed_id=seed_id,
                    message_seed=message_seed,
                    message_length=message_length,
                    signing_variant=signing_variant,
                    addrnd_seed=addrnd_seed,
                    context=bytes(context),
                    capture_phases=phases,
                    mode=hash_mode,
                )
                scans[seed_id] = scan
                for sid in scan["reused_signature_ids"]:
                    old_prefix = seed_dir / f"signature_{sid:03d}" / "capture"
                    traces = __import__("numpy").load(
                        str(old_prefix) + "_traces_random.npy", mmap_mode="r", allow_pickle=False
                    )
                    existing_trace_lengths.add(int(traces.shape[1]))
                print(
                    f"[{p}/{opt_label}/seed_{seed_id:03d}] "
                    f"existing={len(scan['reused_signature_ids'])}, "
                    f"additional={len(scan['missing_signature_ids'])}: "
                    f"{scan['missing_signature_ids']}"
                )
            if len(existing_trace_lengths) > 1:
                raise ValueError(
                    f"Stored captures for {p}/{opt_label} have differing trace lengths "
                    f"{sorted(existing_trace_lengths)}; manual investigation required"
                )
            if not any(scan["missing_signature_ids"] for scan in scans.values()):
                print(f"[SKIP] {p}/{opt_label}: all {num_secret_seeds} seeds complete")
                for seed_id in range(len(seeds)):
                    state["conditions"][f"{p}|{opt_label}|seed_{seed_id:03d}"] = {
                        "status": "completed-reused-disk",
                        "num_signatures": n_signatures,
                        "additional_signatures": 0,
                    }
                save_state()
                continue

            cond_started = time.perf_counter()
            try:
                basebatch._write_parameter_header(
                    live=live, param_set=p, firmware_dir=firmware_dir
                )
                base_build_metadata = {
                    "compiler_optimization": opt_label,
                    "make_opt": make_opt,
                    "platform": platform,
                    "crypto_target": crypto_target,
                    "parameter_set": p,
                    "hash_mode": hash_mode,
                    "capture_mode": "fips205_random_message_signing_multiseed_append",
                    "num_secret_seeds": len(seeds),
                    "num_signatures": int(n_signatures),
                    "message_seed": int(message_seed),
                    "message_length": int(message_length),
                    "signing_variant": str(signing_variant).strip().lower(),
                    "addrnd_seed": int(addrnd_seed),
                    "context_hex": bytes(context).hex(),
                    "capture_phases": ",".join(phases),
                    "shared_seed_manifest": str(seed_manifest),
                }
                live.set_capture_build_metadata(base_build_metadata)
                if build_firmware:
                    build_config = basebatch._build_firmware(
                        live=live,
                        firmware_dir=firmware_dir,
                        result_dir=out_dir,
                        param_set=p,
                        hash_mode=hash_mode,
                        platform=platform,
                        crypto_target=crypto_target,
                        compiler_opt=opt_label,
                    )
                    # Existing build/config files may be updated by the build
                    # workflow; captured waveform files are never modified.
                    base_build_metadata.update({
                        "build_log": build_config["build_log"],
                        "build_config": build_config["build_config"],
                        "optimization_flag_seen_in_build_log": bool(
                            build_config["optimization_flag_seen_in_build_log"]
                        ),
                    })
                firmware_path = firmware_dir / f"simpleserial-SLH-DSA-{platform}.hex"
                if not firmware_path.is_file():
                    raise FileNotFoundError(f"Firmware not found: {firmware_path}")
                if program_target:
                    cw.program_target(
                        scope, basebatch._programmer_for_platform(cw, platform),
                        str(firmware_path),
                    )

                scope.adc.samples = (
                    min(int(number_of_points), int(max_samples))
                    if int(number_of_points) > 0 else int(max_samples)
                )
                calibration_sk_seed = bytes(seeds[0])
                live.reset_and_configure(
                    scope, target,
                    mode=hash_mode,
                    pk_seed=pk_seed,
                    sk_seed=calibration_sk_seed,
                    sk_prf=sk_prf,
                    timeout=int(timeout),
                )
                calibration = live.calibrate_and_set_samples(
                    scope, target,
                    calibration_kind=calibration_kind,
                    mode=hash_mode,
                    pk_seed=pk_seed,
                    sk_seed=calibration_sk_seed,
                    sk_prf=sk_prf,
                    timeout=int(timeout),
                    auto_calibrate=bool(auto_calibrate_points),
                    margin=int(calibration_margin),
                    max_samples=int(max_samples),
                    manual_samples=int(number_of_points),
                    verify_addr=True,
                )
                if existing_trace_lengths:
                    old_samples = next(iter(existing_trace_lengths))
                    if int(scope.adc.samples) != old_samples:
                        if old_samples > int(max_samples):
                            raise ValueError(
                                f"Old trace length {old_samples} exceeds max_samples {max_samples}"
                            )
                        print(
                            f"[{p}/{opt_label}] reuse old waveform length "
                            f"{old_samples} instead of calibration "
                            f"{scope.adc.samples} to keep CPA compatible"
                        )
                        scope.adc.samples = old_samples

                for seed_id, sk_seed in enumerate(seeds):
                    scan = scans[seed_id]
                    key = f"{p}|{opt_label}|seed_{seed_id:03d}"
                    missing = scan["missing_signature_ids"]
                    if not missing:
                        state["conditions"][key] = {
                            "status": "completed-reused-disk",
                            "num_signatures": n_signatures,
                            "additional_signatures": 0,
                        }
                        save_state()
                        continue
                    seed_dir = out_dir / f"seed_{seed_id:03d}"
                    metadata = dict(base_build_metadata)
                    metadata.update({
                        "secret_seed_id": int(seed_id),
                        "sk_seed_sha256": hashlib.sha256(sk_seed).hexdigest(),
                        "pk_root_hex": roots[seed_id].hex(),
                    })
                    live.set_capture_build_metadata(metadata)
                    started = time.perf_counter()
                    print(
                        f"[RUN] {p}/{opt_label}/seed_{seed_id:03d}: "
                        f"add {len(missing)} signatures"
                    )
                    try:
                        collected = msgcap.capture_random_message_signing_prf_sequences(
                            scope, target, seed_dir,
                            platform=platform,
                            num_signatures=int(n_signatures),
                            sk_prf=sk_prf,
                            pk_seed=pk_seed,
                            pk_root=roots[seed_id],
                            sk_seed=sk_seed,
                            secret_seed_id=seed_id,
                            message_seed=int(message_seed),
                            message_length=int(message_length),
                            signing_variant=signing_variant,
                            addrnd_seed=int(addrnd_seed),
                            context=bytes(context),
                            capture_phases=phases,
                            mode=hash_mode,
                            timeout=int(timeout),
                            verify_addr_each_time=bool(verify_addr_each_time),
                            verify_result=bool(verify_result),
                            verify_first_n=int(verify_first_n),
                            flush_every=int(flush_every),
                            resume=True,
                        )
                        state["conditions"][key] = {
                            "status": "completed",
                            "num_signatures": int(n_signatures),
                            "additional_signatures": len(missing),
                            "elapsed_s": round(time.perf_counter() - started, 3),
                            "sequence_manifest": str(
                                seed_dir / "signature_sequence_capture_manifest.json"
                            ),
                            "completed_signatures": len(collected.get("completed", [])),
                        }
                        save_state()
                    except Exception as exc:
                        state["conditions"][key] = {
                            "status": "failed",
                            "error": f"{type(exc).__name__}: {exc}",
                            "elapsed_s": round(time.perf_counter() - started, 3),
                        }
                        save_state()
                        if not continue_on_error:
                            raise
                        print(f"[FAIL] {key}: {exc}")
                live.set_capture_build_metadata(base_build_metadata)
                print(
                    f"[CONDITION DONE] {p}/{opt_label}: "
                    f"{time.perf_counter() - cond_started:.1f}s"
                )
            except Exception as exc:
                print(f"[CONDITION ERROR] {p}/{opt_label}: {type(exc).__name__}: {exc}")
                if not continue_on_error:
                    raise

    save_state()
    print("===== Multi-seed append capture finished =====")
    print("progress:", progress_path)
    return state
