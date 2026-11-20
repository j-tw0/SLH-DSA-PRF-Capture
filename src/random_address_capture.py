"""
Automatic SLH-DSA ChipWhisperer capture batch.

Runs the full matrix
    parameter set x compiler optimization
and, for each condition:
    parameter header -> firmware build -> target program -> calibration
    -> multi-seed WOTS/FORS capture.

The low-level capture implementation is provided by the existing
prf_capture_core helper.
"""

from __future__ import annotations

import json
import math
import os
import shutil
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


BATCH_HELPER_VERSION = "2026-08-18-all-params-all-opts-v1"

DEFAULT_PARAM_SETS = ("128f", "128s", "192f", "192s", "256f", "256s")
DEFAULT_COMPILER_OPTS = ("O0", "O1", "O2", "O3", "Os")


def _timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def normalize_compiler_opt(value: str) -> Tuple[str, str]:
    """Return (display label, ChipWhisperer Makefile OPT value)."""
    raw = str(value).strip()
    aliases = {
        "0": ("O0", "0"), "O0": ("O0", "0"), "o0": ("O0", "0"),
        "1": ("O1", "1"), "O1": ("O1", "1"), "o1": ("O1", "1"),
        "2": ("O2", "2"), "O2": ("O2", "2"), "o2": ("O2", "2"),
        "3": ("O3", "3"), "O3": ("O3", "3"), "o3": ("O3", "3"),
        "s": ("Os", "s"), "S": ("Os", "s"),
        "Os": ("Os", "s"), "OS": ("Os", "s"), "os": ("Os", "s"),
    }
    if raw not in aliases:
        raise ValueError("compiler option must be one of O0, O1, O2, O3, Os")
    return aliases[raw]


def normalize_capture_kinds(value: str) -> Tuple[str, ...]:
    raw = str(value).strip().lower()
    aliases = {
        "wots": ("wots",),
        "wots+": ("wots",),
        "fors": ("fors",),
        "both": ("wots", "fors"),
        "all": ("wots", "fors"),
        "wots+fors": ("wots", "fors"),
        "wots_fors": ("wots", "fors"),
    }
    if raw not in aliases:
        raise ValueError("capture_kind must be 'wots', 'fors', or 'both'")
    return aliases[raw]


def _condition_key(param_set: str, compiler_opt: str) -> str:
    return f"{param_set}|{compiler_opt}"


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


def _load_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        with path.open("r", encoding="utf-8") as f:
            value = json.load(f)
        if isinstance(value, dict):
            return value
    except Exception:
        return None
    return None


def _atomic_write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def condition_output_dir(
    results_base_dir: str | os.PathLike,
    *,
    param_set: str,
    hash_mode: str,
    compiler_opt: str,
) -> Path:
    root = Path(str(results_base_dir))
    return (
        root
        / f"SLH_DSA_{param_set}_{hash_mode}_compiler_compare"
        / compiler_opt
    )


def parameter_experiment_root(
    results_base_dir: str | os.PathLike,
    *,
    param_set: str,
    hash_mode: str,
) -> Path:
    root = Path(str(results_base_dir))
    return root / f"SLH_DSA_{param_set}_{hash_mode}_compiler_compare"


def planned_trace_count_for_condition(
    *,
    compiler_opt: str,
    num_secret_seeds: int,
    capture_kind: str,
    cpa_random_traces_per_seed: int,
    capture_tvla_on_os_first_seed: bool,
    tvla_fixed_traces: int,
    tvla_random_traces: int,
) -> int:
    kinds = normalize_capture_kinds(capture_kind)
    per_kind = int(num_secret_seeds) * int(cpa_random_traces_per_seed)
    if bool(capture_tvla_on_os_first_seed) and compiler_opt == "Os":
        per_kind = (
            int(tvla_fixed_traces)
            + max(int(tvla_random_traces), int(cpa_random_traces_per_seed))
            + max(0, int(num_secret_seeds) - 1)
            * int(cpa_random_traces_per_seed)
        )
    return len(kinds) * per_kind


def _progress_manifest_path(output_dir: Path, kind: str) -> Path:
    return output_dir / f"multi_seed_{kind}_fixed_random_capture_manifest.json"


def condition_complete_on_disk(
    output_dir: str | os.PathLike,
    *,
    param_set: str,
    compiler_opt: str,
    capture_kind: str,
    num_secret_seeds: int,
    cpa_random_traces_per_seed: int,
    capture_tvla_on_os_first_seed: bool,
    tvla_seed_index: int,
    tvla_fixed_traces: int,
    tvla_random_traces: int,
) -> bool:
    """Conservative condition-level resume check.

    False negatives are safe: the condition will be rebuilt/programmed and the
    low-level per-seed resume logic will still reuse valid captures.
    """
    output = Path(output_dir)
    for kind in normalize_capture_kinds(capture_kind):
        manifest = _load_json(_progress_manifest_path(output, kind))
        if not manifest:
            return False

        try:
            if str(manifest.get("parameter_set")) != str(param_set):
                return False
            if str(manifest.get("kind")).lower() != kind:
                return False
            if int(manifest.get("num_secret_seeds", -1)) != int(num_secret_seeds):
                return False
            if int(manifest.get("cpa_random_traces", -1)) < int(cpa_random_traces_per_seed):
                return False

            detected = manifest.get("compiler_optimization_detected")
            if detected is not None and str(detected) != str(compiler_opt):
                return False

            rows = {
                int(row["seed_id"]): row
                for row in manifest.get("completed", [])
                if "seed_id" in row
            }
            if len(rows) < int(num_secret_seeds):
                return False

            for sid in range(int(num_secret_seeds)):
                row = rows.get(sid)
                if row is None:
                    return False
                if int(row.get("available_random_rows", 0)) < int(cpa_random_traces_per_seed):
                    return False

                needs_tvla = (
                    bool(capture_tvla_on_os_first_seed)
                    and compiler_opt == "Os"
                    and sid == int(tvla_seed_index)
                )
                if needs_tvla:
                    if int(row.get("available_fixed_rows", 0)) < int(tvla_fixed_traces):
                        return False
                    if int(row.get("available_random_rows", 0)) < int(tvla_random_traces):
                        return False
        except Exception:
            return False

    return True


def _write_parameter_header(
    *,
    live,
    param_set: str,
    firmware_dir: Path,
) -> Dict[str, Any]:
    params = live.select_parameter_set(param_set)
    header_path = firmware_dir / "slh_param_config.h"
    variant_fast = 1 if params.variant == "f" else 0
    text = "\n".join([
        "#ifndef SLH_PARAM_CONFIG_H",
        "#define SLH_PARAM_CONFIG_H",
        "",
        f"#define SLH_SECURITY_LEVEL {params.security_bits}",
        f"#define SLH_PARAMETER_VARIANT_FAST {variant_fast}",
        "",
        "#endif",
        "",
    ])
    header_path.write_text(text, encoding="ascii")
    return {
        "path": str(header_path),
        "text": text,
        "security_bits": int(params.security_bits),
        "variant": str(params.variant),
        "n": int(params.n),
    }


def _build_firmware(
    *,
    live,
    firmware_dir: Path,
    result_dir: Path,
    param_set: str,
    hash_mode: str,
    platform: str,
    crypto_target: str,
    compiler_opt: str,
) -> Dict[str, Any]:
    label, make_opt = normalize_compiler_opt(compiler_opt)
    expected_cflag = f"-O{make_opt}"

    make_exe = shutil.which("make")
    if make_exe is None:
        raise FileNotFoundError("make executable was not found in PATH")

    make_common = [
        make_exe,
        f"PLATFORM={platform}",
        f"OPT={make_opt}",
        f"CRYPTO_TARGET={crypto_target}",
    ]
    clean_cmd = make_common + ["clean"]
    build_cmd = make_common

    subprocess.run(
        clean_cmd,
        cwd=str(firmware_dir),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    process = subprocess.run(
        build_cmd,
        cwd=str(firmware_dir),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    build_output = process.stdout or ""

    result_dir.mkdir(parents=True, exist_ok=True)
    log_path = result_dir / f"build_{param_set}_{hash_mode}_{label}.log"
    log_path.write_text(build_output, encoding="utf-8", errors="replace")

    config = {
        "parameter_set": param_set,
        "hash_mode": hash_mode,
        "platform": platform,
        "crypto_target": crypto_target,
        "compiler_optimization": label,
        "make_opt": make_opt,
        "expected_cflag": expected_cflag,
        "optimization_flag_seen_in_build_log": expected_cflag in build_output,
        "firmware_dir": str(firmware_dir),
        "clean_command": clean_cmd,
        "build_command": build_cmd,
        "build_log": str(log_path),
    }
    config_path = result_dir / f"build_config_{param_set}_{hash_mode}_{label}.json"
    config["build_config"] = str(config_path)
    config_path.write_text(
        json.dumps(config, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return config


def _programmer_for_platform(cw, platform: str):
    if "STM" in platform or platform in ("CWLITEARM", "CWNANO"):
        return cw.programmers.STM32FProgrammer
    if platform in ("CW303", "CWLITEXMEGA"):
        return cw.programmers.XMEGAProgrammer
    if platform == "CW308_SAM4S":
        return cw.programmers.SAM4SProgrammer
    raise ValueError(f"Unsupported PLATFORM: {platform}")


def _batch_state_template(
    *,
    param_sets: Sequence[str],
    compiler_opts: Sequence[str],
    hash_mode: str,
    capture_kind: str,
) -> Dict[str, Any]:
    return {
        "format": "slh-dsa-auto-capture-all-params-opts-v1",
        "helper_version": BATCH_HELPER_VERSION,
        "param_sets": list(param_sets),
        "compiler_opts": list(compiler_opts),
        "hash_mode": hash_mode,
        "capture_kind": capture_kind,
        "conditions": {},
    }


def _load_or_init_batch_state(
    path: Path,
    *,
    param_sets: Sequence[str],
    compiler_opts: Sequence[str],
    hash_mode: str,
    capture_kind: str,
) -> Dict[str, Any]:
    old = _load_json(path)
    if old and old.get("format") == "slh-dsa-auto-capture-all-params-opts-v1":
        old.setdefault("conditions", {})
        return old
    return _batch_state_template(
        param_sets=param_sets,
        compiler_opts=compiler_opts,
        hash_mode=hash_mode,
        capture_kind=capture_kind,
    )


def _eta_seconds(
    state: Dict[str, Any],
    *,
    remaining_conditions: Sequence[Tuple[str, str, int]],
) -> Optional[float]:
    total_seconds = 0.0
    total_traces = 0
    for row in state.get("conditions", {}).values():
        if row.get("status") != "completed":
            continue
        dur = row.get("duration_s")
        traces = row.get("planned_traces")
        if dur is None or traces is None:
            continue
        if float(dur) > 0 and int(traces) > 0:
            total_seconds += float(dur)
            total_traces += int(traces)

    if total_seconds <= 0 or total_traces <= 0:
        return None

    sec_per_trace = total_seconds / total_traces
    remaining_traces = sum(int(x[2]) for x in remaining_conditions)
    return sec_per_trace * remaining_traces


def run_all_parameter_compiler_captures(
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
    build_firmware: bool = True,
    program_target: bool = True,
    num_secret_seeds: int = 10,
    cpa_random_traces_per_secret_seed: int = 5000,
    capture_kind: str = "both",
    secret_seed_master: int = 424242,
    capture_rng_seed: int = 1234,
    shuffle_fixed_random_sequence: bool = True,
    capture_tvla_on_os_first_seed: bool = False,
    tvla_fixed_traces: int = 10000,
    tvla_random_traces: int = 10000,
    tvla_seed_index: int = 0,
    regenerate_shared_seed_manifest: bool = False,
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
    compatible_resume: bool = True,
    ignore_existing_fixed_nonprimary: bool = True,
    continue_on_error: bool = False,
    progress_json_name: str = "all_params_opts_capture_progress.json",
) -> Dict[str, Any]:
    """Run capture for every selected parameter-set/compiler-option pair.

    Resume behavior:
      * Fully completed conditions are skipped before rebuild/program.
      * If a condition stopped part-way through, it is rebuilt/programmed,
        then the low-level per-seed resume logic reuses completed WOTS/FORS
        seed datasets and continues from the remaining seeds.
    """
    import chipwhisperer as cw

    firmware_dir = Path(firmware_dir)
    results_base_dir = Path(str(results_base_dir))
    results_base_dir.mkdir(parents=True, exist_ok=True)

    required = [
        firmware_dir,
        firmware_dir / "slh_dsa_prf_target.c",
        firmware_dir / "Makefile",
    ]
    for path in required:
        if not path.exists():
            raise FileNotFoundError(str(path))

    params = [live.normalize_param_set(p) for p in param_sets]
    opts = [normalize_compiler_opt(o)[0] for o in compiler_opts]
    kinds = normalize_capture_kinds(capture_kind)
    capture_kind_normalized = "both" if len(kinds) == 2 else kinds[0]

    progress_path = results_base_dir / progress_json_name
    state = _load_or_init_batch_state(
        progress_path,
        param_sets=params,
        compiler_opts=opts,
        hash_mode=hash_mode,
        capture_kind=capture_kind_normalized,
    )

    condition_rows: List[Tuple[str, str, int]] = []
    for param in params:
        for opt in opts:
            planned = planned_trace_count_for_condition(
                compiler_opt=opt,
                num_secret_seeds=num_secret_seeds,
                capture_kind=capture_kind_normalized,
                cpa_random_traces_per_seed=cpa_random_traces_per_secret_seed,
                capture_tvla_on_os_first_seed=capture_tvla_on_os_first_seed,
                tvla_fixed_traces=tvla_fixed_traces,
                tvla_random_traces=tvla_random_traces,
            )
            condition_rows.append((param, opt, planned))

    # Refresh completion state from disk so restart does not depend only on JSON.
    for param, opt, planned in condition_rows:
        out_dir = condition_output_dir(
            results_base_dir,
            param_set=param,
            hash_mode=hash_mode,
            compiler_opt=opt,
        )
        key = _condition_key(param, opt)
        complete = bool(resume) and condition_complete_on_disk(
            out_dir,
            param_set=param,
            compiler_opt=opt,
            capture_kind=capture_kind_normalized,
            num_secret_seeds=num_secret_seeds,
            cpa_random_traces_per_seed=cpa_random_traces_per_secret_seed,
            capture_tvla_on_os_first_seed=capture_tvla_on_os_first_seed,
            tvla_seed_index=tvla_seed_index,
            tvla_fixed_traces=tvla_fixed_traces,
            tvla_random_traces=tvla_random_traces,
        )
        row = state["conditions"].setdefault(key, {})
        row.update({
            "parameter_set": param,
            "compiler_opt": opt,
            "planned_traces": int(planned),
            "output_dir": str(out_dir),
        })
        if complete:
            row["status"] = "completed"
            row.setdefault("completion_source", "disk-discovery")
        elif row.get("status") == "completed":
            # Disk no longer satisfies the current request (e.g.
            # num_secret_seeds was raised 10 -> 30). Clear the stale
            # status so the condition is re-entered and the per-seed
            # resume logic adds only the missing seeds.
            row["status"] = "pending"
            row["stale_completed_cleared_at"] = datetime.now().isoformat(timespec="seconds")
            row.pop("completion_source", None)

    _atomic_write_json(progress_path, state)

    total_planned = sum(x[2] for x in condition_rows)
    completed_planned = sum(
        planned
        for param, opt, planned in condition_rows
        if state["conditions"].get(_condition_key(param, opt), {}).get("status") == "completed"
    )

    total_conditions = len(condition_rows)
    completed_conditions = sum(
        1
        for param, opt, _ in condition_rows
        if state["conditions"].get(_condition_key(param, opt), {}).get("status") == "completed"
    )

    print("===== Automatic SLH-DSA capture batch =====")
    print("parameter sets :", ", ".join(params))
    print("compiler opts  :", ", ".join(opts))
    print("capture kinds  :", ", ".join(kinds))
    print("secret seeds   :", int(num_secret_seeds))
    print("CPA random/seed:", int(cpa_random_traces_per_secret_seed))
    print("TVLA capture   :", bool(capture_tvla_on_os_first_seed))
    print("conditions     :", total_conditions)
    print("planned traces :", f"{total_planned:,}")
    print("already done   :", f"{completed_conditions}/{total_conditions}")
    print("progress file  :", progress_path)
    print()

    overall_start = time.perf_counter()

    for condition_index, (param, opt, planned) in enumerate(condition_rows, start=1):
        key = _condition_key(param, opt)
        current_state = state["conditions"].setdefault(key, {})

        if bool(resume) and current_state.get("status") == "completed":
            pct = 100.0 * completed_planned / total_planned if total_planned else 100.0
            print(
                f"[SKIP {condition_index:02d}/{total_conditions}] "
                f"{param}/{opt} | overall {pct:6.2f}%"
            )
            continue

        remaining_for_eta = [
            row
            for row in condition_rows
            if state["conditions"].get(
                _condition_key(row[0], row[1]), {}
            ).get("status") != "completed"
        ]
        eta_before = _eta_seconds(state, remaining_conditions=remaining_for_eta)
        pct_before = 100.0 * completed_planned / total_planned if total_planned else 0.0

        print(
            f"[RUN  {condition_index:02d}/{total_conditions}] "
            f"{param}/{opt} | overall {pct_before:6.2f}% | "
            f"ETA {_fmt_seconds(eta_before)}"
        )

        condition_start = time.perf_counter()
        out_dir = condition_output_dir(
            results_base_dir,
            param_set=param,
            hash_mode=hash_mode,
            compiler_opt=opt,
        )
        experiment_root = parameter_experiment_root(
            results_base_dir,
            param_set=param,
            hash_mode=hash_mode,
        )
        out_dir.mkdir(parents=True, exist_ok=True)
        experiment_root.mkdir(parents=True, exist_ok=True)

        try:
            params_obj = live.select_parameter_set(param)
            header = _write_parameter_header(
                live=live,
                param_set=param,
                firmware_dir=firmware_dir,
            )

            shared_manifest = experiment_root / "shared_secret_seeds.json"
            secret_seeds, seed_manifest_data = live.load_or_create_secret_seed_manifest(
                shared_manifest,
                num_seeds=int(num_secret_seeds),
                master_seed=int(secret_seed_master),
                parameter_set=param,
                overwrite=bool(regenerate_shared_seed_manifest),
            )

            pk_seed = bytes(live.PUB_SEED)
            sk_prf = bytes(live.SK_PRF)
            calibration_sk_seed = bytes(secret_seeds[0])

            opt_label, make_opt = normalize_compiler_opt(opt)
            expected_cflag = f"-O{make_opt}"

            live.set_capture_build_metadata(
                compiler_optimization=opt_label,
                make_opt=make_opt,
                expected_cflag=expected_cflag,
                platform=platform,
                crypto_target=crypto_target,
                parameter_set=param,
                hash_mode=hash_mode,
                shared_seed_manifest=str(shared_manifest),
                num_secret_seeds=int(num_secret_seeds),
                cpa_random_traces_per_seed=int(cpa_random_traces_per_secret_seed),
                capture_tvla_on_os_first_seed=bool(capture_tvla_on_os_first_seed),
                tvla_fixed_traces=int(tvla_fixed_traces),
                tvla_random_traces=int(tvla_random_traces),
                tvla_seed_index=int(tvla_seed_index),
                secret_seed_master=int(secret_seed_master),
                capture_rng_seed=int(capture_rng_seed),
                shuffle_fixed_random_sequence=bool(shuffle_fixed_random_sequence),
            )

            build_config = None
            if build_firmware:
                build_config = _build_firmware(
                    live=live,
                    firmware_dir=firmware_dir,
                    result_dir=out_dir,
                    param_set=param,
                    hash_mode=hash_mode,
                    platform=platform,
                    crypto_target=crypto_target,
                    compiler_opt=opt_label,
                )
                # Re-register metadata including build files after build.
                metadata = live.get_capture_build_metadata()
                metadata.update({
                    "optimization_flag_seen_in_build_log": bool(
                        build_config["optimization_flag_seen_in_build_log"]
                    ),
                    "build_log": build_config["build_log"],
                    "build_config": build_config["build_config"],
                })
                live.set_capture_build_metadata(metadata)

            fw_path = firmware_dir / f"simpleserial-SLH-DSA-{platform}.hex"
            if not fw_path.is_file():
                raise FileNotFoundError(f"Built firmware not found: {fw_path}")

            if program_target:
                prog = _programmer_for_platform(cw, platform)
                cw.program_target(scope, prog, str(fw_path))

            # Ensure the scope starts calibration with enough room after every
            # rebuild because trigger duration may change with optimization.
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
                sk_seed=calibration_sk_seed,
                sk_prf=sk_prf,
                timeout=int(timeout),
            )

            target_n = int(live.read_target_n(target, timeout=int(timeout)))
            if target_n != int(live.SLH_N):
                raise RuntimeError(
                    f"target/helper n mismatch after programming: "
                    f"target={target_n}, helper={live.SLH_N}"
                )

            calibration = live.calibrate_and_set_samples(
                scope,
                target,
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

            calibration_summary = {
                "parameter_set": param,
                "compiler_opt": opt_label,
                "match": bool(calibration["match"]),
                "trig_count": int(calibration["trig_count"]),
                "scope_samples": int(calibration["scope_samples"]),
                "wave_len": int(calibration["wave_len"]),
                "margin": int(calibration_margin),
            }
            (out_dir / f"calibration_{param}_{opt_label}.json").write_text(
                json.dumps(calibration_summary, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )

            capture_policy = (
                "auto_os_first"
                if bool(capture_tvla_on_os_first_seed)
                else "none"
            )

            result = live.capture_multi_seed_fixed_random_experiment(
                scope,
                target,
                str(out_dir),
                platform=platform,
                seeds=secret_seeds,
                kind=capture_kind_normalized,
                tvla_fixed_traces=int(tvla_fixed_traces),
                tvla_random_traces=int(tvla_random_traces),
                cpa_random_traces=int(cpa_random_traces_per_secret_seed),
                mode=hash_mode,
                capture_rng_seed=int(capture_rng_seed),
                pk_seed=pk_seed,
                sk_prf=sk_prf,
                timeout=int(timeout),
                shuffle_sequence=bool(shuffle_fixed_random_sequence),
                verify_addr_each_time=bool(verify_addr_each_time),
                verify_result=bool(verify_result),
                verify_first_n=int(verify_first_n),
                flush_every=int(flush_every),
                resume=bool(resume),
                compatible_resume=bool(compatible_resume),
                fixed_seed_policy=capture_policy,
                fixed_seed_index=int(tvla_seed_index),
                ignore_existing_fixed_nonprimary=bool(ignore_existing_fixed_nonprimary),
            )

            # Require disk manifests to say the whole condition is complete.
            if not condition_complete_on_disk(
                out_dir,
                param_set=param,
                compiler_opt=opt_label,
                capture_kind=capture_kind_normalized,
                num_secret_seeds=num_secret_seeds,
                cpa_random_traces_per_seed=cpa_random_traces_per_secret_seed,
                capture_tvla_on_os_first_seed=capture_tvla_on_os_first_seed,
                tvla_seed_index=tvla_seed_index,
                tvla_fixed_traces=tvla_fixed_traces,
                tvla_random_traces=tvla_random_traces,
            ):
                raise RuntimeError(
                    "capture returned, but completion manifests do not "
                    "cover the full requested condition"
                )

            duration = time.perf_counter() - condition_start
            current_state.update({
                "parameter_set": param,
                "compiler_opt": opt_label,
                "status": "completed",
                "completed_at": datetime.now().isoformat(timespec="seconds"),
                "duration_s": float(duration),
                "planned_traces": int(planned),
                "output_dir": str(out_dir),
                "scope_samples": int(calibration["scope_samples"]),
                "trig_count": int(calibration["trig_count"]),
                "shared_seed_manifest": str(shared_manifest),
                "capture_summary": result.get("combined_manifest"),
            })
            _atomic_write_json(progress_path, state)

            completed_planned += int(planned)
            completed_conditions += 1

            remaining_after = [
                row
                for row in condition_rows
                if state["conditions"].get(
                    _condition_key(row[0], row[1]), {}
                ).get("status") != "completed"
            ]
            eta_after = _eta_seconds(state, remaining_conditions=remaining_after)
            pct_after = 100.0 * completed_planned / total_planned if total_planned else 100.0

            print(
                f"[DONE {condition_index:02d}/{total_conditions}] "
                f"{param}/{opt_label} | overall {pct_after:6.2f}% | "
                f"condition {_fmt_seconds(duration)} | "
                f"ETA {_fmt_seconds(eta_after)}"
            )

        except Exception as exc:
            duration = time.perf_counter() - condition_start
            current_state.update({
                "parameter_set": param,
                "compiler_opt": opt,
                "status": "failed",
                "failed_at": datetime.now().isoformat(timespec="seconds"),
                "duration_s": float(duration),
                "planned_traces": int(planned),
                "output_dir": str(out_dir),
                "error": f"{type(exc).__name__}: {exc}",
            })
            _atomic_write_json(progress_path, state)
            print(f"[FAIL] {param}/{opt}: {type(exc).__name__}: {exc}")
            if not continue_on_error:
                raise

    elapsed = time.perf_counter() - overall_start
    final_complete = sum(
        1
        for param, opt, _ in condition_rows
        if state["conditions"].get(_condition_key(param, opt), {}).get("status") == "completed"
    )
    print()
    print("===== Capture batch finished =====")
    print("completed :", f"{final_complete}/{total_conditions}")
    print("session   :", _fmt_seconds(elapsed))
    print("progress  :", progress_path)
    return state


def preview_capture_plan(
    *,
    param_sets: Sequence[str] = DEFAULT_PARAM_SETS,
    compiler_opts: Sequence[str] = DEFAULT_COMPILER_OPTS,
    num_secret_seeds: int = 10,
    capture_kind: str = "both",
    cpa_random_traces_per_secret_seed: int = 5000,
    capture_tvla_on_os_first_seed: bool = False,
    tvla_fixed_traces: int = 10000,
    tvla_random_traces: int = 10000,
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for param in param_sets:
        for opt_raw in compiler_opts:
            opt, _ = normalize_compiler_opt(opt_raw)
            rows.append({
                "parameter_set": str(param),
                "compiler_opt": opt,
                "planned_traces": planned_trace_count_for_condition(
                    compiler_opt=opt,
                    num_secret_seeds=num_secret_seeds,
                    capture_kind=capture_kind,
                    cpa_random_traces_per_seed=cpa_random_traces_per_secret_seed,
                    capture_tvla_on_os_first_seed=capture_tvla_on_os_first_seed,
                    tvla_fixed_traces=tvla_fixed_traces,
                    tvla_random_traces=tvla_random_traces,
                ),
            })
    return rows
