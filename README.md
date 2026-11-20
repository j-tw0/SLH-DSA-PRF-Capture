# SLH-DSA PRF Power Trace Capture (ChipWhisperer)

Research code for collecting power traces of SHA-2-based SLH-DSA address-PRF
operations using ChipWhisperer. It includes **three different acquisition workflows**:

1. **Random-address PRF capture:** Valid randomly generated WOTS+/FORS PRF
   addresses, across selected parameter sets, compiler optimization levels,
   and experimental `SK.seed` values. The batch provides calibration,
   fixed/random capture options for TVLA, progress records, and per-seed resume.
2. **Message-driven signing-order PRF capture:** A reproducible message is used
   to derive a FIPS 205 signing path (`PRF_msg`, `H_msg`, FORS indices, tree, and
   leaf). The host sends WOTS+/FORS PRF addresses in the signing-pseudocode
   order, recording **a separate PRF power trace for each call**. This supports
   append-safe capture of additional signatures across multiple experimental
   secret seeds.
3. **Key-generation WOTS_PRF capture:** Top-layer XMSS root-generation WOTS_PRF
   addresses are replayed on the target as isolated PRF operations; no full
   on-target key generation is measured.

> **Scientific scope:** This repository does **not** capture a full SLH-DSA
> signing or key-generation operation on the target. It reconstructs the
> sequence of address-based PRF invocations on the host and measures them
> individually.
> `PRF_msg` and `H_msg` determine the signing path on the host; their power
> consumption is **not** captured. The target firmware must implement the
> matching address-PRF SimpleSerial commands. The software is research-only.

## Associated publication

This repository is associated with the following research preprint:

**Jinwook Chang, Minjeong Lee, JIN YONG MIN, and Dong-Guk Han.**
[**Correlation Power Analysis on SHA-2-Based SLH-DSA**](https://eprint.iacr.org/2026/2753).
*Cryptology ePrint Archive*, Paper **2026/2753** (2026).

- **Paper:** https://eprint.iacr.org/2026/2753
- **Citation:** See [`CITATION.cff`](CITATION.cff), or use the BibTeX entry below.

```bibtex
@misc{cryptoeprint:2026/2753,
  author = {Jinwook Chang and Minjeong Lee and JIN YONG MIN and Dong-Guk Han},
  title = {Correlation Power Analysis on SHA-2-Based SLH-DSA},
  howpublished = {Cryptology {ePrint} Archive, Paper 2026/2753},
  year = {2026},
  url = {https://eprint.iacr.org/2026/2753}
}
```

**Availability and reproduction scope:** This public repository contains
power-trace acquisition code and compatible PRF-only target firmware. It does
**not** include the CPA analysis code, measured trace datasets, or original
experiment-specific keys/settings. The demonstration configurations may differ
from the experimental settings reported in the preprint. In particular, the
message-driven signing-order workflow replays isolated PRF calls rather than
measuring one uninterrupted on-target signature. This repository should not be
interpreted as a complete reproduction package for the paper's CPA results.
The analysis code is maintained separately at
[SLH-DSA-SHA2-CPA](https://github.com/j-tw0/SLH-DSA-SHA2-CPA).

## Contents

```text
src/
  prf_capture_core.py
  random_address_capture.py
  signature_prf_sequence.py
  signature_message_path.py
  signature_sequence_capture.py
  keygen_wots_sequence_capture.py
notebooks/
  01_random_address_capture.ipynb
  02_signature_sequence_capture.ipynb
  03_keygen_wots_prf_capture.ipynb
firmware/
  simpleserial-SLH-DSA/
    slh_dsa_prf_target.c
    slh_param_config.h
    Makefile
    README.md
tests/
  test_capture_smoke.py
  test_append_resume_offline.py
  test_firmware_static.py
  test_notebook_format.py
  test_keygen_wots_capture.py
.github/workflows/
  validate-notebooks.yml
  validate-keygen.yml
requirements.txt
.gitignore
README.md
PUBLICATION_NOTES.md
CITATION.cff
```

Python modules and notebooks use short descriptive filenames. The original
`.npy`/JSON **dataset formats, directory names, manifests, and field names**
are unchanged; existing capture data remains compatible with the updated code.
The previous long Python module filenames are **not** available as import
aliases. Update any personal scripts that imported those names.

## Supported configurations

- SHA-2-based SLH-DSA: 128f, 128s, 192f, 192s, 256f, and 256s.
- `O0`, `O1`, `O2`, `O3`, and `Os`, depending on firmware/compiler support.
- Reference capture platform configuration: `CW308_STM32F3` and
  `CRYPTO_TARGET=MBEDTLS` (change for your actual board/Makefile).
- The generic low-level PRF helper also contains SHAKE PRF support; the
  **message-driven signing-path workflow is SHA-2 only**.
- Generated trace arrays use NumPy `.npy`/memmap storage. FIPS sequence
  metadata uses `uint64` to preserve 256f tree indices.

## Included target firmware (requires a ChipWhisperer build environment)

The source for the compatible PRF-only SimpleSerial target **is included** in
`firmware/simpleserial-SLH-DSA/`:

- `slh_dsa_prf_target.c`
- `slh_param_config.h`
- `Makefile`
- `README.md` (target protocol and build instructions)

This firmware **does not perform a full SLH-DSA signature**. It evaluates one
address-PRF invocation per SimpleSerial command. Before physical acquisition,
copy the entire `simpleserial-SLH-DSA/` directory into the ChipWhisperer
`hardware/victims/firmware/` source tree, alongside `simpleserial/` and
`Makefile.inc`. The supplied Makefile relies on those surrounding files.
Set `SLH_DSA_FIRMWARE_DIR` to that copied directory when running the notebooks.

The host code generates `slh_param_config.h` for the selected parameter set,
builds the firmware with `make clean` / `make`, and programs the target. See the
included firmware README for a manual build example. The included source and
static tests have **not** been verified against a physical target in this release.

## Installation

Use Python 3.10+ in a ChipWhisperer environment with the target programmer,
compiler, and `make` toolchain configured.

```bash
python -m pip install -r requirements.txt
```

Jupyter is required to run the notebooks. Depending on the ChipWhisperer
installation, you may already have a managed environment with these packages.

## Local configuration (do not commit machine-specific values)

Set environment variables before starting Jupyter:

- `SLH_DSA_FIRMWARE_DIR`: path to the **copied** target firmware directory
  inside the ChipWhisperer build tree (containing `slh_dsa_prf_target.c` and
  `Makefile`). Set this for physical capture: the notebooks' fallback path
  points to the repository copy, which cannot be built standalone.
- `SLH_DSA_RESULTS_DIR`: optional destination for captured data (defaults to
  `results/` under the repository; ignored by Git).
- `SLH_DSA_SECRET_SEED_MASTER`: optional integer for deterministic experimental
  `SK.seed` pools. The notebook's public default (`424242`) is a **demo seed**,
  not the private experiment's original master seed.

Example on a Unix shell:

```bash
export SLH_DSA_FIRMWARE_DIR=/absolute/path/to/simpleserial-SLH-DSA
export SLH_DSA_RESULTS_DIR=/absolute/path/to/trace-results
jupyter lab
```

On Windows PowerShell:

```powershell
$env:SLH_DSA_FIRMWARE_DIR = 'C:\path\to\simpleserial-SLH-DSA'
$env:SLH_DSA_RESULTS_DIR = 'D:\path\to\trace-results'
jupyter lab
```

All three notebooks resolve `src/` from the repository root or `notebooks/` folder.
The embedded demo defaults are intentionally small; adjust parameter sets,
optimization flags, the number of signatures or seeds, and trace counts.

## Key-generation WOTS_PRF capture

The notebook [`notebooks/03_keygen_wots_prf_capture.ipynb`](notebooks/03_keygen_wots_prf_capture.ipynb)
records **individual WOTS_PRF power traces** in the logical order used when
FIPS 205 generates the top-level XMSS root during `slh_keygen_internal`:
`xmss_node(top layer, tree=0) -> wots_PKgen`.

**This is not a complete, continuous on-target key-generation trace.**
The host constructs the expected WOTS_PRF public-address sequence and executes
one PRF at a time on the existing SimpleSerial PRF-only firmware. WOTS hash-chain
operations, XMSS node hashing, and other complete key-generation steps are not
included in the power measurements of this workflow.

It supports all six SHA2 SLH-DSA parameter sets, compiler options `O0`--`Os`,
and multiple experimental secret seeds, with safe resume at completed WOTS
keypair boundaries. A public, non-cryptographic demo seed (`424242`) is used
by default. Set `SLH_DSA_SECRET_SEED_MASTER` locally to change the seed pool.

The notebook defaults to `RUN_CAPTURE = False`, so its preview can be run
without a connected ChipWhisperer board. For acquisition, copy the target
firmware to the ChipWhisperer firmware build tree and set `SLH_DSA_FIRMWARE_DIR`.
Optional `SLH_DSA_SIGNING_SEED_SOURCE_DIR` allows the key-generation collector
to use the experimental `SK.seed` manifest from an existing **private**
signing-capture result directory (without modifying that source). Never commit
those private result directories or their secret-seed manifests.

Sample output (private, not committed):

```text
results/SLH_DSA_128f_sha2_keygen_prf_sequence/
  shared_secret_seeds.json
  Os/seed_000/
    keygen_capture_manifest.json
    capture_traces_random.npy
    capture_addrs_random.npy
    capture_params_random.npy
    capture_meta_columns.npy
    capture_capture_config.json
    capture_keygen_sequence.json
```

The `random` suffix follows the common capture-storage convention; key-generation
addresses are generated in a deterministic sequence rather than sampled randomly.
Offline tests: `python tests/test_keygen_wots_capture.py`.

## Run capture

**Random-address experiment:** Open
`notebooks/01_random_address_capture.ipynb`, configure the matrix, review the
capture preview, connect the scope/target, and run the capture cell.

**Message-driven signing-order experiment:** Open
`notebooks/02_signature_sequence_capture.ipynb`, configure per-parameter
signature counts and `SK.seed` counts, review the append preview, connect the
scope/target, and run the append-safe capture cell. The per-seed target is the
**total number of signatures desired**, including existing signatures.

On repeated runs, keep configuration, secret seed master, message/path seeds,
and output locations consistent with saved manifests. Incompatible existing
trace files are not meant to be overwritten; back up data before intentional
reconfiguration. For a new experiment, use a **new empty output directory**.

## Typical output (not committed)

```text
results/
  SLH_DSA_128f_sha2_compiler_compare/Os/
    multi_seed_wots_fixed_random/seed_000/...
    multi_seed_fors_fixed_random/seed_000/...
  SLH_DSA_128f_sha2_message_signature_sequence/
    shared_secret_seeds.json
    derived_pk_root_seed_000.json
    Os/seed_000/
      signature_sequence_capture_manifest.json
      signature_000/
        capture_traces_random.npy
        capture_addrs_random.npy
        capture_signature_sequence_meta.npy
        capture_signature_sequence.json
        ...
```

Output manifests can include **experiment key material** (`sk_seed_hex`),
cryptographic intermediates, paths, machine-specific locations, and filenames.
They are intentionally **not** published here.

## Offline checks (without target hardware)

```bash
python tests/test_notebook_format.py
python tests/test_firmware_static.py
python tests/test_capture_smoke.py
python tests/test_append_resume_offline.py
python tests/test_keygen_wots_capture.py
```

These tests also check key-generation PRF ordering and safe resume; the notebook checks validate JSON/Python syntax, the static firmware command
contract, capture-helper compatibility, parameter/path invariants, large
`uint64` metadata, deterministic message paths, and append-safe resume. The
notebook test requires `nbformat` (installed with JupyterLab in a typical
Jupyter environment). The GitHub Actions workflow also installs `nbformat`
and runs notebook checks on relevant changes. These tests do not prove
compatibility with your particular target, compiler, ChipWhisperer API
version, or measurement hardware.

## Public-source sanitization

- Removed personal Windows paths, original Jupyter outputs/execution history,
  original embedded test seed values, and the experimental master seed value.
- Replaced original embedded keys with explicitly labeled deterministic,
  **public example-only** values; they are not secure cryptographic keys.
- Left PRF capture operations, address generation, FIPS path logic, and saved
  metadata schema intact. Existing private traces are **not guaranteed** to
  match demo keys/settings. Do not merge the public defaults into an existing
  private experiment output directory.
- The original archive-only utility, duplicate source copies, all CPA code,
  and original measurement results are outside this capture-only release.

## Licensing

No open-source license is asserted for code provided by other parties. Confirm
ownership, attribution, institution/partner requirements, and applicable
ChipWhisperer/fork licenses before selecting a license or publishing firmware.
Without a `LICENSE` file, GitHub publication alone does not grant reuse rights.
