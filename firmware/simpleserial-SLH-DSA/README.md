# Target firmware

`slh_dsa_prf_target.c` is a ChipWhisperer SimpleSerial target for collecting a
power trace of **one isolated SLH-DSA address-PRF invocation at a time**.
It is **not** a full SLH-DSA signer. The host handles the FIPS 205 signing
path and supplies the address and experimental seeds.

## Build location (important)

This project uses ChipWhisperer's makefile framework. The supplied Makefile
includes `../simpleserial/Makefile.simpleserial` and `../Makefile.inc`.
Therefore, **do not run make from this standalone repository folder**.
Copy the complete `simpleserial-SLH-DSA/` directory into the existing
`chipwhisperer/hardware/victims/firmware/` directory (alongside
`simpleserial/`), and compile there using the ChipWhisperer ARM toolchain.
The capture notebooks use the resulting directory via
`SLH_DSA_FIRMWARE_DIR`.

Example for the STM32F3 target (adjust the platform for your hardware):

```sh
cd /path/to/chipwhisperer/hardware/victims/firmware/simpleserial-SLH-DSA
make PLATFORM=CW308_STM32F3 CRYPTO_TARGET=MBEDTLS OPT=s clean
make PLATFORM=CW308_STM32F3 CRYPTO_TARGET=MBEDTLS OPT=s
```

The expected output is named like
`simpleserial-SLH-DSA-CW308_STM32F3.hex`.
The Python batch automates parameter header generation, build and programming;
manual compilation is optional. `OPT=s` corresponds to the `Os` optimization
entry in the capture notebooks.

## Parameter selection

The checked-in `slh_param_config.h` sets a **public example** of `128f`.
The capture batch rewrites this header for every parameter set; it is not a
record of any private capture configuration. `SLH_SECURITY_LEVEL` controls
`n = 16/24/32`, the SimpleSerial seed/output sizes. This target's PRF uses
`n` and the input ADRS; it does not execute the full FORS/XMSS algorithms.
The FORS/XMSS shape is controlled by the host, not by the unused f/s tree
constants in this PRF-only C target.

## SimpleSerial protocol

| Command | Purpose |
|---|---|
| `M` | Set hash mode: SHA2 (0) or SHAKE (1) |
| `P` | Set `PK.seed` (`n` bytes) |
| `S` | Set experimental `SK.seed` (`n` bytes) |
| `Q` | Set `SK.prf` (`n` bytes); retained for host/target interface compatibility |
| `A` | Set full ADRS (`32` bytes) |
| `R` | Read ADRS |
| `B` | Read mode |
| `N` | Read compiled `n` |
| `T` | Evaluate a single address PRF (measurement trigger in core hash) |
| `Z` | Read the `n`-byte PRF result |

SHA2 PRF uses a precomputed SHA-256 state for `PK.seed || 0^(64-n)`, then
processes `ADRS^c || SK.seed`. The trigger spans the SHA-256 compression
procedure. SHAKE mode has a Keccak-f trigger. In the SHA2 capture notebook,
the target's `SK.prf` value is not used in this isolated address PRF; it is
used on the host for message-driven path derivation.

## Scope and caution

This source was supplied as part of an experimental side-channel research
workflow. No real board/toolchain build was performed while preparing the
public package. Only public demo settings belong in version control.
Review code provenance and obtain all necessary publication permissions.
