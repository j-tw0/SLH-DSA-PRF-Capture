# Publication notes / review checklist

## Included

- One compatible copy of the multi-seed/random-address capture helper.
- The compatible all-parameter/compiler capture batch.
- FIPS 205 signing-order address-sequence builder.
- SHA-2 message-driven path generator and capture helper.
- Append-safe multi-seed message-signature capture batch.
- Resumable top-layer key-generation WOTS_PRF sequence collector.
- Three cleaned executable Jupyter notebooks: random-address PRF, message-based signing order, and key-generation WOTS_PRF.
- PRF-only ChipWhisperer target firmware sources (`slh_dsa_prf_target.c`,
  `slh_param_config.h`, `Makefile`) and firmware build documentation.
- Offline notebook, firmware-contract, smoke, append/resume, and key-generation tests.
- GitHub Actions notebook and key-generation validation workflows.

## Deliberately excluded

- All CPA source code and CPA notebooks.
- Duplicate variants and experimental batch options that the supplied
  low-level capture helper does not implement (`selected_seed_ids`,
  `fast_capture`, and `combined_cmd`). These are not silently advertised.
- Build-artifact archiving utility (not required to collect traces).
- All original capture traces/results, build products, saved secret-seed
  manifests, derived root caches, Jupyter cell outputs, and local paths.
- Prebuilt firmware and user-specific ChipWhisperer toolchains: only
  reusable target source code is included.

## Sensitive data review

1. Do not upload real `SK.seed`, `SK.prf`, key-generation master seeds,
   private datasets, or JSON manifests containing `sk_seed_hex`.
2. The public helper's synthetic demo keys and master seed can be regenerated
   by anyone. They are **only** for experiments; never use them for real signing.
3. Existing private trace manifests may require the original local master
   seed. Store it outside version control, and supply it through the
   `SLH_DSA_SECRET_SEED_MASTER` environment variable when appropriate.
4. Check any **future** additions and commits separately. `.gitignore` is not
   a substitute for checking `git status` and the staged diff.
5. Review ownership, third-party license notices, and any publication approval
   required by co-authors, collaborators, institutions, or employers.

## Limitations of verification

The included offline checks exercise Python behavior and statically verify
the included firmware's SimpleSerial interface without physical hardware.
Real firmware builds, programming, acquisition timing, and host/target
interoperability require a compatible ChipWhisperer environment and hardware
and must be verified locally. The firmware source is included; its build
system dependencies come from the external ChipWhisperer source tree.

## Key-generation measurement boundary

- Replayed WOTS_PRF calls are captured separately in the logical key-generation address order, not as a single complete key-generation trace.
- No WOTS hash-chain or XMSS internal-node power traces are collected by this workflow.
- Public demonstration seed values differ from private experimental values.
