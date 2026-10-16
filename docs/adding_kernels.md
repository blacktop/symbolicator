# Add and Validate a New Kernel Version
This document describes the end-to-end workflow for adding a new kernel version to the `symbolicator` corpus and validating output quality before publishing.

## 1) Define the target version
1. Choose the new corpus folder (example: `kernel/28.0`).
2. Set version bounds:
   - `min` (example: `28.0.0`)
   - `max` (example: `29.0.0`)
3. Identify matching KDK inputs:
   - kernel binary path
   - extensions directory path

## 2) Register the version in the generator
Update `scripts/all.py` by adding an active entry in the `kernels` list with:
- `target` (typically `com.apple.kernel`)
- `folder` (for example `kernel/28.0`)
- `min`, `max`
- `kernel`
- `extensions`
- `skip_list`

Make sure the entry is not commented out.

## 3) Generate signatures
Run from repository root:
- Kernel only:
  - `DO_KERNELS=1 python3 scripts/all.py`
  - or `make refresh-xnus`
- Kexts only:
  - `DO_KEXTS=1 python3 scripts/all.py`
  - or `make refresh-kexts`
- Both:
  - `DO_KERNELS=1 DO_KEXTS=1 python3 scripts/all.py`
  - or `make refresh`

Expected outputs:
- `kernel/<new-version>/xnu.json`
- `kernel/<new-version>/kexts/*.json` (if kext generation is enabled)

## 4) Verification steps (artifact integrity)
1. Confirm output files exist.
2. Ensure generated JSON parses cleanly.
3. Validate against `schema.json`.
4. Confirm metadata:
   - `target` is correct
   - `version.min/max` match intended range
5. Confirm required signature fields are present (`args`, `anchors`, `symbol`, `prototype`).
6. Compare coverage against the prior version (`total`, signature count) and investigate major unexplained deltas.

## 5) Validation steps (accuracy on binaries)
1. Test with a known in-range binary and confirm symbolication quality improves.
2. Run manual spot checks on 30-50 symbols across provenance classes:
   - `direct`
   - `dual-evidence`
   - `propagated`
   - `weak-string+callee`
3. For sampled symbols, verify:
   - anchor strings exist in expected sections
   - xref/caller context supports the label
   - function behavior matches assigned name
4. Validate `caller` and `backtrace` relationships where present.
5. Repeat a smaller pass on a second in-range binary to check consistency.

## 6) Final validation with a sample crash report
1. Select a crash/panic report from the same kernel family.
2. Generate a symbol map using the new corpus.
3. Run crash symbolication.
4. Verify key stack frames resolve to plausible symbols and look for systematic mislabeling.
5. Record a short pass/fail note and any follow-up fixes.

## 7) Acceptance criteria
Publish only when:
- verification checks pass
- no major unexplained regression appears
- false-positive rate is acceptable in spot checks
- crash-report symbolication is plausible and useful

## 8) Commit and publish
1. Stage updated files.
2. Review staged diff.
3. Commit with a clear message and required attribution:
   - `Co-Authored-By: Oz <oz-agent@warp.dev>`
