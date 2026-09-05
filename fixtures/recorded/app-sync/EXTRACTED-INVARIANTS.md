# EXTRACTED INVARIANT SNAPSHOTS — what is recorded, and what is lost

## Why not the full source

`src/change-set.js` (74 kB governance engine) and
`packages/cli/src/provider/github-enforcement.js` (60 kB provider adapter, carrying the permission
detail behind the 1405 provider-identity caution) are core product logic. Vendoring them whole into
this PUBLIC repository is over-exposure, and it is irreversible while the open-vs-closed-core
position is undecided. Only what the parity tests actually assert is recorded.

## github-enforcement.invariants.txt

Invariant #9 (`test/invariants.test.js`) asserts exactly two textual properties:

- POSITIVE — the true-branch basis must enumerate what was verified ("all six layers VERIFIED").
- NEGATIVE — no basis line may assert something a configuration read cannot establish.

**Coverage of the negative.** The negative is only meaningful if it can see every line that could
carry an overclaim, so EVERY line matching the basis pattern is extracted, not just the positive
one. Measured at extraction: 1 such line in 1306. The extract is COMPLETE for this assertion, not a
sample of it.

**The file holds ONLY the extracted lines, with no prose.** An earlier draft carried this
explanation inside the .txt, and the sentence describing the forbidden pattern MATCHED it — the
snapshot failed its own assertion. What is scanned is now exactly what was recorded.

**What RECORDED no longer catches:** an overclaim introduced on a line matching neither pattern
(say, a new `rationale:` field). LIVE reads the whole file and would catch it.

## change-set.fingerprints.json

The parity test calls the app's `computeBundleFingerprint` on seven fixed inputs and compares
byte-for-byte with the Guard's exported copy. RECORDED replaces the app side with the seven golden
outputs it produced at the pinned commit.

**What RECORDED no longer catches:** a change in the app AFTER the recording. It proves the Guard
still agrees with what the app produced at that commit, not with what the app produces today.

**What is NOT lost:** all seven cases still run and still compare — including the out-of-order and
null-side cases the engine is easiest to break on.

## Where LIVE still holds the line

Every gate that runs RECORDED here runs LIVE wherever a checkout exists, and the LIVE branch ALSO
fails when this recording is stale. The drift is caught in every place that could act on it.

Regenerate with `node scripts/extract-app-invariants.js`. Never hand-edit.
