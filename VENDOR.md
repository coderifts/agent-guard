# Reference verify core

This package does not vendor the published verifier into `src/`. It is a pure,
dependency-light library built to both CommonJS and ESM; the reference core is a
CommonJS module with a CLI entry point and `node:fs` at module scope, and the
build (`tsconfig.json`, no `allowJs`) does not emit hand-placed `.js` files into
`dist/`. Copying it into `src/` would mean changing the build shape of a
security library to accommodate a file it cannot execute in one of its two output
formats.

What is vendored instead is a **test fixture**: a byte-identical copy of the
reference core, used only to check that this package agrees with it.

| File | Source | Revision |
|------|--------|----------|
| `test/fixtures/reference-core/verify.js` | `receipt-verifier/verify.js` | `ccc53f9a592aaa7f6072d5c80d724f36de30a8ab` |
| `test/fixtures/reference-core/arity.js` | `receipt-verifier/arity.js` | same |

SHA-256 of those copies is in `test/fixtures/reference-core/VENDOR.sha256`.
`test/vendor-core.test.js` fails if either drifts from its pin, and separately
runs the key-status vectors through **both** this package's own verify path and
the reference copy, asserting the two reach the same verdict. The fixture is not
published (`package.json` `files` lists `dist` only), so nothing here reaches a
consumer's runtime.

The shipped rule lives in `src/deploy-receipt-token.ts`
(`deriveKeyWithdrawalStatus`), transliterated from the reference
`deriveStatus`. The parity test is what keeps the two from drifting.
