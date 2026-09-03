/**
 * Copy the vendored verify core into both build outputs (1307).
 *
 * WHY A BUILD STEP AND NOT A tsc CONCERN: the vendored files are plain CommonJS JavaScript, byte
 * copies of the public receipt-verifier. tsc does not emit files it did not compile, so without
 * this the offline verifier resolves './vendor/verify.js' inside dist/ and finds nothing — which
 * is exactly what the first test run reported.
 *
 * They are copied rather than compiled ON PURPOSE. Compiling them would produce a file that is no
 * longer byte-identical to the pinned upstream, and the pin — and the drift test that reads it —
 * would then be checking something the build had already changed.
 */
import { cpSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const src = join(root, 'src', 'vendor');
if (!existsSync(src)) {
  process.stderr.write('copy-vendor: src/vendor is missing — the offline verifier cannot work\n');
  process.exit(1);
}
for (const out of ['cjs', 'esm']) {
  const dest = join(root, 'dist', out, 'vendor');
  mkdirSync(dest, { recursive: true });
  cpSync(src, dest, { recursive: true });
  process.stdout.write(`copy-vendor: ${dest}\n`);
}
