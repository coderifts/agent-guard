'use strict';

/**
 * THE SHARED CONTRACT between the installer that WRITES a required check and the verifier that
 * GRADES one. Deliberately dependency-free: `fs`, `chalk`, `child_process` and `@octokit` all stay
 * out, so either side can require it at module top level without a cycle.
 *
 * WHY THIS FILE EXISTS — measured, not stylistic. The dependency ran verifier → installer
 * (`github-enforcement.js` required CHECK_NAME and extractRequiredContexts from
 * `commands/setup-required-check.js`). That direction is what stopped the installer's read-back
 * from calling the verifier: adding the obvious top-level `require` closes the loop, and Node does
 * not throw on a CommonJS cycle — it hands back a PARTIALLY POPULATED exports object. Measured on
 * this pair: with the installer loaded first, the verifier receives `extractRequiredContexts ===
 * undefined` and `CHECK_NAME === undefined`, and Node only prints
 * "Warning: Accessing non-existent property ... inside circular dependency". A verifier whose
 * context matcher is `undefined` matches nothing and would grade every protection as absent —
 * silently, and in the direction of a FALSE PASS. That is strictly worse than the divergence the
 * reuse was meant to close.
 *
 * So the shared primitives moved DOWN into this leaf instead, and both sides now depend on it
 * rather than on each other. The installer can call the real verifier, and the constant below has
 * exactly one definition.
 *
 * ONE DEFINITION, NOT TWO AGREEING ONES. ENFORCING_ISSUER_APP_ID used to be written out in both
 * files with a comment asking the reader to keep them in step, guarded by a test asserting the two
 * were equal. A test over a duplicated constant can only report a divergence after someone writes
 * it; a single definition cannot diverge at all. The equality test is therefore retired as
 * unfalsifiable — see test/issuer-binding-p0.test.js.
 */

/** Same string as mergegate CHECK_NAME_MERGE, and the context the contract-gate Action posts. */
const CHECK_NAME = 'CodeRifts / contract-gate';

/**
 * GitHub Actions' own App id (`GET /apps/github-actions` → id 15368, measured 2026-08-26).
 * The `coderifts/contract-gate` Action posts its check with the workflow's GITHUB_TOKEN, so the
 * issuer GitHub records is github-actions[bot], NOT the CodeRifts App.
 */
const GITHUB_ACTIONS_APP_ID = 15368;
const GITHUB_ACTIONS_APP_SLUG = 'github-actions';

/**
 * The issuer whose check actually blocks. The CodeRifts App's own check is clamped to `neutral`
 * unless the server runs MERGEGATE_ENFORCE=true, and GitHub treats a neutral required check as
 * passing — so binding to it would pin a check that by default cannot block. The contract-gate
 * Action concludes `failure`, and a failing required check blocks the merge.
 *
 * RESIDUAL, named rather than solved: this issuer is shared by every GitHub Actions workflow in
 * the repository, so anyone who can edit .github/workflows can post a passing check under it.
 */
const ENFORCING_ISSUER_APP_ID = GITHUB_ACTIONS_APP_ID;

/**
 * Extract required check context names from a classic branch-protection object.
 * Supports legacy `contexts: string[]` and modern `checks: { context }[]`.
 * Mirrors App observeProtection extraction (contexts || checks[].context), non-empty strings only.
 * @param {object|null} protection
 * @returns {string[]}
 */
function extractRequiredContexts(protection) {
  if (!protection || typeof protection !== 'object') return [];
  const rsc = protection.required_status_checks;
  if (!rsc || typeof rsc !== 'object') return [];
  // App observeProtection (quoted): contexts || checks[].context — empty contexts [] is
  // truthy and does NOT fall through to checks (same JS || discipline).
  const raw = rsc.contexts
    || (Array.isArray(rsc.checks)
      ? rsc.checks.map((c) => (c && c.context))
      : []);
  if (!Array.isArray(raw)) return [];
  return raw
    .map((c) => (c == null ? '' : String(c)))
    .filter(Boolean);
}

module.exports = {
  CHECK_NAME,
  GITHUB_ACTIONS_APP_ID,
  GITHUB_ACTIONS_APP_SLUG,
  ENFORCING_ISSUER_APP_ID,
  extractRequiredContexts,
};
