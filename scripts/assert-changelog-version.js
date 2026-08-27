#!/usr/bin/env node
'use strict';

/**
 * CLI release gate (prepublishOnly): refuse to publish a version the CHANGELOG does not name.
 *
 * WHY THIS EXISTS — measured, not hypothetical. THIS package has the same disease: 9.7.0 and
 * 10.0.0 are published to npm with no CHANGELOG section at all, and 12.0.0 shipped while still
 * titled "Unreleased" (11.0.1 before it had to retitle a stale heading by hand). It was found in
 * the CLI first: on 2026-08-27 packages/cli/CHANGELOG.md listed
 * 4.10.0 and then "Unreleased", while npm carried 4.11.0, 4.12.0, 5.0.0 and 5.0.1. Four published
 * versions were undocumented and a fifth (5.0.0) was published while still labelled Unreleased.
 * Two distinct failure modes produced that, and BOTH are caught by the one check below:
 *
 *   1. The bump commit never touched the changelog at all. Measured: of the last eight CLI version
 *      bumps, four omitted it (4.11.0, 4.12.0, 4.13.0, 5.0.1) — and those four are exactly the
 *      versions that went missing. The correlation is not partial.
 *   2. The bump commit DID write the entry, but under "## Unreleased", and nobody retitled it at
 *      publish. Atomicity alone does not save you: @coderifts/agent-guard 12.0.0 was written
 *      atomically and still shipped as "Unreleased", and 11.0.1 before it had to retitle a stale
 *      heading by hand.
 *
 * So the invariant is NOT "the bump touched the changelog" — it is that the version being published
 * appears as its own heading. A human step that must be remembered at publish time is the step that
 * gets skipped; this makes it fail the publish instead.
 *
 * Dependency-free on purpose: a publish gate that needs an install to run is a gate that stops
 * running (same reasoning as assert-guard-major.js).
 */

const fs = require('fs');
const path = require('path');

const PKG_PATH = path.join(__dirname, '..', 'package.json');
const CHANGELOG_PATH = path.join(__dirname, '..', 'CHANGELOG.md');

function fail(msg) {
  console.error(`assert-changelog-version: FAIL — ${msg}`);
  process.exit(1);
}

/**
 * Headings this file recognises as "this version is documented".
 * A heading may carry a trailing note (e.g. "## 4.13.0 — never published"), so match the version
 * token at a word boundary rather than requiring the line to be exactly the version.
 */
function headingNamesVersion(line, version) {
  if (!/^##\s+/.test(line)) return false;
  const rest = line.replace(/^##\s+/, '').trim();
  const esc = version.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`^v?${esc}(\\b|$)`).test(rest);
}

function main() {
  if (!fs.existsSync(PKG_PATH)) fail(`package.json not found at ${PKG_PATH}`);
  if (!fs.existsSync(CHANGELOG_PATH)) fail(`CHANGELOG.md not found at ${CHANGELOG_PATH}`);

  let version;
  try {
    version = JSON.parse(fs.readFileSync(PKG_PATH, 'utf8')).version;
  } catch (err) {
    fail(`package.json is not readable JSON: ${err.message}`);
  }
  if (typeof version !== 'string' || !version.trim()) fail('package.json has no version string');

  const lines = fs.readFileSync(CHANGELOG_PATH, 'utf8').split('\n');
  const headings = lines.filter((l) => /^##\s+/.test(l));
  if (headings.length === 0) fail('CHANGELOG.md has no "## " headings at all');

  const match = headings.find((l) => headingNamesVersion(l, version));
  if (!match) {
    const listed = headings.slice(0, 4).map((h) => h.replace(/^##\s+/, '').trim());
    fail(
      `package.json is ${version} but CHANGELOG.md has no "## ${version}" heading.\n`
      + `  Top headings are: ${listed.join(' · ')}\n`
      + '  Publishing now is how a version goes undocumented. Retitle the Unreleased section to\n'
      + `  ${version}, or add its section, then publish.`,
    );
  }

  // "Unreleased" must never be the section that documents the version being published.
  if (/^##\s+unreleased\b/i.test(match)) {
    fail(`the section naming ${version} is the Unreleased heading — retitle it before publishing`);
  }

  console.log(`assert-changelog-version: OK — ${version} is documented ("${match.trim()}")`);
}

main();

module.exports = { headingNamesVersion, PKG_PATH, CHANGELOG_PATH };
