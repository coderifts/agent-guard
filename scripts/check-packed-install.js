#!/usr/bin/env node
'use strict';

/**
 * Pack → install the tarball into a temp dir → require the documented entry.
 *
 * Pattern (1413 / prove check-packed-sample.js): the working tree is not the
 * artifact. `files` decides what ships. So: `npm pack`, install THAT tarball,
 * then run the documented smoke (README: `import { guardToolCall } from
 * '@coderifts/agent-guard'`). Exit 0 = the published tarball installs clean
 * and its entrypoint loads.
 */

const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const REPO = path.join(__dirname, '..');
const PKG = require(path.join(REPO, 'package.json'));

function run(cmd, args, opts) {
  const r = spawnSync(cmd, args, { encoding: 'utf8', ...opts });
  if (r.error) throw r.error;
  return r;
}

function fail(msg) {
  process.stderr.write(`FAIL: ${msg}\n`);
  process.exit(1);
}

const distMain = path.join(REPO, 'dist', 'cjs', 'index.js');
if (!fs.existsSync(distMain)) {
  fail(`dist/cjs/index.js is missing — run npm run build before packing. `
    + 'A tarball without dist cannot load.');
}

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'guard-pack-'));
try {
  const packed = run('npm', ['pack', '--silent', '--pack-destination', tmp], { cwd: REPO });
  if (packed.status !== 0) fail(`npm pack failed:\n${packed.stderr}`);
  const tgz = packed.stdout.trim().split('\n').pop().trim();
  const tarball = path.join(tmp, path.basename(tgz));
  if (!fs.existsSync(tarball)) fail(`npm pack reported ${tgz} but no tarball is there`);
  process.stdout.write(`tarball              : ${path.basename(tarball)} `
    + `(${fs.statSync(tarball).size} bytes)\n`);

  const installDir = path.join(tmp, 'install');
  fs.mkdirSync(installDir);
  const init = run('npm', ['init', '-y'], { cwd: installDir });
  if (init.status !== 0) fail(`npm init failed:\n${init.stderr}`);
  const inst = run('npm', ['install', tarball], { cwd: installDir });
  if (inst.status !== 0) fail(`npm install tarball failed:\n${inst.stderr}`);

  // Documented install is `npm install @coderifts/agent-guard @coderifts/sdk`.
  // npm 7+ may already have pulled the peer; if not, install it explicitly.
  const peerDir = path.join(installDir, 'node_modules', '@coderifts', 'sdk');
  if (!fs.existsSync(peerDir) && PKG.peerDependencies && PKG.peerDependencies['@coderifts/sdk']) {
    const peer = run('npm', ['install', `@coderifts/sdk@${PKG.peerDependencies['@coderifts/sdk']}`], {
      cwd: installDir,
    });
    if (peer.status !== 0) fail(`npm install peer @coderifts/sdk failed:\n${peer.stderr}`);
  }

  const smoke = run(process.execPath, ['-e',
    "const g = require('@coderifts/agent-guard');\n"
    + "if (typeof g.guardToolCall !== 'function') throw new Error('guardToolCall missing');\n"
    + "if (typeof g.withCodeRifts !== 'function') throw new Error('withCodeRifts missing');\n"
    + "process.stdout.write('ok require @coderifts/agent-guard guardToolCall,withCodeRifts\\n');\n",
  ], { cwd: installDir });
  process.stdout.write(smoke.stdout);
  if (smoke.status !== 0) fail(`documented require failed:\n${smoke.stderr}`);
  process.stdout.write('packed install smoke: OK\n');
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}
