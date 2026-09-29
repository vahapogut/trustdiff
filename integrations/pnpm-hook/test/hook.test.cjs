'use strict';
const { test, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createHooks, planRefs, parseReport } = require('../.pnpmfile.cjs');

const pkg = () => ({ resolution: { integrity: 'sha512-fixture' } });
const lock = () => ({ lockfileVersion: '9.0', importers: { '.': { dependencies: { alias: 'real@1.2.3' } } }, packages: { 'real@1.2.3': pkg() } });
let root;
let previous;
beforeEach(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'trustdiff-pnpm-unit-'));
  fs.copyFileSync(path.join(__dirname, 'stub-check.cjs'), path.join(root, 'check'));
  previous = { ...process.env };
  process.env.TRUSTDIFF_BIN = process.execPath;
  delete process.env.TRUSTDIFF_PNPM_TIMEOUT_MS;
  delete process.env.TRUSTDIFF_TEST_MODE;
});
afterEach(() => {
  for (const key of Object.keys(process.env)) if (!(key in previous)) delete process.env[key];
  Object.assign(process.env, previous);
  // root is an exclusively owned mkdtemp path, never a user-provided path.
  fs.rmSync(root, { recursive: true, force: true });
});

test('registry aliases, scopes, peers, patches and duplicate versions use actual npm identity', () => {
  const input = lock();
  input.packages['@scope/lib@2.0.0(react@19.0.0)'] = pkg();
  input.packages['@scope/lib@2.0.0(react@18.0.0)'] = pkg();
  input.packages['other@3.0.0(patch_hash=abcdef)'] = pkg();
  input.packages['pre@1.2.3-beta.1+build.2'] = pkg();
  input.importers['.'].dependencies.scoped = '@scope/lib@2.0.0(react@19.0.0)';
  assert.deepEqual(planRefs(input).refs, ['npm:@scope/lib@2.0.0', 'npm:other@3.0.0', 'npm:pre@1.2.3-beta.1+build.2', 'npm:real@1.2.3']);
});

test('serialized v9 importer objects and snapshot edges resolve correctly', () => {
  const input = lock();
  input.importers['.'].dependencies.alias = { specifier: 'npm:real@^1', version: 'real@1.2.3' };
  input.snapshots = { 'real@1.2.3': { dependencies: { leaf: '2.3.4' } } };
  input.packages['leaf@2.3.4'] = pkg();
  assert.deepEqual(planRefs(input).refs, ['npm:leaf@2.3.4', 'npm:real@1.2.3']);
});

test('workspace links and injected local directories are explicit local exclusions', () => {
  const input = lock();
  input.importers['.'].dependencies.local = 'link:packages/local';
  input.packages['local@file:packages/local'] = { resolution: { type: 'directory', directory: 'packages/local' }, dependencies: { real: '1.2.3' } };
  assert.deepEqual(planRefs(input), { refs: ['npm:real@1.2.3'], local: 2 });
});

for (const key of ['evil@git+https://example.invalid/repo', 'evil@https://example.invalid/x.tgz', 'evil@file:../x.tgz', 'evil@latest', 'evil@^1.0.0', 'evil@1.0.0;echo bad', 'evil@1.0.0(x', '--flag@1.0.0', 'bad name@1.0.0']) {
  test(`refuses ambiguous or exotic package ${key}`, () => {
    const input = lock();
    input.packages[key] = { ...pkg(), name: 'innocent', version: '1.0.0' };
    assert.throws(() => planRefs(input), /cannot check/);
  });
}

test('resolution type cannot disguise git as a registry version', () => {
  const input = lock();
  input.packages['real@1.2.3'].resolution = { type: 'git', repo: 'x', commit: 'abc' };
  assert.throws(() => planRefs(input), /cannot check/);
});

for (const change of [
  input => { input.lockfileVersion = '6.0'; },
  input => { input.importers = null; },
  input => { input.packages = []; },
  input => { input.packages = {}; },
  input => { input.snapshots = { 'omitted@1.0.0': {} }; },
  input => { input.importers['.'].dependencies.alias = { specifier: '^1' }; },
]) {
  test('refuses incomplete or unsupported lockfile instead of skipping packages', () => {
    const input = lock();
    change(input);
    assert.throws(() => planRefs(input));
  });
}

test('empty tree returns the same object without requiring a binary', async () => {
  process.env.TRUSTDIFF_BIN = path.join(root, 'missing');
  const input = { lockfileVersion: 9, importers: { '.': {} } };
  assert.equal(await createHooks(root).afterAllResolved(input), input);
});

test('clean scan preserves the exact object and fixed argument contract', async () => {
  process.env.TRUSTDIFF_TEST_RECORD = path.join(root, 'args.jsonl');
  const input = lock();
  assert.equal(await createHooks(root).afterAllResolved(input), input);
  assert.deepEqual(JSON.parse(fs.readFileSync(process.env.TRUSTDIFF_TEST_RECORD, 'utf8')), ['--format', 'json', '--', 'npm:real@1.2.3']);
});

test('warning passes when policy permits warnings', async () => {
  process.env.TRUSTDIFF_TEST_MODE = 'warn';
  await createHooks(root).afterAllResolved(lock());
});

for (const [mode, pattern] of [
  ['block', /install refused/], ['block-exit-zero', /install refused/], ['warn-policy', /install refused/],
  ['data-unavailable', /install refused/], ['unchecked', /no checks completed/], ['omit', /omitted/],
  ['malformed', /JSON report/], ['failure', /exit 2.*synthetic failure/],
  ['overflow', /8 MiB/], ['stderr-overflow', /64 KiB/],
]) {
  test(`fails closed for ${mode}`, async () => {
    process.env.TRUSTDIFF_TEST_MODE = mode;
    await assert.rejects(createHooks(root).afterAllResolved(lock()), pattern);
  });
}

test('missing binary explains installation and TRUSTDIFF_BIN', async () => {
  process.env.TRUSTDIFF_BIN = path.join(root, 'missing');
  await assert.rejects(createHooks(root).afterAllResolved(lock()), /Install trustdiff separately.*TRUSTDIFF_BIN/);
});

test('timeout kills the child and refuses the install', async () => {
  process.env.TRUSTDIFF_TEST_MODE = 'timeout';
  process.env.TRUSTDIFF_PNPM_TIMEOUT_MS = '100';
  await assert.rejects(createHooks(root).afterAllResolved(lock()), /timed out/);
});

for (const value of ['0', '-1', 'abc', '10.5', '2147483648']) {
  test(`invalid timeout ${value} is a configuration error`, async () => {
    process.env.TRUSTDIFF_PNPM_TIMEOUT_MS = value;
    await assert.rejects(createHooks(root).afterAllResolved(lock()), /positive whole number/);
  });
}

test('large trees are bounded batches and every package is asked exactly once', async () => {
  process.env.TRUSTDIFF_TEST_RECORD = path.join(root, 'args.jsonl');
  const input = { lockfileVersion: 9, importers: { '.': {} }, packages: {} };
  for (let i = 0; i < 205; i++) input.packages[`pkg-${i}@1.0.0`] = pkg();
  await createHooks(root).afterAllResolved(input);
  const batches = fs.readFileSync(process.env.TRUSTDIFF_TEST_RECORD, 'utf8').trim().split('\n').map(JSON.parse);
  assert.deepEqual(batches.map(batch => batch.length - 3), [100, 100, 5]);
  assert.equal(new Set(batches.flatMap(batch => batch.slice(3))).size, 205);
});

test('preResolution scans wanted lockfile even when afterAllResolved will be skipped', async () => {
  process.env.TRUSTDIFF_TEST_MODE = 'block';
  await assert.rejects(createHooks(root).preResolution({ existsNonEmptyWantedLockfile: true, wantedLockfile: lock(), lockfileDir: root }), /install refused/);
  await createHooks(root).preResolution({ existsNonEmptyWantedLockfile: false });
});

test('report validation refuses wrong identity, duplicate, exit mismatch and malformed fields', () => {
  const refs = ['npm:real@1.2.3'];
  const ref = { ecosystem: 'npm', name: 'real', version: '1.2.3' };
  const report = () => ({ schema: 'trustdiff.report/1', subjects: [{ ref, evaluated: ['TD002'], findings: [], skipped: [], verdict: 'ok' }], summary: { subjects: 1, exit_code: 0 } });
  for (const change of [
    doc => { doc.subjects[0].ref = { ...ref, ecosystem: 'pypi' }; },
    doc => { doc.subjects.push(doc.subjects[0]); },
    doc => { doc.summary.exit_code = 1; },
    doc => { delete doc.subjects[0].evaluated; },
    doc => { doc.subjects[0].findings = [null]; },
    doc => { doc.subjects[0].skipped = [null]; },
    doc => { doc.summary.subjects = 0; },
  ]) {
    const doc = report();
    change(doc);
    assert.throws(() => parseReport(JSON.stringify(doc), refs, 0));
  }
});
