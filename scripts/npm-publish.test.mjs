import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

// The executable PATH fixture uses a POSIX shebang, just like the Ubuntu job.
// Fail clearly on native Windows instead of silently skipping this coverage.
if (process.platform === 'win32') {
  throw new Error('Run these tests in Linux/WSL or Ubuntu GitHub Actions, not native Windows.');
}

const script = fileURLToPath(new URL('./npm-publish.mjs', import.meta.url));
const packageName = '@trustdiff/bun-scanner';
const packageVersion = '0.5.0';
const expectedQuery = [
  'view', packageName, 'versions', '--json', '--registry=https://registry.npmjs.org/',
];

function fixture(t) {
  const directory = mkdtempSync(join(tmpdir(), 'trustdiff-npm-publish-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const bin = join(directory, 'bin');
  mkdirSync(bin);
  writeFileSync(join(directory, 'package.json'), JSON.stringify({
    name: packageName,
    version: packageVersion,
  }));
  const callsFile = join(directory, 'npm-calls.jsonl');
  const outputFile = join(directory, 'github-output');
  const sentinel = join(directory, 'shell-executed');
  writeFileSync(join(bin, 'npm'), `#!/usr/bin/env node
const fs = require('node:fs');
fs.appendFileSync(process.env.NPM_STUB_CALLS, JSON.stringify(process.argv.slice(2)) + '\\n');
process.stdout.write(process.env.NPM_STUB_STDOUT || '');
process.stderr.write(process.env.NPM_STUB_STDERR || '');
process.exitCode = Number(process.env.NPM_STUB_STATUS || '0');
`, { mode: 0o755 });

  function run(mode = 'decide', overrides = {}) {
    const result = spawnSync(process.execPath, [script, mode], {
      cwd: directory,
      encoding: 'utf8',
      timeout: 10_000,
      env: {
        ...process.env,
        PATH: `${bin}${delimiter}${process.env.PATH || ''}`,
        GITHUB_REF_TYPE: 'tag',
        GITHUB_REF_NAME: 'v0.5.0',
        GITHUB_EVENT_NAME: 'push',
        GITHUB_OUTPUT: outputFile,
        NAME: packageName,
        VERSION: packageVersion,
        REASON: '',
        NPM_STUB_CALLS: callsFile,
        NPM_STUB_STDOUT: JSON.stringify(['0.4.0', '0.4.1']),
        NPM_STUB_STDERR: '',
        NPM_STUB_STATUS: '0',
        ...overrides,
      },
    });
    assert.equal(result.error, undefined, `CLI could not run: ${result.error}`);
    assert.equal(result.signal, null, `CLI was killed: ${result.stderr}`);
    const calls = existsSync(callsFile)
      ? readFileSync(callsFile, 'utf8').trim().split('\n').map(line => JSON.parse(line))
      : [];
    const outputs = existsSync(outputFile)
      ? Object.fromEntries(readFileSync(outputFile, 'utf8').trim().split('\n')
        .filter(Boolean).map(line => {
          const separator = line.indexOf('=');
          return [line.slice(0, separator), line.slice(separator + 1)];
        }))
      : {};
    return { ...result, calls, outputs };
  }
  return { run, sentinel };
}

function assertDecision(result, publish, reason, calls = [expectedQuery]) {
  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.deepEqual(result.outputs, {
    name: packageName,
    version: packageVersion,
    publish: String(publish),
    reason,
  });
  assert.deepEqual(result.calls, calls);
}

for (const tag of ['v0.5.2', 'v0.5.0-rc.1', 'v0.6.0-beta.1']) {
  test(`${tag} skips the unchanged stable scanner before any registry query`, t => {
    const result = fixture(t).run('decide', {
      GITHUB_REF_NAME: tag,
      // If queried, this response would fail. A mismatch must not depend on npm.
      NPM_STUB_STATUS: '1',
      NPM_STUB_STDOUT: 'unavailable registry',
    });
    assertDecision(result, false, 'tag-mismatch', []);
  });
}

test('matching tag stages a version missing from the public versions list', t => {
  assertDecision(fixture(t).run(), true, 'new');
});

test('matching tag skips a version already publicly published', t => {
  const result = fixture(t).run('decide', {
    NPM_STUB_STDOUT: JSON.stringify(['0.4.0', '0.4.1', '0.5.0']),
  });
  assertDecision(result, false, 'published');
});

for (const [version, publish, reason] of [
  ['0.4.0', true, 'new'],
  ['0.5.0', false, 'published'],
]) {
  test(`npm's single-version JSON string ${version} is accepted`, t => {
    assertDecision(fixture(t).run('decide', {
      NPM_STUB_STDOUT: JSON.stringify(version),
    }), publish, reason);
  });
}

test('structured npm E404 preserves the documented first-publish bootstrap skip', t => {
  const result = fixture(t).run('decide', {
    NPM_STUB_STATUS: '1',
    NPM_STUB_STDOUT: JSON.stringify({ error: {
      code: 'E404',
      summary: 'Not Found - GET https://registry.npmjs.org/@trustdiff%2fbun-scanner - Not found',
      detail: "'@trustdiff/bun-scanner@*' is not in this registry.",
    } }),
    NPM_STUB_STDERR: 'npm error code E404\nnpm error 404 Not Found\n',
  });
  assertDecision(result, false, 'absent');
  assert.match(result.stdout + result.stderr, /first version|by hand|bootstrap/i);
  assert.match(result.stdout + result.stderr, /docs\/releasing\.md/);
});

for (const [versions, publish, reason] of [
  [['0.4.0', '0.4.1'], true, 'new'],
  [['0.4.0', '0.5.0'], false, 'published'],
]) {
  test(`branch workflow_dispatch preserves the ${reason} recovery decision`, t => {
    assertDecision(fixture(t).run('decide', {
      GITHUB_EVENT_NAME: 'workflow_dispatch',
      GITHUB_REF_TYPE: 'branch',
      GITHUB_REF_NAME: 'main',
      NPM_STUB_STDOUT: JSON.stringify(versions),
    }), publish, reason);
  });
}

test('workflow_dispatch on a mismatched tag still skips without querying npm', t => {
  assertDecision(fixture(t).run('decide', {
    GITHUB_EVENT_NAME: 'workflow_dispatch',
    GITHUB_REF_TYPE: 'tag',
    GITHUB_REF_NAME: 'v0.5.2',
  }), false, 'tag-mismatch', []);
});

const registryFailures = [
  ...['E401', 'E403', 'ENEEDAUTH', 'ENOTFOUND', 'ECONNRESET', 'ETIMEDOUT', 'E500', 'E503']
    .map(code => [code, '1', JSON.stringify({ error: { code, summary: `Registry failure ${code}` } })]),
  ['malformed failure JSON', '1', '{'],
  ['empty failed response', '1', ''],
  ['unstructured E404 text', '1', 'npm error code E404'],
  ['nonzero exit despite a versions list', '1', JSON.stringify(['0.4.0'])],
  ['malformed success JSON', '0', '{'],
  ['empty successful response', '0', ''],
  ['empty versions array', '0', '[]'],
  ['null response', '0', 'null'],
  ['object instead of versions', '0', '{"versions":["0.4.0"]}'],
  ['numeric version entry', '0', '["0.4.0",42]'],
  ['empty version entry', '0', '["0.4.0",""]'],
  ['empty scalar version', '0', '""'],
  ['E404 object with successful exit', '0', '{"error":{"code":"E404"}}'],
];

for (const [description, status, stdout] of registryFailures) {
  test(`${description} fails explicitly without authorizing staging or a successful skip`, t => {
    const result = fixture(t).run('decide', {
      NPM_STUB_STATUS: status,
      NPM_STUB_STDOUT: stdout,
      NPM_STUB_STDERR: status === '1' ? `npm registry query failed: ${description}\n` : '',
    });
    assert.notEqual(result.status, 0, 'An inconclusive registry query must fail');
    assert.deepEqual(result.calls, [expectedQuery]);
    assert.equal(result.outputs.publish, undefined);
    assert.equal(result.outputs.reason, undefined);
    assert.match(result.stdout + result.stderr, /error|fail|invalid|unexpected|could not/i);
    assert.doesNotMatch(result.stdout + result.stderr, /nothing staged;|\bis staged\b/);
  });
}

test('an E404 mention in stderr cannot turn a structured E401 into a bootstrap skip', t => {
  const result = fixture(t).run('decide', {
    NPM_STUB_STATUS: '1',
    NPM_STUB_STDOUT: JSON.stringify({ error: { code: 'E401', summary: 'Unauthorized' } }),
    NPM_STUB_STDERR: 'npm error E401 Unauthorized; an E404 may indicate a missing package\n',
  });
  assert.notEqual(result.status, 0);
  assert.deepEqual(result.calls, [expectedQuery]);
  assert.equal(result.outputs.publish, undefined);
  assert.equal(result.outputs.reason, undefined);
  assert.match(result.stdout + result.stderr, /E401/);
});

for (const [reason, explanation] of [
  ['tag-mismatch', /tag|mismatch/i],
  ['absent', /does not exist|not .*registry|bootstrap|first version/i],
  ['published', /already published/i],
]) {
  test(`${reason} summary explains the skip without announcing staging success`, t => {
    const result = fixture(t).run('summary', {
      REASON: reason,
      GITHUB_REF_NAME: 'v0.5.2',
    });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /^nothing staged;/);
    assert.match(result.stdout, explanation);
    assert.doesNotMatch(result.stdout, /\bis staged\b|\bwas staged\b|\bis published\b/);
    assert.deepEqual(result.calls, []);
    if (reason === 'tag-mismatch') {
      assert.ok(result.stdout.includes('v0.5.2'));
      assert.ok(result.stdout.includes('0.5.0'));
    }
  });
}

test('new summary announces staging and explains the separate human approval', t => {
  const result = fixture(t).run('summary', { REASON: 'new' });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /@trustdiff\/bun-scanner@0\.5\.0 is staged/);
  assert.match(result.stdout, /npm stage list @trustdiff\/bun-scanner/);
  assert.match(result.stdout, /npm stage approve <stage-id>/);
  assert.doesNotMatch(result.stdout, /\bis published\b/);
  assert.deepEqual(result.calls, []);
});

for (const reason of ['', 'unexpected']) {
  test(`unknown summary reason ${JSON.stringify(reason)} cannot claim a successful staging`, t => {
    const result = fixture(t).run('summary', { REASON: reason });
    assert.doesNotMatch(result.stdout, /\bis staged\b|\bwas staged\b|\bis published\b/);
    assert.deepEqual(result.calls, []);
  });
}

test('tag and summary environment values remain literal instead of executing shell substitutions', t => {
  const f = fixture(t);
  const substitution = `$(touch ${f.sentinel})`;
  const mismatch = f.run('decide', { GITHUB_REF_NAME: `v0.5.2${substitution}` });
  assertDecision(mismatch, false, 'tag-mismatch', []);
  assert.equal(existsSync(f.sentinel), false);
  const summary = f.run('summary', { REASON: 'new', NAME: `@trustdiff/${substitution}` });
  assert.equal(summary.status, 0, summary.stderr);
  assert.ok(summary.stdout.includes(substitution));
  assert.equal(existsSync(f.sentinel), false);
  assert.deepEqual(summary.calls, []);
});
