// Copyright 2026 Abdulvahap Ogut. SPDX-License-Identifier: Apache-2.0
// Copy this complete file beside pnpm-lock.yaml. No npm package is required.
// Verified 2026-09-29 against https://pnpm.io/10.x/pnpmfile and pnpm v10.33.2:
// pkg-manager/core/src/install/index.ts and lockfile/types/src/index.ts.
// afterAllResolved is NOT called by headless/frozen installs. preResolution
// therefore checks the existing wanted lockfile too, without weakening frozen mode.
// Both hooks see pnpm's internal v9 object, with peers in packages keys; the
// serialized v9 form has a separate snapshots map. Both shapes are accepted.
'use strict';

const { spawn } = require('node:child_process');
const path = require('node:path');

const PREFIX = 'trustdiff pnpm hook: ';
const MAX_OUTPUT = 8 * 1024 * 1024;
const MAX_STDERR = 64 * 1024;
const VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const NAME = /^(?:@[A-Za-z0-9][A-Za-z0-9._-]*\/)?[A-Za-z0-9][A-Za-z0-9._-]*$/;
const CHECK = /^[A-Z]+[0-9]{3}$/;
const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const fail = message => { throw new Error(PREFIX + message); };
// JSON-escape terminal controls so registry text cannot hide diagnostics.
const printable = value => JSON.stringify(String(value)).slice(1, -1);

function packageRef(key) {
  const bare = key.split('(')[0];
  const at = bare.lastIndexOf('@');
  const name = bare.slice(0, at);
  const version = bare.slice(at + 1);
  if (at <= 0 || name.length > 214 || !NAME.test(name) || !VERSION.test(version)) return null;
  // Reject malformed peer suffixes instead of treating an arbitrary tail as a peer.
  const suffix = key.slice(bare.length);
  let depth = 0;
  for (const char of suffix) {
    if (char === '(') depth++;
    else if (char === ')') { if (--depth < 0) return null; }
    else if (depth === 0 || /[\s\x00-\x1f\x7f]/.test(char)) return null;
  }
  return depth === 0 ? `npm:${name}@${version}` : null;
}

function planRefs(lockfile) {
  if (!isObject(lockfile) || !/^9(?:\.0)?$/.test(String(lockfile.lockfileVersion))) {
    fail('expected a pnpm v9 lockfile (pnpm 10). Upgrade this hook before using another lockfile format.');
  }
  if (!isObject(lockfile.importers) || (lockfile.packages !== undefined && !isObject(lockfile.packages))) {
    fail('invalid lockfile: importers and packages must be objects.');
  }
  const packages = lockfile.packages || {};
  const refs = new Set();
  const keys = new Set(Object.keys(packages));
  let local = 0;
  for (const [key, pkg] of Object.entries(packages)) {
    if (!isObject(pkg) || !isObject(pkg.resolution)) fail(`invalid resolution for ${printable(key)}.`);
    if (pkg.resolution.type === 'directory' && typeof pkg.resolution.directory === 'string') {
      local++;
      continue;
    }
    const ref = packageRef(key);
    // Never turn a git/tarball package's self-declared name and version into a
    // public npm identity. That would check completely different code.
    if (!ref || pkg.resolution.type !== undefined || pkg.resolution.repo !== undefined) {
      fail(`cannot check non-registry or unresolved dependency ${printable(key)}. Git, URL and tarball dependencies need a separate review; they are not public npm releases.`);
    }
    refs.add(ref);
  }
  // Validate graph edges too: a missing packages entry must not become a pass.
  const snapshots = lockfile.snapshots;
  if (snapshots !== undefined && !isObject(snapshots)) fail('invalid snapshots map.');
  for (const key of Object.keys(snapshots || {})) {
    if (!keys.has(key) && !keys.has(key.split('(')[0])) fail(`no package resolution for snapshot ${printable(key)}.`);
  }
  for (const item of [...Object.values(lockfile.importers), ...Object.values(packages), ...Object.values(snapshots || {})]) {
    if (!isObject(item)) fail('invalid lockfile dependency entry.');
    for (const field of ['dependencies', 'devDependencies', 'optionalDependencies']) {
      if (item[field] === undefined) continue;
      if (!isObject(item[field])) fail(`invalid ${field} map.`);
      for (const [alias, value] of Object.entries(item[field])) {
        const resolved = isObject(value) ? value.version : value;
        if (typeof resolved !== 'string') fail(`missing resolved version for ${printable(alias)}.`);
        if (resolved.startsWith('link:')) { local++; continue; }
        const candidate = VERSION.test(resolved.split('(')[0]) ? `${alias}@${resolved}` : resolved.replace(/^npm:/, '');
        if (!keys.has(candidate) && !keys.has(candidate.split('(')[0])) {
          fail(`no package resolution for ${printable(alias)} (${printable(resolved)}).`);
        }
      }
    }
  }
  return { refs: [...refs].sort(), local };
}

function parseReport(stdout, refs, exitCode) {
  let report;
  try { report = JSON.parse(stdout); } catch { fail('the binary did not write a JSON report.'); }
  if (!isObject(report) || report.schema !== 'trustdiff.report/1' || !Array.isArray(report.subjects) ||
      !isObject(report.summary) || ![0, 1, 3].includes(exitCode) || report.summary.exit_code !== exitCode) {
    fail('invalid report schema or inconsistent exit code. Use a compatible trustdiff binary.');
  }
  const pending = new Set(refs);
  const notes = [];
  let blocked = exitCode !== 0;
  let partialSkips = 0;
  for (const subject of report.subjects) {
    if (!isObject(subject) || !isObject(subject.ref)) fail('invalid subject in report.');
    const ref = `${subject.ref.ecosystem}:${subject.ref.name}@${subject.ref.version}`;
    if (!pending.delete(ref)) fail(`unexpected or duplicate subject ${printable(ref)}.`);
    if (!Array.isArray(subject.evaluated) || !subject.evaluated.every(id => typeof id === 'string' && CHECK.test(id)) ||
        !Array.isArray(subject.skipped) || !subject.skipped.every(skip => isObject(skip) && CHECK.test(skip.check) && typeof skip.reason === 'string') ||
        !Array.isArray(subject.findings) || !['ok', 'info', 'warn', 'block', 'skipped'].includes(subject.verdict)) {
      fail(`invalid evaluation details for ${printable(ref)}.`);
    }
    if (subject.evaluated.length === 0 || subject.verdict === 'skipped') {
      fail(`no checks completed for ${printable(ref)}; an unchecked package cannot pass the install gate.`);
    }
    partialSkips += subject.skipped.length;
    if (subject.verdict === 'block') blocked = true;
    for (const finding of subject.findings) {
      if (!isObject(finding) || !CHECK.test(finding.id) || typeof finding.name !== 'string' ||
          !['info', 'warn', 'block'].includes(finding.level) || typeof finding.title !== 'string' ||
          typeof finding.explanation !== 'string' || !isObject(finding.ref) ||
          `${finding.ref.ecosystem}:${finding.ref.name}@${finding.ref.version}` !== ref) {
        fail(`invalid finding for ${printable(ref)}.`);
      }
      if (finding.level === 'block') blocked = true;
      if (finding.level !== 'info') notes.push(`${finding.level} ${finding.id} ${ref}: ${finding.title}. ${finding.explanation}`);
    }
  }
  if (pending.size) fail(`report omitted ${pending.size} requested package(s), starting with ${printable([...pending][0])}.`);
  if (report.summary.subjects !== refs.length) fail('report subject count does not match the requested packages.');
  return { blocked, partialSkips, notes };
}

function configuration(env) {
  const text = env.TRUSTDIFF_PNPM_TIMEOUT_MS || '120000';
  if (!/^[1-9]\d*$/.test(text) || !Number.isSafeInteger(Number(text)) || Number(text) > 2147483647) {
    fail('TRUSTDIFF_PNPM_TIMEOUT_MS must be a positive whole number no larger than 2147483647.');
  }
  return { binary: env.TRUSTDIFF_BIN || 'trustdiff', timeout: Number(text) };
}

function runCheck(refs, config, cwd) {
  return new Promise((resolve, reject) => {
    let child;
    let timer;
    let stopTimer;
    let aborted;
    let settled = false;
    let stdoutSize = 0;
    let stderrSize = 0;
    const stdout = [];
    const stderr = [];
    const finish = (error, result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearTimeout(stopTimer);
      if (error) {
        child?.kill('SIGKILL');
        child?.stdout?.destroy();
        child?.stderr?.destroy();
        child?.unref();
        reject(new Error(PREFIX + error));
      }
      else resolve(result);
    };
    const abort = error => {
      if (settled || aborted) return;
      aborted = error;
      clearTimeout(timer);
      child.kill('SIGKILL');
      // Normally close arrives immediately. Keep a bound even if a replacement
      // executable leaked its output handles to another process.
      stopTimer = setTimeout(() => finish(error), 1000);
    };
    try {
      child = spawn(config.binary, ['check', '--format', 'json', '--', ...refs], {
        cwd, shell: false, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch (error) { finish(`could not start the binary: ${error.message}`); return; }
    timer = setTimeout(() => abort(`scan timed out after ${config.timeout} ms; install refused.`), config.timeout);
    child.on('error', error => finish(error.code === 'ENOENT'
      ? `binary ${printable(config.binary)} was not found. Install trustdiff separately (https://github.com/vahapogut/trustdiff#install), or set TRUSTDIFF_BIN to its executable path.`
      : `could not run the binary: ${printable(error.message)}.`));
    child.stdout.on('data', chunk => {
      stdoutSize += chunk.length;
      if (stdoutSize > MAX_OUTPUT) abort('report exceeded the 8 MiB output limit; install refused.');
      else if (!settled && !aborted) stdout.push(chunk);
    });
    child.stderr.on('data', chunk => {
      stderrSize += chunk.length;
      if (stderrSize > MAX_STDERR) abort('diagnostics exceeded the 64 KiB output limit; install refused.');
      else if (!settled && !aborted) stderr.push(chunk);
    });
    child.on('close', (code, signal) => {
      if (settled) return;
      if (aborted) { finish(aborted); return; }
      if (signal || ![0, 1, 3].includes(code)) {
        finish(`binary failed (${signal || `exit ${code}`}): ${printable(Buffer.concat(stderr).toString('utf8').slice(0, 2000))}`);
        return;
      }
      finish(null, { stdout: Buffer.concat(stdout).toString('utf8'), code });
    });
  });
}

async function scan(lockfile, cwd) {
  const config = configuration(process.env);
  const { refs, local } = planRefs(lockfile);
  if (local) console.error(PREFIX + `${local} local link/directory entries are outside registry checks; their locked registry dependencies are included.`);
  let offset = 0;
  while (offset < refs.length) {
    const batch = [];
    let chars = 0;
    while (offset < refs.length && batch.length < 100 && chars + refs[offset].length < 8000) {
      chars += refs[offset].length + 1;
      batch.push(refs[offset++]);
    }
    if (!batch.length) fail('a package reference exceeds the command line limit.');
    const result = await runCheck(batch, config, cwd);
    const parsed = parseReport(result.stdout, batch, result.code);
    for (const note of parsed.notes) console.error(PREFIX + printable(note));
    if (parsed.partialSkips) console.error(PREFIX + `${parsed.partialSkips} checks were skipped; see trustdiff check for details.`);
    if (parsed.blocked) fail(`install refused by trustdiff (exit ${result.code}). Resolve the finding or required data source failure before retrying.`);
  }
}

function createHooks(root = __dirname) {
  return {
    async preResolution(options) {
      // Always scan the wanted lockfile, including repeat and frozen installs.
      // A later full resolution is checked again by afterAllResolved.
      if (options.existsNonEmptyWantedLockfile) await scan(options.wantedLockfile, options.lockfileDir || root);
    },
    async afterAllResolved(lockfile) {
      await scan(lockfile, path.resolve(root));
      return lockfile;
    },
  };
}

module.exports = { hooks: createHooks(), createHooks, planRefs, parseReport };
