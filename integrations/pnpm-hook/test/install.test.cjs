// Real pnpm installation against an in-process loopback registry. All packages,
// tarballs and reports are synthetic, authored 2026-09-29, Apache-2.0. No internet.
'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { gzipSync } = require('node:zlib');
const { createHash } = require('node:crypto');
const { spawn } = require('node:child_process');

// One regular tar entry with a POSIX ustar header, enough for a package.json.
function tarball(manifest) {
  const data = Buffer.from(JSON.stringify(manifest));
  const header = Buffer.alloc(512);
  const field = (offset, length, value) => header.write(value, offset, length, 'ascii');
  field(0, 100, 'package/package.json');
  field(100, 8, '0000644\0');
  field(108, 8, '0000000\0');
  field(116, 8, '0000000\0');
  field(124, 12, data.length.toString(8).padStart(11, '0') + '\0');
  field(136, 12, '00000000000\0');
  field(148, 8, '        ');
  field(156, 1, '0');
  field(257, 6, 'ustar\0');
  field(263, 2, '00');
  const sum = header.reduce((total, byte) => total + byte, 0);
  field(148, 8, sum.toString(8).padStart(6, '0') + '\0 ');
  return gzipSync(Buffer.concat([header, data, Buffer.alloc((512 - data.length % 512) % 512), Buffer.alloc(1024)]));
}

function run(cli, args, cwd, mode) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cli, ...args], {
      cwd, shell: false, windowsHide: true,
      env: { ...process.env, CI: 'true', TRUSTDIFF_BIN: process.execPath, TRUSTDIFF_TEST_MODE: mode,
        TRUSTDIFF_TEST_RECORD: path.join(cwd, 'scans.jsonl'), COREPACK_ENABLE_NETWORK: '0',
        HTTP_PROXY: 'http://127.0.0.1:9', HTTPS_PROXY: 'http://127.0.0.1:9', NO_PROXY: '127.0.0.1,localhost',
        npm_config_userconfig: path.join(cwd, '.npmrc'), npm_config_registry: 'http://127.0.0.1:9',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let output = '';
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('pnpm fixture install timed out')); }, 45000);
    child.stdout.on('data', data => { output += data; });
    child.stderr.on('data', data => { output += data; });
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('close', code => { clearTimeout(timer); resolve({ code, output }); });
  });
}

test('real pnpm gates new, repeat and frozen installs, resolves aliases and transitive scoped packages', {
  skip: !process.env.PNPM_CLI && 'Set PNPM_CLI to the installed pnpm 10.33.2 bin/pnpm.cjs to run lifecycle tests.',
  timeout: 180000,
}, async () => {
  const cli = path.resolve(process.env.PNPM_CLI);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'trustdiff-pnpm-install-'));
  const manifests = {
    'real-target': { name: 'real-target', version: '1.0.0', dependencies: { '@fixture/leaf': '2.0.0' } },
    '@fixture/leaf': { name: '@fixture/leaf', version: '2.0.0' },
  };
  const tarballs = Object.fromEntries(Object.entries(manifests).map(([name, manifest]) => [name, tarball(manifest)]));
  let origin;
  const server = http.createServer((request, response) => {
    const pathname = decodeURIComponent(new URL(request.url, 'http://localhost').pathname).slice(1);
    if (pathname.startsWith('tarballs/')) {
      const name = pathname.slice('tarballs/'.length, -4);
      if (!tarballs[name]) { response.writeHead(404).end(); return; }
      response.writeHead(200, { 'content-type': 'application/octet-stream' }).end(tarballs[name]);
      return;
    }
    const manifest = manifests[pathname];
    if (!manifest) { response.writeHead(404).end(); return; }
    response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({
      name: manifest.name, 'dist-tags': { latest: manifest.version },
      versions: { [manifest.version]: { ...manifest, dist: {
        tarball: `${origin}/tarballs/${encodeURIComponent(manifest.name)}.tgz`,
        integrity: 'sha512-' + createHash('sha512').update(tarballs[pathname]).digest('base64'),
      } } },
    }));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
  function project(name, frozenLock) {
    const dir = path.join(root, name);
    fs.mkdirSync(dir);
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'fixture-project', version: '1.0.0', private: true,
      dependencies: { alias: 'npm:real-target@1.0.0' }, scripts: { postinstall: 'node installed.cjs' } }));
    fs.writeFileSync(path.join(dir, 'installed.cjs'), "require('node:fs').writeFileSync('lifecycle-ran', 'yes');");
    fs.copyFileSync(path.join(__dirname, '..', '.pnpmfile.cjs'), path.join(dir, '.pnpmfile.cjs'));
    fs.copyFileSync(path.join(__dirname, 'stub-check.cjs'), path.join(dir, 'check'));
    fs.writeFileSync(path.join(dir, '.npmrc'), `registry=${origin}\nstore-dir=${path.join(root, 'store').replaceAll('\\', '/')}\npackage-manager-strict=false\nmanage-package-manager-versions=false\nupdate-notifier=false\n`);
    if (frozenLock) fs.copyFileSync(frozenLock, path.join(dir, 'pnpm-lock.yaml'));
    return dir;
  }
  try {
    const version = await run(cli, ['--version'], root, 'clean');
    assert.equal(version.code, 0, version.output);
    assert.match(version.output, /^10\.33\.2\s*$/);
    const blocked = project('blocked');
    const denied = await run(cli, ['install', '--no-frozen-lockfile', '--registry', origin], blocked, 'block');
    assert.notEqual(denied.code, 0, denied.output);
    assert.match(denied.output, /install refused by trustdiff/);
    assert.equal(fs.existsSync(path.join(blocked, 'lifecycle-ran')), false);
    assert.equal(fs.existsSync(path.join(blocked, 'node_modules', 'alias')), false);

    const clean = project('clean');
    const allowed = await run(cli, ['install', '--no-frozen-lockfile', '--registry', origin], clean, 'clean');
    assert.equal(allowed.code, 0, allowed.output);
    assert.equal(fs.existsSync(path.join(clean, 'lifecycle-ran')), true);
    assert.equal(JSON.parse(fs.readFileSync(path.join(clean, 'node_modules', 'alias', 'package.json'))).name, 'real-target');
    const refs = fs.readFileSync(path.join(clean, 'scans.jsonl'), 'utf8').trim().split('\n').flatMap(line => JSON.parse(line).slice(3));
    assert.deepEqual([...new Set(refs)].sort(), ['npm:@fixture/leaf@2.0.0', 'npm:real-target@1.0.0']);

    fs.unlinkSync(path.join(clean, 'lifecycle-ran'));
    const repeated = await run(cli, ['install', '--registry', origin], clean, 'block');
    assert.notEqual(repeated.code, 0, repeated.output);
    assert.match(repeated.output, /install refused by trustdiff/);
    assert.equal(fs.existsSync(path.join(clean, 'lifecycle-ran')), false);

    const frozen = project('frozen', path.join(clean, 'pnpm-lock.yaml'));
    const frozenDenied = await run(cli, ['install', '--frozen-lockfile', '--registry', origin], frozen, 'block');
    assert.notEqual(frozenDenied.code, 0, frozenDenied.output);
    assert.match(frozenDenied.output, /install refused by trustdiff/);
    assert.equal(fs.existsSync(path.join(frozen, 'node_modules', 'alias')), false);
    assert.equal(fs.existsSync(path.join(frozen, 'lifecycle-ran')), false);

    const frozenClean = await run(cli, ['install', '--frozen-lockfile', '--registry', origin], frozen, 'clean');
    assert.equal(frozenClean.code, 0, frozenClean.output);
    assert.equal(fs.existsSync(path.join(frozen, 'lifecycle-ran')), true);
  } finally {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
    // root was generated by mkdtemp for this fixture only.
    fs.rmSync(root, { recursive: true, force: true });
  }
});
