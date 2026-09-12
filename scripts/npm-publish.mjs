// Used by npm-publish.yml from integrations/bun-scanner. Tests replace npm on PATH.
import { spawnSync } from 'node:child_process';
import { appendFileSync, readFileSync } from 'node:fs';

function output(values) {
  for (const [key, value] of Object.entries(values)) {
    appendFileSync(process.env.GITHUB_OUTPUT, `${key}=${value}\n`);
  }
}

function decide() {
  const { name, version } = JSON.parse(readFileSync('package.json', 'utf8'));
  output({ name, version });
  console.log(`${name} in this checkout is ${version}`);

  // CLI-only releases (including prereleases) must not restage an older scanner.
  // A manual dispatch on a branch still recovers the version in that checkout.
  if (process.env.GITHUB_REF_TYPE === 'tag' && `v${version}` !== process.env.GITHUB_REF_NAME) {
    output({ publish: false, reason: 'tag-mismatch' });
    console.log(`::notice::nothing staged; tag ${process.env.GITHUB_REF_NAME} does not match scanner v${version}`);
    return;
  }

  // Public versions only: npm view cannot tell us whether a stage is pending.
  // One successful list avoids treating an exact-version lookup failure as new.
  const result = spawnSync('npm', [
    'view', name, 'versions', '--json', '--registry=https://registry.npmjs.org/',
  ], { encoding: 'utf8' });
  if (result.stderr) process.stderr.write(result.stderr);
  if (result.error) throw result.error;
  if (result.signal) throw new Error(`npm view terminated by ${result.signal}`);

  let data;
  try {
    data = JSON.parse(result.stdout);
  } catch {
    throw new Error(`npm view returned invalid JSON (exit ${result.status}); check registry connectivity and authentication`);
  }
  if (result.status !== 0) {
    // npm's structured E404 is the only bootstrap skip. Auth, transport and
    // server errors must stay failures, even when stderr happens to mention 404.
    if (data?.error?.code === 'E404') {
      output({ publish: false, reason: 'absent' });
      console.log(`::notice::${name} is absent from the public registry; publish the first version by hand: docs/releasing.md section 9`);
      return;
    }
    throw new Error(`npm view failed (exit ${result.status}, ${data?.error?.code ?? 'unknown error'}); check registry connectivity and authentication`);
  }

  const versions = typeof data === 'string' ? [data] : data;
  if (!Array.isArray(versions) || versions.length === 0 ||
      versions.some(value => typeof value !== 'string' || value.length === 0)) {
    throw new Error('npm view returned an invalid public version list; refusing to stage');
  }
  const published = versions.includes(version);
  output({ publish: !published, reason: published ? 'published' : 'new' });
  if (published) console.log(`::notice::${name}@${version} is already published; nothing to stage`);
}

function summary() {
  const { NAME: name, VERSION: version, REASON: reason, GITHUB_REF_NAME: ref } = process.env;
  switch (reason) {
    case 'tag-mismatch':
      console.log(`nothing staged; tag ${ref} does not match scanner v${version}`);
      return;
    case 'absent':
      console.log(`nothing staged; ${name} does not exist on the public registry yet (bootstrap required: docs/releasing.md section 9)`);
      return;
    case 'published':
      console.log(`nothing staged; ${name}@${version} is already published`);
      return;
    case 'new':
      console.log(`::notice::${name}@${version} is staged and nobody can install it yet.`);
      console.log('Approve it to make it public:');
      console.log(`  npm stage list ${name}`);
      console.log('  npm stage download <stage-id>   # read what this job built');
      console.log('  npm stage approve <stage-id>    # asks for a one time password');
      console.log('The package page on npmjs.com does the same through a form.');
      return;
    default:
      console.log('nothing staged; the run did not get as far as deciding');
  }
}

try {
  switch (process.argv[2]) {
    case 'decide': decide(); break;
    case 'summary': summary(); break;
    default: throw new Error('usage: node scripts/npm-publish.mjs <decide|summary>');
  }
} catch (error) {
  console.error(`::error::${error.message}`);
  process.exitCode = 1;
}
