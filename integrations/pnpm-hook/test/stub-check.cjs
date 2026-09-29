// Synthetic trustdiff process fixture. Invoked as `node check --format json -- refs`.
// Source: authored for this repository, 2026-09-29. Apache-2.0. No network.
'use strict';
const fs = require('node:fs');
const args = process.argv.slice(2);
if (JSON.stringify(args.slice(0, 3)) !== JSON.stringify(['--format', 'json', '--'])) process.exit(99);
if (process.env.TRUSTDIFF_TEST_RECORD) fs.appendFileSync(process.env.TRUSTDIFF_TEST_RECORD, JSON.stringify(args) + '\n');
const mode = process.env.TRUSTDIFF_TEST_MODE;
if (mode === 'timeout') { setInterval(() => {}, 1000); }
else if (mode === 'overflow') { process.stdout.write('x'.repeat(8 * 1024 * 1024 + 1)); }
else if (mode === 'stderr-overflow') { process.stderr.write('x'.repeat(64 * 1024 + 1)); }
else if (mode === 'failure') { process.stderr.write('synthetic failure'); process.exitCode = 2; }
else if (mode === 'malformed') { process.stdout.write('{no'); }
else {
  const code = ['block', 'warn-policy'].includes(mode) ? 1 : mode === 'data-unavailable' ? 3 : 0;
  const subjects = args.slice(3).map(text => {
    const at = text.lastIndexOf('@');
    const ref = { ecosystem: 'npm', name: text.slice(4, at), version: text.slice(at + 1) };
    const level = mode === 'block' || mode === 'block-exit-zero' ? 'block' : ['warn', 'warn-policy'].includes(mode) ? 'warn' : 'info';
    const findings = ['block', 'block-exit-zero', 'warn', 'warn-policy'].includes(mode)
      ? [{ id: 'TD002', name: 'publisher-changed', level, ref, title: 'Fixture finding', explanation: 'Synthetic publisher changed.' }] : [];
    return { ref, evaluated: mode === 'unchecked' ? [] : ['TD002'], skipped: [], findings, verdict: mode === 'unchecked' ? 'skipped' : findings.length ? level : 'ok' };
  });
  if (mode === 'omit') subjects.pop();
  process.stdout.write(JSON.stringify({ schema: 'trustdiff.report/1', subjects, summary: { subjects: subjects.length, exit_code: code } }));
  process.exitCode = code;
}
