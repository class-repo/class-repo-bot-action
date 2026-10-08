'use strict';
// job-example.json is a real protocol 2 job produced by the ClassRepo server (class-repo-site, server/test/fixtures),
// with a test-only roster key. The server's tests prove it still produces exactly this shape; this proves the bot accepts
// and carries out that example. If either side changes the protocol, one of the two fails.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const run = require('../scripts/provision');
const { setup } = require('./helpers');
const example = require('./job-example.json');

const exercise = t => run({ github: t.github, context: t.context, core: t.core, env: t.env, deps: t.deps });

test('the job the server really produces is accepted and carried out', async () => {
  const t = setup({ job: example.job, privateKeyPem: example.rosterPrivateKeyPem, githubOverrides: { logins: { 1001: 'alice-gh' } } });
  await exercise(t);
  assert.deepEqual(t.logs.filter(l => l.startsWith('FAILED') || l.startsWith('error')), []);
  assert.deepEqual(t.calls.map(c => c.slice(0, 2)), [
    ['lookup', 1001], ['create', 'lab1-alice-gh'], ['topics', 'lab1-alice-gh'], ['invite', 'alice-gh'], ['actions', 'lab1-alice-gh'], ['badge', 'lab1-alice-gh'],
  ]);
  assert.deepEqual(t.calls.find(c => c[0] === 'actions'), ['actions', 'lab1-alice-gh', false]);
  assert.deepEqual(t.calls.find(c => c[0] === 'invite'), ['invite', 'alice-gh', 'push']);
  const reported = t.requests.filter(r => r.url.endsWith('/results')).flatMap(r => r.body.results);
  assert.deepEqual(reported, [{ index: 0, status: 'ready' }]);
  const roster = fs.readFileSync(path.join(t.tmpDir, 'logs_generated', 'alice-gh.txt'), 'utf8');
  assert.match(roster, /name: Alice Smith/);
  assert.match(roster, /email: alice@univ.edu/);
});

test('a job example with a feature the bot does not know is refused whole (so a newer server cannot be half-obeyed)', async () => {
  const job = JSON.parse(JSON.stringify(example.job));
  job.repos[0].settings.snapshot_tag = true;
  const t = setup({ job, privateKeyPem: example.rosterPrivateKeyPem });
  await exercise(t);
  assert.deepEqual(t.calls, []);
  assert.ok(t.logs.some(l => /feature this bot does not have/.test(l)));
});
