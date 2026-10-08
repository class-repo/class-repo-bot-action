'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const run = require('../scripts/provision');
const { seal, setup, SENSITIVE, BATCH, TEMPLATE, SOURCE, SNAPSHOT } = require('./helpers');
const { generateRosterKeyPair } = require('../scripts/roster-crypto');
const vector = require('./vector.json');

// One repository entry of a protocol 2 job. `who` is a sealed record's contents.
const repoEntry = (pair, who, { sync_key = null, permission = 'push', settings = {}, more = [] } = {}) => ({
  sync_key,
  collaborators: [{ sealed: seal(pair.publicKeyB64, who), permission }, ...more.map(m => ({ sealed: seal(pair.publicKeyB64, m.who), permission: m.permission || 'push' }))],
  settings,
});

const baseJob = (pair, extra = {}) => ({
  protocol: 3, mode: 'ensure_repos', template: TEMPLATE, assignment_name: 'lab1', target_owner: 'cs101-org', shortcode: 'abc123xyz',
  repos: [
    repoEntry(pair, { github: 'alice-gh', name: 'Alice Smith', email: 'alice@univ.edu' }, { sync_key: 'k1' }),
    repoEntry(pair, { github: 'bob-gh', name: 'Bob Jones', email: 'bob@univ.edu' }),
  ],
  ...extra,
});

const oneRepo = (pair, who, opts, extra = {}) => ({ ...baseJob(pair), repos: [repoEntry(pair, who, { sync_key: 'k1', ...opts })], ...extra });
const ALICE = { github: 'alice-gh', name: 'Alice Smith', email: 'alice@univ.edu' };

const exercise = (t) => run({ github: t.github, context: t.context, core: t.core, env: t.env, deps: t.deps });
const results = t => t.requests.filter(r => r.url.endsWith('/results')).flatMap(r => r.body.results);
const failedLines = t => t.logs.filter(l => l.startsWith('FAILED'));
const githubWrites = t => t.calls.filter(c => c[0] !== 'lookup');

// ------------------------------------------------------------------------------------------------ the normal flow

test('creates a private repo per student, labels it, invites them with push access, and reports results by position', async () => {
  const pair = generateRosterKeyPair();
  const t = setup({ job: baseJob(pair), privateKeyPem: pair.privateKeyPem });
  await exercise(t);
  assert.deepEqual(t.calls, [
    ['create', 'lab1-alice-gh', true], ['topics', 'lab1-alice-gh', ['classrepo']], ['invite', 'alice-gh', 'push'],
    ['create', 'lab1-bob-gh', true], ['topics', 'lab1-bob-gh', ['classrepo']], ['invite', 'bob-gh', 'push'],
  ]);
  assert.deepEqual(results(t), [{ index: 0, status: 'ready' }]); // bob is a bulk row: nobody is waiting
  assert.deepEqual(failedLines(t), []);
});

test('says which bot it is when it claims the job, so the server only asks for what it supports', async () => {
  const pair = generateRosterKeyPair();
  const t = setup({ job: baseJob(pair), privateKeyPem: pair.privateKeyPem });
  await exercise(t);
  const claim = t.requests.find(r => r.url.endsWith('/claim')).body.bot;
  assert.match(claim.version, /^\d+\.\d+\.\d+$/);
  assert.deepEqual(claim.protocols, [3]);
  for (const c of ['ensure_repos', 'snapshot', 'setup_keys', 'permission:push', 'permission:pull', 'setting:archived', 'marker:topic']) assert.ok(claim.capabilities.includes(c), c);
  assert.ok(!claim.capabilities.some(c => /admin|delete|public|maintain/.test(c)));
});

test('authenticates every server call with an OIDC token for the server origin', async () => {
  const pair = generateRosterKeyPair();
  const t = setup({ job: baseJob(pair), privateKeyPem: pair.privateKeyPem });
  await exercise(t);
  assert.ok(t.requests.length >= 2);
  for (const r of t.requests) {
    assert.equal(r.auth, 'Bearer oidc-for-https://api.classrepo.org');
    assert.match(r.url, new RegExp(`^https://api.classrepo.org/api/batch/${BATCH}/`));
  }
});

test('NEVER logs anything identifying (the repo may be public)', async () => {
  const pair = generateRosterKeyPair();
  const t = setup({ job: baseJob(pair), privateKeyPem: pair.privateKeyPem,
    githubOverrides: { invite: async ({ username }) => { if (username === 'bob-gh') { const e = new Error(`boom for bob-gh at cs101-org/lab1-bob-gh`); e.status = 422; throw e; } } } });
  const printed = [];
  const origLog = console.log; console.log = (...a) => printed.push(a.join(' '));
  try { await exercise(t); } finally { console.log = origLog; }
  const everything = [...t.logs, ...printed].join('\n');
  for (const s of SENSITIVE) assert.ok(!everything.includes(s), `log leaked ${JSON.stringify(s)}:\n${everything}`);
  assert.match(everything, /repository 1 of 2: done/);
  assert.match(everything, /repository 2 of 2: The repository exists, but sending the invitation failed/);
});

test('masks sensitive values as secrets', async () => {
  const pair = generateRosterKeyPair();
  const t = setup({ job: baseJob(pair), privateKeyPem: pair.privateKeyPem });
  await exercise(t);
  for (const s of [TEMPLATE, 'lab1', 'cs101-org', 'abc123xyz', 'alice-gh', 'Alice Smith', 'alice@univ.edu']) assert.ok(t.secrets.includes(s), `${s} not masked`);
});

test('failures are reported generically and fail the job without identities', async () => {
  const pair = generateRosterKeyPair();
  const t = setup({ job: baseJob(pair), privateKeyPem: pair.privateKeyPem, githubOverrides: { create: async () => { const e = new Error('nope'); e.status = 404; throw e; } } });
  await exercise(t);
  assert.deepEqual(results(t), [{ index: 0, status: 'failed', error: 'Could not create the repository from the template (HTTP 404).' }]);
  assert.deepEqual(failedLines(t), ['FAILED: 2 of 2 repositories failed.']);
});

test('a record sealed to a different key fails that repository only', async () => {
  const pair = generateRosterKeyPair();
  const other = generateRosterKeyPair();
  const job = baseJob(pair);
  job.repos[0] = repoEntry(other, ALICE, { sync_key: 'k1' });
  const t = setup({ job, privateKeyPem: pair.privateKeyPem });
  await exercise(t);
  assert.equal(results(t)[0].status, 'failed');
  assert.deepEqual(t.calls.map(c => c[0]), ['create', 'topics', 'invite']);
  assert.ok(t.calls.every(c => !JSON.stringify(c).includes('alice')));
});

// ------------------------------------------------------------------------------------------------ the rules the bot enforces itself

test('only ever creates private repositories, and never deletes or changes visibility (any other GitHub call would throw)', async () => {
  const pair = generateRosterKeyPair();
  const t = setup({ job: oneRepo(pair, ALICE, { settings: { actions_enabled: true, codespaces_badge: true, archived: true } }), privateKeyPem: pair.privateKeyPem });
  await exercise(t);
  assert.deepEqual(failedLines(t), []);
  assert.ok(t.calls.filter(c => c[0] === 'create').every(c => c[2] === true));
});

test('never grants more than push: any other permission refuses the whole job before GitHub is touched', async () => {
  const pair = generateRosterKeyPair();
  for (const permission of ['admin', 'maintain', 'triage', 'write', 'owner', '']) {
    const t = setup({ job: oneRepo(pair, ALICE, { permission }), privateKeyPem: pair.privateKeyPem });
    await exercise(t);
    assert.deepEqual(t.calls, [], `permission ${JSON.stringify(permission)} reached GitHub`);
    assert.match(failedLines(t)[0], /never grants/);
  }
});

test('allows read-only access (end of term) with the same job shape', async () => {
  const pair = generateRosterKeyPair();
  const t = setup({ job: oneRepo(pair, ALICE, { permission: 'pull' }), privateKeyPem: pair.privateKeyPem, existing: { 'lab1-alice-gh': { topics: ['classrepo'], archived: false } } });
  await exercise(t);
  assert.deepEqual(t.calls, [['invite', 'alice-gh', 'pull']]);
});

test('leaves alone an existing repository that merely has a matching name (a compromised server cannot point the bot at your other repos)', async () => {
  const pair = generateRosterKeyPair();
  const t = setup({ job: oneRepo(pair, ALICE), privateKeyPem: pair.privateKeyPem,
    existing: { 'lab1-alice-gh': { topics: ['internal'], archived: false, private: true, template_repository: null } } });
  await exercise(t);
  assert.deepEqual(t.calls, [], 'must not invite anyone, label, or change anything');
  assert.deepEqual(results(t), [{ index: 0, status: 'failed', error: 'A repository with that name already exists and was not created by ClassRepo, so it was left alone.' }]);
});

test('also leaves alone a lookalike generated from a DIFFERENT template', async () => {
  const pair = generateRosterKeyPair();
  const t = setup({ job: oneRepo(pair, ALICE), privateKeyPem: pair.privateKeyPem,
    existing: { 'lab1-alice-gh': { topics: [], archived: false, template_repository: { full_name: 'someone/else' } } } });
  await exercise(t);
  assert.deepEqual(t.calls, []);
  assert.equal(results(t)[0].status, 'failed');
});

test('recognises repositories made before labelling existed (generated from this template) and labels them', async () => {
  const pair = generateRosterKeyPair();
  const t = setup({ job: oneRepo(pair, ALICE), privateKeyPem: pair.privateKeyPem,
    existing: { 'lab1-alice-gh': { topics: ['python'], archived: false, template_repository: { full_name: 'CS101-ORG/' + SNAPSHOT.toUpperCase() } } } });
  await exercise(t);
  assert.deepEqual(t.calls, [['topics', 'lab1-alice-gh', ['python', 'classrepo']], ['invite', 'alice-gh', 'push']]);
  assert.deepEqual(results(t), [{ index: 0, status: 'ready' }]);
});

test('running the same job twice is harmless: the second run only re-applies what is wanted', async () => {
  const pair = generateRosterKeyPair();
  const job = oneRepo(pair, ALICE, { settings: { actions_enabled: false } });
  const t = setup({ job, privateKeyPem: pair.privateKeyPem });
  await exercise(t);
  const afterFirst = t.calls.length;
  await exercise(t);
  const second = t.calls.slice(afterFirst);
  assert.ok(!second.some(c => c[0] === 'create'), 'must not create again');
  assert.ok(!second.some(c => c[0] === 'topics'), 'must not relabel');
  assert.deepEqual(second, [['invite', 'alice-gh', 'push'], ['actions', 'lab1-alice-gh', false]]);
});

test('a failure to label a new repository is only a warning, and the next run still recognises it', async () => {
  const pair = generateRosterKeyPair();
  const t = setup({ job: oneRepo(pair, ALICE), privateKeyPem: pair.privateKeyPem, githubOverrides: { topics: async () => { throw new Error('no'); } } });
  await exercise(t);
  assert.deepEqual(results(t), [{ index: 0, status: 'ready' }]);
  assert.ok(t.logs.some(l => l.startsWith('warning: Could not label')));
  await exercise(t); // generated from this template, so still recognised
  assert.equal(results(t).at(-1).status, 'ready');
});

// ------------------------------------------------------------------------------------------------ settings

test('settings are applied only when present: actions on, off, or untouched', async () => {
  const pair = generateRosterKeyPair();
  for (const [settings, expected] of [[{ actions_enabled: false }, [['actions', 'lab1-alice-gh', false]]], [{ actions_enabled: true }, [['actions', 'lab1-alice-gh', true]]], [{}, []]]) {
    const t = setup({ job: oneRepo(pair, ALICE, { settings }), privateKeyPem: pair.privateKeyPem });
    await exercise(t);
    assert.deepEqual(t.calls.filter(c => c[0] === 'actions'), expected);
  }
});

test('adds the Codespaces badge only when asked', async () => {
  const pair = generateRosterKeyPair();
  const on = setup({ job: oneRepo(pair, ALICE, { settings: { codespaces_badge: true } }), privateKeyPem: pair.privateKeyPem });
  await exercise(on);
  assert.deepEqual(on.calls.filter(c => c[0] === 'badge'), [['badge', 'lab1-alice-gh']]);
  const off = setup({ job: oneRepo(pair, ALICE), privateKeyPem: pair.privateKeyPem });
  await exercise(off);
  assert.deepEqual(off.calls.filter(c => c[0] === 'badge'), []);
});

test('a failure to change a setting is a generic warning, not a failed student, and leaks nothing', async () => {
  const pair = generateRosterKeyPair();
  const t = setup({ job: oneRepo(pair, ALICE, { settings: { actions_enabled: false } }), privateKeyPem: pair.privateKeyPem,
    githubOverrides: { actions: async () => { throw new Error('forbidden for alice-gh'); } } });
  await exercise(t);
  assert.deepEqual(results(t), [{ index: 0, status: 'ready' }]);
  assert.ok(t.logs.some(l => l.startsWith('warning: Could not change the GitHub Actions setting')));
  assert.ok(!t.logs.join('\n').includes('alice-gh'));
  assert.deepEqual(failedLines(t), []);
});

test('archiving happens last, after the collaborators are set', async () => {
  const pair = generateRosterKeyPair();
  const t = setup({ job: oneRepo(pair, ALICE, { permission: 'pull', settings: { archived: true } }), privateKeyPem: pair.privateKeyPem, existing: { 'lab1-alice-gh': { topics: ['classrepo'], archived: false } } });
  await exercise(t);
  assert.deepEqual(t.calls, [['invite', 'alice-gh', 'pull'], ['archived', 'lab1-alice-gh', true]]);
});

test('an already-archived repository is left as it is when archiving is asked for, and reopened only when asked', async () => {
  const pair = generateRosterKeyPair();
  const existing = () => ({ 'lab1-alice-gh': { topics: ['classrepo'], archived: true } });
  const keep = setup({ job: oneRepo(pair, ALICE, { settings: { archived: true } }), privateKeyPem: pair.privateKeyPem, existing: existing() });
  await exercise(keep);
  assert.deepEqual(keep.calls.filter(c => c[0] !== 'lookup'), []);
  assert.equal(results(keep)[0].status, 'ready');

  const reopen = setup({ job: oneRepo(pair, ALICE, { settings: { archived: false } }), privateKeyPem: pair.privateKeyPem, existing: existing() });
  await exercise(reopen);
  assert.deepEqual(reopen.calls, [['archived', 'lab1-alice-gh', false], ['invite', 'alice-gh', 'push']]);

  const silent = setup({ job: oneRepo(pair, ALICE), privateKeyPem: pair.privateKeyPem, existing: existing() });
  await exercise(silent);
  assert.deepEqual(silent.calls, []);
  assert.equal(results(silent)[0].error, 'This repository has been archived.');
});

test('several collaborators: all are invited with their own permission, and the repository is named after the first', async () => {
  const pair = generateRosterKeyPair();
  const job = oneRepo(pair, { github: 'zed', name: 'Z', email: 'z@x' }, { more: [{ who: { github: 'amy', name: 'A', email: 'a@x' }, permission: 'pull' }, { who: { github: 'bo', name: 'B', email: 'b@x' } }] });
  const t = setup({ job, privateKeyPem: pair.privateKeyPem });
  await exercise(t);
  assert.deepEqual(t.calls.filter(c => c[0] === 'create'), [['create', 'lab1-zed', true]]);
  assert.deepEqual(t.calls.filter(c => c[0] === 'invite'), [['invite', 'zed', 'push'], ['invite', 'amy', 'pull'], ['invite', 'bo', 'push']]);
  assert.deepEqual(fs.readdirSync(path.join(t.tmpDir, 'logs_generated')).sort(), ['amy.txt', 'bo.txt', 'zed.txt']);
});

// ------------------------------------------------------------------------------------------------ versions: refuse what we do not understand

test('a job from a newer protocol is refused as a whole, and the waiting students are told the bot needs updating', async () => {
  const pair = generateRosterKeyPair();
  const t = setup({ job: baseJob(pair, { protocol: 4 }), privateKeyPem: pair.privateKeyPem });
  await exercise(t);
  assert.deepEqual(t.calls, []);
  assert.match(failedLines(t)[0], /protocol 4.*Update the bot/);
  assert.deepEqual(results(t), [{ index: 0, status: 'failed', error: "Your instructor's ClassRepo bot needs updating, so this could not be done. Please let them know." }]);
});

test('a job using a setting or field this bot does not know is refused before anything is done (never half-done)', async () => {
  const pair = generateRosterKeyPair();
  for (const mutate of [r => { r.settings.snapshot_tag = true; }, r => { r.nickname = 'x'; }]) {
    const job = oneRepo(pair, ALICE);
    mutate(job.repos[0]);
    const t = setup({ job, privateKeyPem: pair.privateKeyPem });
    await exercise(t);
    assert.deepEqual(t.calls, []);
    assert.match(failedLines(t)[0], /feature this bot does not have/);
    assert.equal(results(t)[0].status, 'failed');
  }
});

test('refuses empty jobs, oversized jobs and malformed settings', async () => {
  const pair = generateRosterKeyPair();
  const tooMany = { ...baseJob(pair), repos: Array.from({ length: 201 }, () => ({ collaborators: [{ sealed: 'x', permission: 'push' }] })) };
  for (const job of [{ ...baseJob(pair), repos: [] }, tooMany, oneRepo(pair, ALICE, { settings: { archived: 'yes' } })]) {
    const t = setup({ job, privateKeyPem: pair.privateKeyPem });
    await exercise(t);
    assert.deepEqual(t.calls, []);
    assert.equal(failedLines(t).length, 1);
  }
});

test('an unknown job type fails clearly and the old student_join type is not accepted', async () => {
  const pair = generateRosterKeyPair();
  for (const mode of ['something-else', 'student_join']) {
    const t = setup({ job: { ...baseJob(pair), mode }, privateKeyPem: pair.privateKeyPem });
    await exercise(t);
    assert.deepEqual(t.calls, []);
    assert.match(failedLines(t)[0], /not supported by this version of the bot/);
  }
});

// ------------------------------------------------------------------------------------------------ job-level checks (unchanged rules)

test('rejects invalid job fields before touching GitHub', async () => {
  const pair = generateRosterKeyPair();
  for (const bad of [{ assignment_name: '../x' }, { template: 'not a template' }, { target_owner: 'a/b' }]) {
    const t = setup({ job: baseJob(pair, bad), privateKeyPem: pair.privateKeyPem });
    await exercise(t);
    assert.deepEqual(t.calls, []);
    assert.deepEqual(failedLines(t), ['FAILED: The job contains invalid names.']);
  }
});

test('stops cleanly if the server refuses the claim or the batch id is bad', async () => {
  const pair = generateRosterKeyPair();
  const refused = setup({ job: baseJob(pair), privateKeyPem: pair.privateKeyPem, serverStatus: 403 });
  await exercise(refused);
  assert.deepEqual(failedLines(refused), ['FAILED: Could not fetch the job from the ClassRepo server (HTTP 403).']);
  assert.deepEqual(refused.calls, []);

  const bad = setup({ job: baseJob(pair), privateKeyPem: pair.privateKeyPem });
  bad.env.BATCH_ID = '../../etc';
  await exercise(bad);
  assert.equal(bad.requests.length, 0);
});

test('refuses an http server url', async () => {
  const pair = generateRosterKeyPair();
  const t = setup({ job: baseJob(pair), privateKeyPem: pair.privateKeyPem });
  t.env.SERVER_URL = 'http://api.classrepo.org';
  t.deps.allowHttp = false;
  await exercise(t);
  assert.equal(t.requests.length, 0);
});

test('fails with guidance when no roster key secret exists yet', async () => {
  const pair = generateRosterKeyPair();
  const t = setup({ job: baseJob(pair), privateKeyPem: '' });
  await exercise(t);
  assert.match(failedLines(t)[0], /Turn on the encrypted roster/);
  assert.deepEqual(t.calls, []);
});

// ------------------------------------------------------------------------------------------------ roster

test('records the roster only in a private tracking repo, with markdown-safe cells', async () => {
  const pair = generateRosterKeyPair();
  const job = baseJob(pair);
  job.repos[0] = repoEntry(pair, { github: 'alice-gh', name: 'Al | <b>x</b> [link](http://evil)\nnewline', email: 'alice@univ.edu' }, { sync_key: 'k1' });
  const t = setup({ job, privateKeyPem: pair.privateKeyPem });
  let readme = '';
  t.deps.execFile = (cmd, args, opts) => {
    t.exec.push({ cmd, args, opts });
    if (args[0] === 'clone') fs.mkdirSync(args[args.length - 1], { recursive: true });
    if (args[0] === 'add') readme = fs.readFileSync(path.join(opts.cwd, 'logs', 'lab1', 'README.md'), 'utf8');
  };
  await exercise(t);
  assert.ok(t.exec.some(e => e.args[0] === 'push'));
  assert.ok(!t.exec.some(e => JSON.stringify(e.args).includes('ghs_executor') && e.args[0] !== 'clone'));
  assert.match(readme, /\[@alice-gh\]\(https:\/\/github.com\/alice-gh\)/);
  assert.ok(!readme.includes('<b>'), 'html must be escaped');
  assert.ok(readme.includes('\\[link\\](http://evil)'), 'brackets must be escaped so it renders as text, not a link');
  assert.equal(readme.split('\n').filter(l => l.startsWith('| [@')).length, 2);
});

test('does not record the roster when the tracking repo is public', async () => {
  const pair = generateRosterKeyPair();
  const t = setup({ job: baseJob(pair), privateKeyPem: pair.privateKeyPem });
  const originalGet = t.github.rest.repos.get;
  t.github.rest.repos.get = async a => a.repo === 'class-repo-tracking' ? { data: { private: false } } : originalGet(a);
  await exercise(t);
  assert.equal(t.exec.length, 0);
  assert.ok(t.logs.some(l => l.includes('tracking repository is public')));
});

// ------------------------------------------------------------------------------------------------ setup_keys

test('setup_keys stores the private key as a secret and sends only the public key', async () => {
  const t = setup({ job: { mode: 'setup_keys' }, privateKeyPem: '' });
  await exercise(t);
  const gh = t.exec.find(e => e.cmd === 'gh');
  assert.deepEqual(gh.args, ['secret', 'set', 'CLASSREPO_ROSTER_PRIVATE_KEY', '--repo', 'cs101-org/class-repo-bot']);
  assert.match(gh.opts.input, /BEGIN PRIVATE KEY/);
  assert.equal(gh.opts.env.GH_TOKEN, 'ghs_executor');
  const reg = t.requests.find(r => r.url.endsWith('/roster-key'));
  assert.deepEqual(Object.keys(reg.body), ['public_key']);
  assert.ok(!JSON.stringify(t.requests.filter(r => r.url.endsWith('/roster-key'))).includes('PRIVATE KEY'));
  assert.ok(!t.logs.join('\n').includes('PRIVATE KEY'));
  assert.ok(t.secrets.some(s => s.includes('BEGIN PRIVATE KEY')), 'private key must be masked');
});

test('setup_keys also introduces the bot, so the server knows its version straight after setup', async () => {
  const t = setup({ job: { mode: 'setup_keys' }, privateKeyPem: '' });
  await exercise(t);
  assert.deepEqual(t.requests.find(r => r.url.endsWith('/claim')).body.bot.protocols, [3]);
});

test('setup_keys fails clearly if the secret cannot be stored, and does not register a key', async () => {
  const t = setup({ job: { mode: 'setup_keys' }, privateKeyPem: '', execFile: () => { throw new Error('gh failed'); } });
  await exercise(t);
  assert.match(failedLines(t)[0], /Secrets permission/);
  assert.ok(!t.requests.some(r => r.url.endsWith('/roster-key')));
});

// ------------------------------------------------------------------------------------------------ identity by account id

const idJob = (pair, records) => ({ ...baseJob(pair), repos: records.map((r, i) => repoEntry(pair, r, { sync_key: `k${i}` })) });

test('the checked-in interop vector is also accepted by the workflow path', async () => {
  const job = { ...baseJob({ publicKeyB64: vector.publicKeyB64 }), repos: [{ sync_key: null, collaborators: [{ sealed: vector.sealed, permission: 'push' }], settings: {} }] };
  const t = setup({ job, privateKeyPem: vector.privateKeyPem });
  await exercise(t);
  assert.deepEqual(t.calls.map(c => c.slice(0, 2)), [['create', 'lab1-alice-example'], ['topics', 'lab1-alice-example'], ['invite', 'alice-example']]);
});

test('uses the handle the account has now, so a renamed student is still invited', async () => {
  const pair = generateRosterKeyPair();
  const t = setup({ job: idJob(pair, [{ github_id: 77, github: 'old-name', name: 'Rena Med', email: 'rena@univ.edu' }]),
    privateKeyPem: pair.privateKeyPem, githubOverrides: { logins: { 77: 'new-name' } } });
  await exercise(t);
  assert.deepEqual(t.calls.map(c => c.slice(0, 2)), [['lookup', 77], ['create', 'lab1-new-name'], ['topics', 'lab1-new-name'], ['invite', 'new-name']]);
  assert.deepEqual(results(t), [{ index: 0, status: 'ready' }]);
  const roster = fs.readFileSync(path.join(t.tmpDir, 'logs_generated', 'new-name.txt'), 'utf8');
  assert.match(roster, /github_id: 77/);
  assert.match(roster, /github_handle: new-name/);
  assert.match(roster, /permission: push/);
  const everything = t.logs.join('\n');
  for (const s of ['old-name', 'new-name', 'Rena Med', 'rena@univ.edu']) assert.ok(!everything.includes(s), `leaked ${s}`);
});

test('a recycled handle never reaches the wrong person: the account id decides', async () => {
  const pair = generateRosterKeyPair();
  const t = setup({ job: idJob(pair, [{ github_id: 77, github: 'taken-handle', name: 'A', email: 'a@x' }]),
    privateKeyPem: pair.privateKeyPem, githubOverrides: { logins: { 77: 'alice-new' } } });
  await exercise(t);
  assert.ok(t.calls.some(c => c[0] === 'invite' && c[1] === 'alice-new'));
  assert.ok(!t.calls.some(c => JSON.stringify(c).includes('taken-handle')));
});

test('an account that no longer exists is reported generically and creates nothing', async () => {
  const pair = generateRosterKeyPair();
  const t = setup({ job: idJob(pair, [{ github_id: 5, github: 'gone', name: 'G', email: 'g@x' }]), privateKeyPem: pair.privateKeyPem,
    githubOverrides: { lookup: async () => { const e = new Error('nf'); e.status = 404; throw e; } } });
  await exercise(t);
  assert.deepEqual(t.calls, [['lookup', 5]]);
  assert.deepEqual(results(t), [{ index: 0, status: 'failed', error: 'That GitHub account no longer exists.' }]);
  assert.ok(!t.logs.join('\n').includes('gone'));
});

test('a lookup that returns something that is not a handle is refused', async () => {
  const pair = generateRosterKeyPair();
  const t = setup({ job: idJob(pair, [{ github_id: 5, github: 'x', name: 'G', email: 'g@x' }]), privateKeyPem: pair.privateKeyPem,
    githubOverrides: { lookup: async () => ({ data: { login: '../../etc' } }) } });
  await exercise(t);
  assert.deepEqual(t.calls, [['lookup', 5]]);
  assert.equal(results(t)[0].status, 'failed');
});

// ---------------------------------------------------------------------------------- waiting for GitHub's template copy

test('waits for GitHub to finish copying the template before labelling, inviting or writing anything into the repository', async () => {
  const pair = generateRosterKeyPair();
  const t = setup({ job: oneRepo(pair, ALICE, { settings: { codespaces_badge: true } }), privateKeyPem: pair.privateKeyPem, githubOverrides: { copyPending: 3 } });
  await exercise(t);
  assert.equal(t.looks.length, 4, 'looks until the files appear');
  assert.equal(t.sleeps.length, 3, 'pauses between looks');
  // Every look happened when the only thing done so far was asking GitHub to create the repository.
  assert.deepEqual(t.looks, [1, 1, 1, 1], `nothing else is written until the copy is done: ${JSON.stringify(t.calls)}`);
  assert.ok(['topics', 'invite', 'badge'].every(n => t.calls.some(c => c[0] === n)), 'and then it does all of it');
  assert.equal(failedLines(t).length, 0);
});

test('gives up with a clear message if GitHub never finishes the copy, and invites nobody', async () => {
  const pair = generateRosterKeyPair();
  const t = setup({ job: oneRepo(pair, ALICE, { settings: { codespaces_badge: true } }), privateKeyPem: pair.privateKeyPem, githubOverrides: { copyPending: 1000 } });
  await exercise(t);
  assert.deepEqual(results(t).map(r => [r.status, /still copying/.test(r.error)]), [['failed', true]]);
  assert.equal(t.calls.filter(c => ['topics', 'invite', 'badge'].includes(c[0])).length, 0);
});

// ---------------------------------------------------------------------------------------------------------- snapshots

const snapshotJob = (extra = {}) => ({ protocol: 3, mode: 'snapshot', template: SOURCE, assignment_name: SNAPSHOT, target_owner: 'cs101-org', shortcode: 'abc123xyz', ...extra });
const snapshotRun = (job, overrides = {}, existing) => setup({ job, privateKeyPem: '', githubOverrides: { creatingSnapshot: true, ...overrides }, existing });

test('a snapshot copies the starter into a private repository, labels it as ClassRepo\'s, and marks it as a template', async () => {
  let created;
  const t = snapshotRun(snapshotJob(), { create: a => { created = a; } });
  await exercise(t);
  assert.deepEqual(t.calls, [['create', SNAPSHOT, true], ['topics', SNAPSHOT, ['classrepo', 'classrepo-snapshot']], ['template', SNAPSHOT, true]]);
  assert.deepEqual([created.template_owner, created.template_repo, created.owner, created.private], ['cs101', 'starter', 'cs101-org', true]);
  assert.deepEqual(results(t), [{ index: 0, status: 'ready' }]);
  assert.deepEqual(failedLines(t), []);
  assert.ok(!t.logs.some(l => l.includes(SOURCE)), 'the starter\'s name is not logged');
});

test('running a snapshot twice reuses the copy and does not copy again', async () => {
  const t = snapshotRun(snapshotJob(), {}, { [SNAPSHOT]: { topics: ['classrepo', 'classrepo-snapshot'], archived: false } });
  await exercise(t);
  assert.equal(t.calls.filter(c => c[0] === 'create').length, 0);
  assert.deepEqual(results(t), [{ index: 0, status: 'ready' }]);
});

test('a snapshot never takes over a repository that merely has the same name', async () => {
  const t = snapshotRun(snapshotJob(), {}, { [SNAPSHOT]: { topics: ['mine'], archived: false } });
  await exercise(t);
  assert.deepEqual(t.calls, []);
  assert.deepEqual(results(t), [{ index: 0, status: 'failed', code: 'name_taken' }]);
});

test('a snapshot only ever uses the reserved name, and refuses anything extra', async () => {
  for (const extra of [{ assignment_name: 'lab1' }, { assignment_name: '../x' }, { template: 'not a template' }, { target_owner: 'a/b' }, { delete_after: true }]) {
    const t = snapshotRun(snapshotJob(extra));
    await exercise(t);
    assert.deepEqual(t.calls, [], JSON.stringify(extra));
    assert.deepEqual(results(t), [{ index: 0, status: 'failed', code: 'invalid_job' }]);
  }
});

test('the optional allow-list of template owners applies to what a snapshot is copied from', async () => {
  const blocked = snapshotRun(snapshotJob());
  blocked.env.ALLOWED_TEMPLATE_OWNERS = 'someone-else, another';
  await exercise(blocked);
  assert.deepEqual(blocked.calls, []);
  assert.deepEqual(results(blocked), [{ index: 0, status: 'failed', code: 'owner_not_allowed' }]);
  const ok = snapshotRun(snapshotJob());
  ok.env.ALLOWED_TEMPLATE_OWNERS = 'CS101';
  await exercise(ok);
  assert.deepEqual(results(ok), [{ index: 0, status: 'ready' }]);
});

test('a snapshot reports failure, and does not mark anything as a template, if GitHub cannot copy', async () => {
  const t = snapshotRun(snapshotJob(), { create: () => { const e = new Error('x'); e.status = 404; throw e; } });
  await exercise(t);
  assert.ok(!t.calls.some(c => c[0] === 'template'));
  assert.deepEqual(results(t), [{ index: 0, status: 'failed', code: 'copy_failed', http: 404 }]);
});

test('students\' repositories are only generated from a snapshot this bot made in the target account', async () => {
  const pair = generateRosterKeyPair();
  for (const template of [SOURCE, 'cs101-org/starter', `other-org/${SNAPSHOT}`, `cs101-org/${SNAPSHOT}/x`]) {
    const t = setup({ job: oneRepo(pair, ALICE, {}, { template }), privateKeyPem: pair.privateKeyPem });
    await exercise(t);
    assert.deepEqual(githubWrites(t), [], template);
    assert.deepEqual(results(t).map(r => r.status), ['failed'], template);
  }
});

test('and only if that repository really carries the snapshot label', async () => {
  const pair = generateRosterKeyPair();
  const t = setup({ job: oneRepo(pair, ALICE), privateKeyPem: pair.privateKeyPem, githubOverrides: { noSnapshot: true } });
  await exercise(t);
  assert.deepEqual(githubWrites(t), []);
  assert.deepEqual(results(t).map(r => r.status), ['failed']);
});

// ----------------------------------------------------------------------------------------------- instructions link

test('puts the instructions link above the Codespaces badge in the README, once', async () => {
  const pair = generateRosterKeyPair();
  const url = 'https://example.edu/cs101/lab1?x=1&y=2#top';
  const t = setup({ job: oneRepo(pair, ALICE, { settings: { instructions_url: url, codespaces_badge: true } }), privateKeyPem: pair.privateKeyPem });
  await exercise(t);
  const readme = t.readmes['lab1-alice-gh'];
  assert.ok(readme.startsWith(`**[Assignment instructions](${url})**\n\n[![Open in GitHub Codespaces]`), readme);
  assert.equal(failedLines(t).length, 0);
});

test('an instructions link alone works too, and a link that is already there is not added again', async () => {
  const pair = generateRosterKeyPair();
  const url = 'https://example.edu/lab1';
  const t = setup({ job: oneRepo(pair, ALICE, { settings: { instructions_url: url } }), privateKeyPem: pair.privateKeyPem });
  await exercise(t);
  assert.equal(t.readmes['lab1-alice-gh'], `**[Assignment instructions](${url})**\n`);
});

test('an instructions link that is not a plain https address refuses the whole job before anything is done', async () => {
  const pair = generateRosterKeyPair();
  for (const bad of ['http://example.edu/x', 'javascript:alert(1)', 'https://example.edu/a b', 'https://example.edu/x)[y](https://evil.example', 'https://example.edu/<script>', 'https://x.edu/"', 42, `https://example.edu/${'a'.repeat(400)}`]) {
    const t = setup({ job: oneRepo(pair, ALICE, { settings: { instructions_url: bad } }), privateKeyPem: pair.privateKeyPem });
    await exercise(t);
    assert.deepEqual(t.calls, [], String(bad));
    assert.equal(failedLines(t).length, 1, String(bad));
  }
});

test('a repository with the snapshot\'s name but without ClassRepo\'s snapshot label is not used', async () => {
  const pair = generateRosterKeyPair();
  const t = setup({ job: oneRepo(pair, ALICE), privateKeyPem: pair.privateKeyPem, githubOverrides: { snapshotTopics: ['classrepo'] } });
  await exercise(t);
  assert.deepEqual(githubWrites(t), []);
  assert.deepEqual(results(t).map(r => r.status), ['failed']);
});

test('a snapshot that GitHub never finishes copying is reported as a timeout, with only a code', async () => {
  const t = snapshotRun(snapshotJob(), { copyPending: 1000 });
  await exercise(t);
  assert.deepEqual(results(t), [{ index: 0, status: 'failed', code: 'copy_timeout' }]);
  assert.ok(!t.calls.some(c => c[0] === 'template'));
});

test('nothing but a code from the fixed list and a status number ever travels back about a snapshot failure', async () => {
  const t = snapshotRun(snapshotJob(), { create: () => { const e = new Error('Resource not accessible: cs101/starter is private for cs101-org'); e.status = 403; throw e; } });
  await exercise(t);
  const [report] = results(t);
  assert.deepEqual(Object.keys(report).sort(), ['code', 'http', 'index', 'status']);
  assert.ok(!JSON.stringify(report).includes('cs101'));
});

// ------------------------------------------------------------------------------------------ the roster repository

const trackingCalls = t => t.calls.filter(c => c[1] === 'class-repo-tracking');

test('creates a missing roster repository from the fixed template, private, with Actions off before anything is written', async () => {
  const pair = generateRosterKeyPair();
  let created;
  const t = setup({ job: baseJob(pair), privateKeyPem: pair.privateKeyPem, githubOverrides: { noTracking: true, create: a => { if (a.name === 'class-repo-tracking') created = a; } } });
  const order = [];
  t.deps.execFile = (cmd, args, opts) => { order.push(`git ${args[0]}`); if (args[0] === 'clone') fs.mkdirSync(args[args.length - 1], { recursive: true }); };
  const originalActions = t.github.rest.actions.setGithubActionsPermissionsRepository;
  t.github.rest.actions.setGithubActionsPermissionsRepository = async a => { if (a.repo === 'class-repo-tracking') order.push('actions off'); return originalActions(a); };
  await exercise(t);
  assert.deepEqual([created.template_owner, created.template_repo, created.owner, created.private], ['class-repo', 'class-repo-tracking-template', 'cs101-org', true]);
  assert.deepEqual(trackingCalls(t), [['create', 'class-repo-tracking', true], ['actions', 'class-repo-tracking', false], ['topics', 'class-repo-tracking', ['classrepo']]]);
  assert.ok(order.indexOf('actions off') < order.indexOf('git clone'), order.join());
  assert.ok(order.includes('git push'), 'and then the roster is written');
});

test('does not write the roster if Actions cannot be turned off on a roster repository it just made', async () => {
  const pair = generateRosterKeyPair();
  const t = setup({ job: baseJob(pair), privateKeyPem: pair.privateKeyPem, githubOverrides: { noTracking: true, actions: a => { if (a.repo === 'class-repo-tracking') throw new Error('no'); } } });
  await exercise(t);
  assert.equal(t.exec.length, 0);
  assert.ok(t.logs.some(l => l.includes('Could not create the tracking repository')));
});

test('uses a roster repository the educator already made as it is, without changing it', async () => {
  const pair = generateRosterKeyPair();
  const t = setup({ job: baseJob(pair), privateKeyPem: pair.privateKeyPem });
  await exercise(t);
  assert.deepEqual(trackingCalls(t), []);
  assert.ok(t.exec.some(e => e.args[0] === 'push'));
});

// ------------------------------------------------------------------------------------------------------------ check

test('a check job only introduces the bot: no GitHub calls, no roster key needed, and it succeeds', async () => {
  const t = setup({ job: { protocol: 3, mode: 'check', shortcode: null }, privateKeyPem: '' });
  await exercise(t);
  assert.deepEqual(t.calls, []);
  assert.equal(t.exec.length, 0);
  assert.deepEqual(failedLines(t), []);
  assert.equal(t.requests.filter(r => r.url.endsWith('/results')).length, 0);
  const claim = t.requests.find(r => r.url.endsWith('/claim')).body.bot;
  assert.deepEqual(claim.protocols, [3]);
  assert.ok(claim.capabilities.includes('check'));
});
