'use strict';
// Shared by the bot's tests: a way to seal records like the server does, and a fake GitHub / server / runner.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

// Seals a record the way the server does: AES-256-GCM key wrapped with RSA-OAEP (see roster-crypto.js).
function seal(publicKeyB64, record) {
  const rsa = crypto.createPublicKey({ key: Buffer.from(publicKeyB64, 'base64'), format: 'der', type: 'spki' });
  const aes = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', aes, iv);
  cipher.setAAD(Buffer.from('classrepo-roster-v1'));
  const body = Buffer.concat([cipher.update(JSON.stringify(record)), cipher.final(), cipher.getAuthTag()]);
  const wrapped = crypto.publicEncrypt({ key: rsa, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, aes);
  return ['v1', 'kid', wrapped.toString('base64url'), iv.toString('base64url'), body.toString('base64url')].join('.');
}

const SENSITIVE = ['alice-gh', 'Alice Smith', 'alice@univ.edu', 'bob-gh', 'Bob Jones', 'bob@univ.edu', 'cs101/starter', 'lab1', 'cs101-org'];
const BATCH = 'AbCdEfGhIjKlMnOpQrStUv';
const TEMPLATE = 'cs101/starter';

// A GitHub whose every method must be one the bot is meant to use: reaching for anything else (deleting a repository,
// changing visibility, ...) throws, so those rules are checked by the tests rather than only promised.
const strict = (name, target) => new Proxy(target, {
  get(t, prop) { if (!(prop in t)) throw new Error(`UNEXPECTED GITHUB CALL: ${name}.${String(prop)}`); return t[prop]; },
});

function setup({ job, privateKeyPem, githubOverrides = {}, serverStatus = 200, execFile, existing = {} } = {}) {
  const logs = [];
  const record = (level) => (msg) => logs.push(`${level}: ${msg}`);
  const secrets = [];
  const core = {
    info: record('info'), warning: record('warning'), error: record('error'), debug: record('debug'), notice: record('notice'),
    setFailed: record('FAILED'), setSecret: s => secrets.push(s), getIDToken: async aud => `oidc-for-${aud}`,
  };
  const calls = [];
  // Repositories that exist on "GitHub": name -> what repos.get returns. Pass `existing` to pre-seed some.
  const repos = new Map(Object.entries(existing));
  let pendingCopy = githubOverrides.copyPending || 0;
  const sleeps = [];
  const looks = [];
  const notFound = () => { const e = new Error('nf'); e.status = 404; return e; };
  const github = strict('github', { rest: strict('rest', {
    repos: strict('repos', {
      get: async ({ repo }) => {
        if (repo === 'class-repo-tracking') return { data: { private: true } };
        if (!repos.has(repo)) throw notFound();
        return { data: repos.get(repo) };
      },
      createUsingTemplate: async a => {
        calls.push(['create', a.name, a.private]);
        if (githubOverrides.create) await githubOverrides.create(a);
        repos.set(a.name, { topics: [], archived: false, private: true, template_repository: { full_name: `${a.template_owner}/${a.template_repo}` } });
        return { data: {} };
      },
      replaceAllTopics: async a => {
        calls.push(['topics', a.repo, a.names]);
        if (githubOverrides.topics) await githubOverrides.topics(a);
        repos.get(a.repo).topics = a.names;
        return { data: {} };
      },
      addCollaborator: async a => {
        calls.push(['invite', a.username, a.permission]);
        if (githubOverrides.invite) await githubOverrides.invite(a);
      },
      update: async a => {
        calls.push(['archived', a.repo, a.archived]);
        if (githubOverrides.update) await githubOverrides.update(a);
        repos.get(a.repo).archived = a.archived;
      },
      getContent: async ({ path: filePath }) => {
        if (filePath !== '') throw notFound();
        // The root listing is how the bot knows GitHub has finished copying a template. `copyPending` = how many looks come back empty.
        looks.push(calls.length); // how many writes had happened when the bot looked
        if (pendingCopy > 0) { pendingCopy--; throw notFound(); }
        return { data: [{ name: 'README.md' }] };
      },
      createOrUpdateFileContents: async a => { calls.push(['badge', a.repo]); },
      createInOrg: async () => ({ data: { private: true } }),
    }),
    users: strict('users', {
      getByUsername: async () => ({ data: { type: 'Organization' } }),
    }),
    actions: strict('actions', {
      setGithubActionsPermissionsRepository: async a => {
        calls.push(['actions', a.repo, a.enabled]);
        if (githubOverrides.actions) await githubOverrides.actions(a);
      },
    }),
  }),
  // Endpoints without a method in github-script's Octokit are called by route, so only these routes are allowed.
  request: async (route, params) => {
    if (route !== 'GET /user/{account_id}') throw new Error(`UNEXPECTED GITHUB CALL: request ${route}`);
    const { account_id } = params;
    calls.push(['lookup', account_id]);
    if (githubOverrides.lookup) return githubOverrides.lookup(account_id);
    return { data: { login: (githubOverrides.logins || {})[account_id] || `user${account_id}` } };
  } });
  const requests = [];
  const fetch = async (url, init) => {
    const body = JSON.parse(init.body);
    requests.push({ url, auth: init.headers.Authorization, body });
    if (url.endsWith('/claim')) return { ok: serverStatus === 200, status: serverStatus, json: async () => job };
    return { ok: true, status: 200, json: async () => ({}) };
  };
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'prov-'));
  const exec = [];
  const deps = { fetch, tmpDir, sleep: async ms => { sleeps.push(ms); }, execFile: execFile || ((cmd, args, opts) => { exec.push({ cmd, args, opts }); if (args[0] === 'clone') fs.mkdirSync(args[args.length - 1], { recursive: true }); }) };
  const env = {
    BATCH_ID: BATCH, SERVER_URL: 'https://api.classrepo.org/', EXECUTOR_TOKEN: 'ghs_executor', ROSTER_PRIVATE_KEY: privateKeyPem,
    TRACKING_REPO: 'class-repo-tracking', RUNNER_TEMP: tmpDir,
  };
  const context = { repo: { owner: 'cs101-org', repo: 'class-repo-bot' } };
  return { logs, secrets, core, github, deps, env, context, calls, requests, exec, tmpDir, repos, sleeps, looks };
}

module.exports = { seal, setup, strict, SENSITIVE, BATCH, TEMPLATE };
