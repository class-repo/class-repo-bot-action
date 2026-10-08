'use strict';
// Logic for .github/workflows/provision.yml, kept in a file so it can be tested.
//
// THE RULES THIS BOT ENFORCES ITSELF, whatever the server asks (the server is not trusted with the Executor App's
// authority, only with deciding WHEN to run and WHICH students):
//   - repositories are only ever created private, from the template named in the job (and the allow-list, if set);
//   - collaborators get at most "push" access; nothing is ever deleted; visibility is never changed;
//   - it only touches repositories ClassRepo made: ones carrying the `classrepo` topic, or generated from this job's
//     template. A repository that merely has a matching name is left alone.
//   - a job using anything this bot does not understand is refused as a whole, with a clear "update your bot" message,
//     rather than being half-done.
//
// This repository may be PUBLIC, which makes the workflow's inputs, logs and annotations public too. So:
//   - the dispatch carries only a batch id; the job is fetched from the ClassRepo server with the run's
//     GitHub OIDC token, and student records arrive sealed to this repo's roster key (roster-crypto.js);
//   - nothing identifying (handles, names, emails, template, assignment, owner) is ever logged: progress is
//     reported by position ("repository 3 of 40") and every sensitive value is registered as a masked secret.
//   - the roster itself is only written to the educator's PRIVATE tracking repository.

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const { generateRosterKeyPair, publicKeyFromPrivate, openSealed } = require('./roster-crypto');
const { version: BOT_VERSION } = require('../package.json');

// Job format version. The server sends a job only to a bot that lists its protocol.
const PROTOCOL = 4;
const COPY_WAIT_ATTEMPTS = 30; // GitHub usually takes a few seconds; give up after about a minute
const COPY_WAIT_MS = 2000;
const MAX_REPOS = 200;
const MAX_COLLABORATORS = 10;
const ALLOWED_PERMISSIONS = ['pull', 'push'];
const SUPPORTED_SETTINGS = ['actions_enabled', 'codespaces_badge', 'archived', 'instructions_url'];
// Where the roster repository comes from when the educator has none yet. Fixed here, never taken from a job.
const TRACKING_TEMPLATE = { owner: 'class-repo', repo: 'class-repo-tracking-template' };
const SUPPORTED_SNAPSHOT_FIELDS = ['protocol', 'mode', 'template', 'assignment_name', 'target_owner', 'shortcode'];
const SNAPSHOT_TOPIC = 'classrepo-snapshot';
const SNAPSHOT_RE = /^classrepo-snapshot-[A-Za-z0-9]{1,32}$/;
// https only, and none of the characters that could break out of a Markdown link or an HTML attribute.
const INSTRUCTIONS_RE = /^https:\/\/[A-Za-z0-9._~:/?#@!$&*+,;=%-]{1,300}$/;
const SUPPORTED_REPO_FIELDS = ['sync_key', 'collaborators', 'settings'];
const MARKER_TOPIC = 'classrepo';

// What this bot can do. The server only asks for what is listed here, and tells the educator when the bot is too old.
const BOT = {
  version: BOT_VERSION,
  protocols: [PROTOCOL],
  capabilities: [
    'ensure_repos', 'snapshot', 'setup', 'roster_repo', 'setup_keys', 'collaborators:multiple', ...ALLOWED_PERMISSIONS.map(p => `permission:${p}`),
    ...SUPPORTED_SETTINGS.map(k => `setting:${k}`), 'marker:topic',
  ],
};

const OUTDATED = "Your instructor's ClassRepo bot needs updating, so this could not be done. Please let them know.";

const HANDLE_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const NAME_RE = /^[A-Za-z0-9._-]{1,60}$/;
const TEMPLATE_RE = /^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/;
const ROSTER_SECRET = 'CLASSREPO_ROSTER_PRIVATE_KEY';

const oneLine = (value, max = 200) => String(value == null ? '' : value).replace(/[\r\n\u2028\u2029]+/g, ' ').trim().slice(0, max);
const mdCell = value => oneLine(value).replace(/\|/g, '\\|').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\[/g, '\\[').replace(/\]/g, '\\]');

// What GitHub said about a refusal, for the run log. Every job value and student detail is already masked as a secret, so this cannot print one.
const whatGitHubSaid = e => oneLine(e && e.message, 300) || 'no reason given';

async function run({ github, context, core, env = process.env, deps = {} }) {
  const fetchFn = deps.fetch || fetch;
  const execFile = deps.execFile || childProcess.execFileSync;
  const tmp = deps.tmpDir || env.RUNNER_TEMP || os.tmpdir();
  const sleep = deps.sleep || (ms => new Promise(resolve => setTimeout(resolve, ms)));

  const serverUrl = String(env.SERVER_URL || '').replace(/\/+$/, '');
  const batchId = String(env.BATCH_ID || '');
  if (!/^https:\/\//.test(serverUrl) && !deps.allowHttp) return core.setFailed('server_url must be an https address.');
  if (!/^[A-Za-z0-9_-]{16,64}$/.test(batchId)) return core.setFailed('batch_id is not valid.');
  const audience = new URL(serverUrl).origin;

  // A fresh token per call: each one is short-lived and a run can last several minutes.
  async function call(action, body) {
    const token = await core.getIDToken(audience);
    return fetchFn(`${serverUrl}/api/batch/${batchId}/${action}`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(body || {}),
    });
  }
  const mask = value => { if (value && String(value).length >= 3) core.setSecret(String(value)); };

  // Claiming the job also tells the server which bot this is, so it can offer only what this bot supports.
  const claim = await call('claim', { bot: BOT });
  if (!claim.ok) return core.setFailed(`Could not fetch the job from the ClassRepo server (HTTP ${claim.status}).`);
  const job = await claim.json();
  [job.template, job.assignment_name, job.target_owner, job.shortcode].forEach(mask);

  // check: claiming the job already told the server which bot this is, which lets the educator's setup check confirm, end to end, that
  // this workflow runs and reaches the server, and which version it is. It also makes sure the roster repository works (see ensureRosterRepo).
  if (job.mode === 'setup') return setupRun();
  if (job.mode === 'setup_keys') return setupKeys();
  if (job.mode === 'ensure_repos') return ensureRepos();
  if (job.mode === 'snapshot') return snapshot();
  await reportAll(OUTDATED);
  return core.setFailed('This job type is not supported by this version of the bot. Update the bot.');

  // Tells every waiting student the job could not be done (used when the whole job is refused).
  async function reportAll(message) {
    const entries = Array.isArray(job.repos) ? job.repos : [];
    const results = entries.map((entry, index) => ({ entry, index })).filter(({ entry }) => entry && entry.sync_key)
      .map(({ index }) => ({ index, status: 'failed', error: message }));
    if (results.length === 0) return;
    try { await call('results', { results }); } catch { core.warning('Could not send a status report to the server.'); }
  }

  // Looks at a whole job BEFORE touching GitHub. Returns null if it is acceptable, or { message, student }.
  function refuseJob() {
    if (job.protocol !== PROTOCOL) return { message: `The job uses protocol ${job.protocol}; this bot supports ${BOT.protocols.join(', ')}. Update the bot.`, student: OUTDATED };
    const repos = job.repos;
    if (!Array.isArray(repos) || repos.length === 0 || repos.length > MAX_REPOS) return { message: 'The job lists no repositories, or too many.', student: 'This could not be done.' };
    // Anything this bot does not know about makes it refuse everything, so nothing is half-done.
    for (const spec of repos) {
      if (!spec || typeof spec !== 'object') return { message: 'The job is malformed.', student: 'This could not be done.' };
      const unknownField = Object.keys(spec).find(k => !SUPPORTED_REPO_FIELDS.includes(k));
      const unknownSetting = Object.keys(spec.settings || {}).find(k => !SUPPORTED_SETTINGS.includes(k));
      if (unknownField || unknownSetting) return { message: 'The job uses a feature this bot does not have. Update the bot.', student: OUTDATED };
    }
    for (const spec of repos) {
      const people = spec.collaborators;
      if (!Array.isArray(people) || people.length === 0 || people.length > MAX_COLLABORATORS) return { message: 'A repository has no collaborators, or too many.', student: 'This could not be done.' };
      if (people.some(p => !p || typeof p.sealed !== 'string' || !ALLOWED_PERMISSIONS.includes(p.permission))) {
        return { message: `The job asks for a permission this bot never grants (it grants only: ${ALLOWED_PERMISSIONS.join(', ')}).`, student: 'This could not be done.' };
      }
      const settingsOk = Object.entries(spec.settings || {}).every(([k, v]) => (k === 'instructions_url' ? typeof v === 'string' && INSTRUCTIONS_RE.test(v) : typeof v === 'boolean'));
      if (!settingsOk) return { message: 'A repository setting has an invalid value.', student: 'This could not be done.' };
    }
    return null;
  }

  // ---------------------------------------------------------------------------------------------
  // setup_keys: create the roster key pair here. The private key goes straight into this repo's
  // Actions secrets; only the public key is sent to the server.
  // ---------------------------------------------------------------------------------------------
  async function setupKeys() {
    const { publicKeyB64, privateKeyPem } = generateRosterKeyPair();
    core.setSecret(privateKeyPem);
    privateKeyPem.split('\n').forEach(mask);
    try {
      storeRosterSecret(privateKeyPem);
    } catch {
      return core.setFailed('Could not store the roster key as an Actions secret. Check the Executor App has the Secrets permission on this repository.');
    }
    const res = await call('roster-key', { public_key: publicKeyB64 });
    if (!res.ok) return core.setFailed(`The server did not accept the roster key (HTTP ${res.status}). Run the setup again.`);
    core.info('Encrypted roster enabled.');
  }

  // GitHub copies a template in the background: the repository exists straight away but is empty for a few seconds.
  // Inviting people or writing files into it before the copy finishes can collide with the copy, so wait for the files.
  async function waitForTemplateCopy(owner, repoName) {
    for (let attempt = 0; attempt < COPY_WAIT_ATTEMPTS; attempt++) {
      try {
        const root = await github.rest.repos.getContent({ owner, repo: repoName, path: '' });
        if (Array.isArray(root.data) && root.data.length > 0) return;
      } catch { /* not there yet */ }
      await sleep(COPY_WAIT_MS);
    }
    const timeout = new Error('GitHub is still copying the template into the repository. Please try again in a minute.');
    timeout.code = 'copy_timeout';
    throw timeout;
  }

  // Labels a repository as ClassRepo's. Best effort: a repository generated from this template is recognised anyway.
  async function markTopics(owner, repoName, names) {
    try {
      await github.rest.repos.replaceAllTopics({ owner, repo: repoName, names: [...new Set(names)] });
    } catch {
      core.warning('Could not label one repository as created by ClassRepo.');
    }
  }

  // Makes sure the educator's PRIVATE roster repository exists in `owner`, creating it if not. Returns { repo, created } or
  // { problem: { code, http? } }. It is called early (by the setup check and when a snapshot is made) so that a problem shows up
  // BEFORE any student joins, and again when the roster is written. Generating from a template works in a personal account as well
  // as an organization (an app cannot create an EMPTY repository in a personal account). The roster is the most sensitive thing written
  // anywhere, so nothing may run in this repository: Actions is turned off before anything is written to it.
  async function ensureRosterRepo(owner, trackingRepo) {
    // "none": the educator keeps their own records, so no roster repository is made, checked or written to.
    if (/^none$/i.test(trackingRepo)) return { off: true };
    let repo = null;
    let created = false;
    try {
      repo = (await github.rest.repos.get({ owner, repo: trackingRepo })).data;
    } catch (e) {
      if (e.status !== 404) return { problem: { code: 'roster_failed', http: e.status } };
      try {
        await github.rest.repos.createUsingTemplate({ template_owner: TRACKING_TEMPLATE.owner, template_repo: TRACKING_TEMPLATE.repo, owner, name: trackingRepo, private: true, description: 'ClassRepo roster', include_all_branches: false });
        created = true;
        await github.rest.actions.setGithubActionsPermissionsRepository({ owner, repo: trackingRepo, enabled: false });
        await waitForTemplateCopy(owner, trackingRepo);
        await markTopics(owner, trackingRepo, [MARKER_TOPIC]);
        repo = (await github.rest.repos.get({ owner, repo: trackingRepo })).data;
      } catch (err) {
        return { problem: { code: 'roster_failed', ...(err.status ? { http: err.status } : {}) } };
      }
    }
    if (!repo.private) return { problem: { code: 'roster_public' } };
    return { repo, created };
  }

  // Tells the server the one result of a job that is not about students (a snapshot). A failure is a short code from a fixed
  // list (plus GitHub's HTTP status): the server owns the wording shown to the educator, so no free text travels back.
  async function reportOne(status, problem) {
    try { await call('results', { results: [{ index: 0, status, ...(problem || {}) }] }); } catch { core.warning('Could not send a status report to the server.'); }
  }

  // Stores a private key as the roster Actions secret of THIS (bot) repository. Throws if it cannot.
  function storeRosterSecret(privateKeyPem) {
    execFile('gh', ['secret', 'set', ROSTER_SECRET, '--repo', `${context.repo.owner}/${context.repo.repo}`], {
      input: privateKeyPem,
      stdio: ['pipe', 'ignore', 'ignore'],
      env: { ...env, GH_TOKEN: env.EXECUTOR_TOKEN },
    });
  }

  // setup: everything the educator's final setup step needs, in one run, and safe to run again. (1) The encryption key: made only if
  // this repository has none (rotating is the separate setup_keys job); if one exists its public half is worked out from it and sent
  // again, so a server that has forgotten it is put right without replacing anything. (2) The private roster repository. (3) Claiming
  // the job has already told the server which bot this is. The result is one report with fixed codes only.
  async function setupRun() {
    const owner = context.repo.owner;
    const trackingRepo = env.TRACKING_REPO || 'class-repo-tracking';
    if (!NAME_RE.test(trackingRepo)) return core.setFailed('The roster repository name is not valid.');
    const stop = async (problem, log) => { await reportOne('failed', problem); core.setFailed(log); };

    let publicKeyB64;
    let key;
    if (env.ROSTER_PRIVATE_KEY) {
      try {
        publicKeyB64 = publicKeyFromPrivate(env.ROSTER_PRIVATE_KEY);
      } catch {
        return stop({ code: 'key_failed' }, 'The roster key secret in this repository cannot be read. Replace the encryption key from the ClassRepo setup page.');
      }
      key = 'existing';
    } else {
      const pair = generateRosterKeyPair();
      core.setSecret(pair.privateKeyPem);
      pair.privateKeyPem.split('\n').forEach(mask);
      try {
        storeRosterSecret(pair.privateKeyPem);
      } catch {
        return stop({ code: 'key_failed' }, 'Could not store the roster key as an Actions secret. Check the Executor App has the Secrets permission on this repository.');
      }
      publicKeyB64 = pair.publicKeyB64;
      key = 'created';
    }
    const registered = await call('roster-key', { public_key: publicKeyB64 });
    if (!registered.ok) return stop({ code: 'key_rejected', http: registered.status }, `The server did not accept the roster key (HTTP ${registered.status}). Run the setup again.`);

    const roster = await ensureRosterRepo(owner, trackingRepo);
    if (roster.problem) {
      return stop(roster.problem, `The roster repository is not ready (${roster.problem.code}${roster.problem.http ? `, HTTP ${roster.problem.http}` : ''}).`);
    }
    await reportOne('ready', { key, roster: roster.off ? 'none' : roster.created ? 'created' : 'existing' });
    core.info('setup: the encryption key and the roster repository are ready.');
  }

  // ---------------------------------------------------------------------------------------------
  // snapshot: make the frozen copy of an assignment's starter that every student's repository is generated from.
  // It lives in the educator's own account, is private, and carries a topic so this bot (and only this bot) can tell it
  // is one of ClassRepo's. This is the one repository the bot ever marks as a template.
  // ---------------------------------------------------------------------------------------------
  async function snapshot() {
    const { template, assignment_name: name } = job;
    const owner = job.target_owner || context.repo.owner;
    const stop = async (code, http, log) => { await reportOne('failed', { code, ...(http ? { http } : {}) }); core.setFailed(log || `The snapshot failed (${code}${http ? `, HTTP ${http}` : ''}).`); };

    if (!TEMPLATE_RE.test(template || '') || !SNAPSHOT_RE.test(name || '') || !HANDLE_RE.test(owner) || Object.keys(job).some(k => !SUPPORTED_SNAPSHOT_FIELDS.includes(k))) {
      return stop('invalid_job');
    }
    const allowedOwners = String(env.ALLOWED_TEMPLATE_OWNERS || '').split(',').map(x => x.trim().toLowerCase()).filter(Boolean);
    if (allowedOwners.length && !allowedOwners.includes(template.split('/')[0].toLowerCase())) {
      return stop('owner_not_allowed', null, 'The template owner is not in this repository\'s allowed list (CLASSREPO_ALLOWED_TEMPLATE_OWNERS).');
    }
    const [templateOwner, templateRepo] = template.split('/');

    // The roster repository for this account must work BEFORE anything is made, so a problem is found now and not at the first join.
    const trackingRepo = env.TRACKING_REPO || 'class-repo-tracking';
    if (!NAME_RE.test(trackingRepo)) return stop('invalid_job');
    const roster = await ensureRosterRepo(owner, trackingRepo);
    if (roster.problem) return stop(roster.problem.code, roster.problem.http);

    let existing = null;
    try {
      existing = (await github.rest.repos.get({ owner, repo: name })).data;
    } catch (e) {
      if (e.status !== 404) return stop('check_failed', e.status);
    }
    if (existing && !(existing.topics || []).includes(SNAPSHOT_TOPIC)) {
      return stop('name_taken');
    }
    // The snapshot holds the educator's starter, so it must be private. An organization that only lets GitHub Apps create PUBLIC
    // repositories can end up with a public copy even though private was asked for: stop before anything else is done to it.
    const publicNotice = 'GitHub made the snapshot a public repository although private was requested (the organization may only allow public repositories for members and apps). Nothing was shared. Allow private repositories, then make this one private or delete it.';
    if (existing && existing.private !== true) return stop('snapshot_public', null, publicNotice);
    if (!existing) {
      try {
        const made = (await github.rest.repos.createUsingTemplate({ template_owner: templateOwner, template_repo: templateRepo, owner, name, private: true, include_all_branches: false })).data;
        if (!made || made.private !== true) return stop('snapshot_public', null, publicNotice);
      } catch (e) {
        return stop('copy_failed', e.status, `GitHub refused to copy the template (HTTP ${e.status || 'error'}): ${whatGitHubSaid(e)}`);
      }
    }
    try {
      await waitForTemplateCopy(owner, name);
    } catch (e) {
      return stop(e.code || 'copy_failed');
    }
    await markTopics(owner, name, [MARKER_TOPIC, SNAPSHOT_TOPIC]);
    try {
      await github.rest.repos.update({ owner, repo: name, is_template: true });
    } catch (e) {
      return stop('template_failed', e.status);
    }
    core.info('snapshot: done');
    await reportOne('ready');
  }

  // ---------------------------------------------------------------------------------------------
  // ensure_repos: make these repositories look like the job says. Creates what is missing and corrects what differs,
  // so running the same job twice is harmless.
  // ---------------------------------------------------------------------------------------------
  async function ensureRepos() {
    const assignment = job.assignment_name;
    const template = job.template;
    const owner = job.target_owner || context.repo.owner;
    const repos = Array.isArray(job.repos) ? job.repos : [];
    const trackingRepo = env.TRACKING_REPO || 'class-repo-tracking';

    const refusal = refuseJob();
    if (refusal) {
      await reportAll(refusal.student);
      return core.setFailed(refusal.message);
    }
    if (!NAME_RE.test(assignment || '') || !TEMPLATE_RE.test(template || '') || !HANDLE_RE.test(owner) || !NAME_RE.test(trackingRepo)) {
      await reportAll('This could not be done.');
      return core.setFailed('The job contains invalid names.');
    }
    // Students' repositories are only ever generated from a snapshot THIS bot made in the educator's own account, never from
    // whatever repository a job names. (The educator's allowed-template-owners list applies to the snapshot's source instead.)
    const [snapshotOwner, snapshotRepo] = template.split('/');
    if (snapshotOwner.toLowerCase() !== owner.toLowerCase() || !SNAPSHOT_RE.test(snapshotRepo)) {
      await reportAll('The assignment is not set up correctly. Please let your instructor know.');
      return core.setFailed('The job names a template that is not one of ClassRepo\'s snapshots in the target account.');
    }
    try {
      const copy = (await github.rest.repos.get({ owner: snapshotOwner, repo: snapshotRepo })).data;
      if (!(copy.topics || []).includes(SNAPSHOT_TOPIC)) throw new Error('not a snapshot');
    } catch {
      await reportAll('The assignment is not ready yet. Please let your instructor know.');
      return core.setFailed('The snapshot does not exist or is not labelled as ClassRepo\'s.');
    }
    if (!env.ROSTER_PRIVATE_KEY) return core.setFailed('No roster key is configured. Use "Turn on the encrypted roster" in the ClassRepo dashboard.');

    const [templateOwner, templateRepo] = template.split('/');
    const logDir = path.join(tmp, 'logs_generated');
    fs.mkdirSync(logDir, { recursive: true });

    // Opens one sealed collaborator record and works out the handle the account has NOW. The account id never changes
    // but the handle can, so a renamed student is still invited and a re-registered handle never reaches the wrong person.
    async function resolvePerson(collaborator) {
      let record;
      try {
        record = openSealed(collaborator.sealed, env.ROSTER_PRIVATE_KEY);
        if (!record || !HANDLE_RE.test(record.github)) throw new Error('bad record');
      } catch {
        const error = new Error('Your details could not be processed. Please ask your instructor to check the encrypted roster setup.');
        error.log = "could not open the student's record (was the roster key replaced?).";
        throw error;
      }
      [record.github, record.name, record.email].forEach(mask);
      if (record.github_id != null) {
        let login;
        try {
          // No users.getById in the Octokit that github-script ships, so call the endpoint directly.
          login = (await github.request('GET /user/{account_id}', { account_id: Number(record.github_id) })).data.login;
        } catch (e) {
          throw new Error(e.status === 404 ? 'That GitHub account no longer exists.' : `Could not look up the GitHub account (HTTP ${e.status || 'error'}).`);
        }
        if (!HANDLE_RE.test(String(login))) throw new Error('Could not look up the GitHub account.');
        record.github = login;
        mask(login);
      }
      return { record, permission: collaborator.permission };
    }

    const mark = (repoName, existingTopics = []) => markTopics(owner, repoName, [...existingTopics, MARKER_TOPIC]);
    const waitForCopy = repoName => waitForTemplateCopy(owner, repoName);

    // A student's repository must be private. If it is not (an organization that only allows public repositories for apps), nobody is invited.
    const notPrivate = () => {
      const error = new Error("Your instructor's GitHub settings do not allow private repositories, so this could not be done. Please let them know.");
      error.log = 'The repository is not private, so no one was invited. The organization may only allow public repositories for members and apps.';
      return error;
    };

    // Throws an Error with a short message that is safe to show to the student and to log.
    async function ensureRepo(spec, people) {
      const settings = spec.settings || {};
      const repoName = `${assignment}-${people[0].record.github}`; // a repository is named after its first collaborator

      let existing = null;
      try {
        existing = (await github.rest.repos.get({ owner, repo: repoName })).data;
      } catch (e) {
        if (e.status !== 404) throw new Error(`Could not check for an existing repository (HTTP ${e.status || 'error'}).`);
      }

      if (!existing) {
        let made;
        try {
          made = (await github.rest.repos.createUsingTemplate({ template_owner: templateOwner, template_repo: templateRepo, owner, name: repoName, private: true, include_all_branches: false })).data;
        } catch (e) {
          const error = new Error(`Could not create the repository from the template (HTTP ${e.status || 'error'}).`);
          error.log = `GitHub refused to create the repository (HTTP ${e.status || 'error'}): ${whatGitHubSaid(e)}`;
          throw error;
        }
        if (!made || made.private !== true) throw notPrivate();
        await waitForCopy(repoName);
        await mark(repoName);
        existing = { archived: false };
      } else {
        // A repository that only has a matching NAME is not ours to change, however the name came about.
        if (existing.private === false) throw notPrivate(); // never invite a student into a public repository
        const topics = existing.topics || [];
        const generatedFromTemplate = !!existing.template_repository
          && String(existing.template_repository.full_name).toLowerCase() === template.toLowerCase();
        if (!topics.includes(MARKER_TOPIC) && !generatedFromTemplate) {
          throw new Error('A repository with that name already exists and was not created by ClassRepo, so it was left alone.');
        }
        await waitForCopy(repoName); // a retry may find a repository GitHub has not finished filling
        if (!topics.includes(MARKER_TOPIC)) await mark(repoName, topics);
      }

      if (existing.archived) {
        if (settings.archived === true) return writeRoster(people, repoName); // already as asked
        if (settings.archived !== false) throw new Error('This repository has been archived.');
        try { await github.rest.repos.update({ owner, repo: repoName, archived: false }); } catch (e) { throw new Error(`Could not reopen the archived repository (HTTP ${e.status || 'error'}).`); }
      }

      for (const { record, permission } of people) {
        try {
          await github.rest.repos.addCollaborator({ owner, repo: repoName, username: record.github, permission });
        } catch (e) {
          throw new Error(`The repository exists, but sending the invitation failed (HTTP ${e.status || 'error'}).`);
        }
      }
      if (settings.actions_enabled !== undefined) await setActions(repoName, settings.actions_enabled); // best effort
      await addReadmeNotes(repoName, { instructionsUrl: settings.instructions_url, badge: settings.codespaces_badge === true }); // best effort
      writeRoster(people, repoName);
      if (settings.archived === true) {
        try { await github.rest.repos.update({ owner, repo: repoName, archived: true }); } catch (e) { throw new Error(`Could not archive the repository (HTTP ${e.status || 'error'}).`); }
      }
    }

    function writeRoster(people, repoName) {
      for (const { record, permission } of people) {
        const lines = [`github_id: ${record.github_id == null ? '' : record.github_id}`, `github_handle: ${record.github}`, `name: ${oneLine(record.name)}`, `email: ${oneLine(record.email) || 'no-email'}`,
          `permission: ${permission}`, `created_at: ${new Date().toISOString()}`, `repo: ${owner}/${repoName}`];
        fs.writeFileSync(path.join(logDir, `${record.github}.txt`), lines.join('\n'));
      }
    }

    // Students have write access, so they could add workflows that spend the organization's Actions minutes or
    // read organization-wide secrets. Educators who don't need autograding can turn Actions off per assignment.
    async function setActions(repoName, enabled) {
      try {
        await github.rest.actions.setGithubActionsPermissionsRepository({ owner, repo: repoName, enabled });
      } catch {
        core.warning('Could not change the GitHub Actions setting of one repository.');
      }
    }

    // Puts the instructions link and the Codespaces badge at the top of the README, once each (so re-running is harmless).
    async function addReadmeNotes(repoName, { instructionsUrl, badge }) {
      const notes = [];
      if (instructionsUrl) notes.push({ key: instructionsUrl, text: `**[Assignment instructions](${instructionsUrl})**` });
      if (badge) notes.push({ key: 'codespaces.new', text: `[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/${owner}/${repoName}?quickstart=1)` });
      if (notes.length === 0) return;
      try {
        const readme = await github.rest.repos.getContent({ owner, repo: repoName, path: 'README.md' }).catch(() => null);
        const current = readme && readme.data ? Buffer.from(readme.data.content, 'base64').toString('utf8') : '';
        const missing = notes.filter(n => !current.includes(n.key));
        if (missing.length === 0) return;
        const content = Buffer.from(`${missing.map(n => n.text).join('\n\n')}\n\n${current}`.trimEnd() + '\n').toString('base64');
        await github.rest.repos.createOrUpdateFileContents({ owner, repo: repoName, path: 'README.md', message: 'Add assignment links', content, ...(readme && readme.data ? { sha: readme.data.sha } : {}) });
      } catch {
        core.warning('Could not add the assignment links to one repository.');
      }
    }

    async function report(index, status, error) {
      if (!repos[index].sync_key) return; // bulk roster rows: nobody is waiting
      try {
        const res = await call('results', { results: [{ index, status, error }] });
        if (!res.ok) core.warning(`The server rejected a status report (HTTP ${res.status}).`);
      } catch {
        core.warning('Could not send a status report to the server.');
      }
    }

    let failed = 0;
    for (const [index, spec] of repos.entries()) {
      const label = `repository ${index + 1} of ${repos.length}`;
      try {
        const people = [];
        for (const collaborator of spec.collaborators) people.push(await resolvePerson(collaborator));
        await ensureRepo(spec, people);
        core.info(`${label}: done`);
        await report(index, 'ready');
      } catch (e) {
        failed++;
        core.error(`${label}: ${e.log || e.message}`);
        await report(index, 'failed', e.message);
      }
    }

    await pushTracking({ owner, trackingRepo, assignment, logDir });
    if (failed > 0) core.setFailed(`${failed} of ${repos.length} repositories failed.`);
  }

  // Records the roster in the educator's PRIVATE tracking repository (creating it if needed).
  async function pushTracking({ owner, trackingRepo, assignment, logDir }) {
    const files = fs.readdirSync(logDir).filter(f => f.endsWith('.txt'));
    if (files.length === 0) return;

    const roster = await ensureRosterRepo(owner, trackingRepo);
    if (roster.off) return; // the educator keeps their own records
    if (roster.problem) {
      return core.warning(roster.problem.code === 'roster_public'
        ? 'The tracking repository is public, so the roster was NOT recorded. Make it private.'
        : 'Could not create or check the tracking repository; roster not recorded.');
    }

    const dir = path.join(tmp, 'tracking');
    fs.rmSync(dir, { recursive: true, force: true });
    const git = (args, cwd) => execFile('git', args, { cwd, stdio: 'pipe', env });
    try {
      git(['clone', '--depth', '1', `https://x-access-token:${env.EXECUTOR_TOKEN}@github.com/${owner}/${trackingRepo}.git`, dir]);
      git(['config', 'user.name', 'ClassRepo Bot'], dir);
      git(['config', 'user.email', 'bot@classrepo.internal'], dir);
      git(['checkout', '-B', 'main'], dir);

      const logsDir = path.join(dir, 'logs', assignment);
      fs.mkdirSync(logsDir, { recursive: true });
      for (const f of files) fs.copyFileSync(path.join(logDir, f), path.join(logsDir, f));
      fs.writeFileSync(path.join(logsDir, 'README.md'), buildDashboard(logsDir));

      git(['add', 'logs'], dir);
      try { git(['commit', '-m', 'Record repository creation'], dir); } catch { return; } // nothing new
      for (let attempt = 0; attempt < 5; attempt++) {
        try { git(['pull', '--rebase', 'origin', 'main'], dir); } catch { /* empty remote or no changes */ }
        try { git(['push', 'origin', 'HEAD:main'], dir); return; } catch { /* retry */ }
      }
      core.warning('Could not push to the tracking repository after several attempts.');
    } catch {
      core.warning('Could not update the tracking repository.');
    }
  }

  function buildDashboard(logsDir) {
    const rows = fs.readdirSync(logsDir).filter(f => f.endsWith('.txt')).map(f => {
      const data = {};
      for (const line of fs.readFileSync(path.join(logsDir, f), 'utf8').split('\n')) {
        const i = line.indexOf(': ');
        if (i > 0) data[line.slice(0, i)] = line.slice(i + 2);
      }
      return data;
    }).filter(d => HANDLE_RE.test(d.github_handle || ''));
    rows.sort((a, b) => String(a.created_at).localeCompare(String(b.created_at)));
    return ['# Student Repository Dashboard', '', '| GitHub Handle | Name | Email | Repository | Created At |', '|---------------|------|-------|------------|------------|',
      ...rows.map(d => `| [@${d.github_handle}](https://github.com/${d.github_handle}) | ${mdCell(d.name)} | ${mdCell(d.email)} | ${mdCell(d.repo)} | ${mdCell(d.created_at)} |`), ''].join('\n');
  }
}

module.exports = run;
