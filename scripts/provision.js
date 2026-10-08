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
const { generateRosterKeyPair, openSealed } = require('./roster-crypto');
const { version: BOT_VERSION } = require('../package.json');

// Job format version. A newer server keeps sending protocol 2 jobs to bots that list 2, so bots can lag safely.
const PROTOCOL = 2;
const MAX_REPOS = 200;
const MAX_COLLABORATORS = 10;
const ALLOWED_PERMISSIONS = ['pull', 'push'];
const SUPPORTED_SETTINGS = ['actions_enabled', 'codespaces_badge', 'archived'];
const SUPPORTED_REPO_FIELDS = ['sync_key', 'collaborators', 'settings'];
const MARKER_TOPIC = 'classrepo';

// What this bot can do. The server only asks for what is listed here, and tells the educator when the bot is too old.
const BOT = {
  version: BOT_VERSION,
  protocols: [PROTOCOL],
  capabilities: [
    'ensure_repos', 'setup_keys', 'collaborators:multiple', ...ALLOWED_PERMISSIONS.map(p => `permission:${p}`),
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

async function run({ github, context, core, env = process.env, deps = {} }) {
  const fetchFn = deps.fetch || fetch;
  const execFile = deps.execFile || childProcess.execFileSync;
  const tmp = deps.tmpDir || env.RUNNER_TEMP || os.tmpdir();

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

  if (job.mode === 'setup_keys') return setupKeys();
  if (job.mode === 'ensure_repos') return ensureRepos();
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
      if (Object.values(spec.settings || {}).some(v => typeof v !== 'boolean')) return { message: 'A repository setting is not true or false.', student: 'This could not be done.' };
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
      execFile('gh', ['secret', 'set', ROSTER_SECRET, '--repo', `${context.repo.owner}/${context.repo.repo}`], {
        input: privateKeyPem,
        stdio: ['pipe', 'ignore', 'ignore'],
        env: { ...env, GH_TOKEN: env.EXECUTOR_TOKEN },
      });
    } catch {
      return core.setFailed('Could not store the roster key as an Actions secret. Check the Executor App has the Secrets permission on this repository.');
    }
    const res = await call('roster-key', { public_key: publicKeyB64 });
    if (!res.ok) return core.setFailed(`The server did not accept the roster key (HTTP ${res.status}). Run the setup again.`);
    core.info('Encrypted roster enabled.');
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
      return core.setFailed('The job contains invalid names.');
    }
    const allowedOwners = String(env.ALLOWED_TEMPLATE_OWNERS || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
    if (allowedOwners.length && !allowedOwners.includes(template.split('/')[0].toLowerCase())) {
      return core.setFailed('The template owner is not in this repository\'s allowed list (CLASSREPO_ALLOWED_TEMPLATE_OWNERS).');
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

    // Labels a repository as ClassRepo's. Best effort: a repository generated from this template is recognised anyway.
    async function mark(repoName, existingTopics = []) {
      try {
        await github.rest.repos.replaceAllTopics({ owner, repo: repoName, names: [...new Set([...existingTopics, MARKER_TOPIC])] });
      } catch {
        core.warning('Could not label one repository as created by ClassRepo.');
      }
    }

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
        try {
          await github.rest.repos.createUsingTemplate({ template_owner: templateOwner, template_repo: templateRepo, owner, name: repoName, private: true, include_all_branches: false });
        } catch (e) {
          throw new Error(`Could not create the repository from the template (HTTP ${e.status || 'error'}).`);
        }
        await mark(repoName);
        existing = { archived: false };
      } else {
        // A repository that only has a matching NAME is not ours to change, however the name came about.
        const topics = existing.topics || [];
        const generatedFromTemplate = !!existing.template_repository
          && String(existing.template_repository.full_name).toLowerCase() === template.toLowerCase();
        if (!topics.includes(MARKER_TOPIC) && !generatedFromTemplate) {
          throw new Error('A repository with that name already exists and was not created by ClassRepo, so it was left alone.');
        }
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
      if (settings.codespaces_badge === true) await addCodespacesBadge(repoName); // best effort
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

    async function addCodespacesBadge(repoName) {
      const badge = `[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/${owner}/${repoName}?quickstart=1)`;
      try {
        const readme = await github.rest.repos.getContent({ owner, repo: repoName, path: 'README.md' }).catch(() => null);
        if (readme && readme.data) {
          const current = Buffer.from(readme.data.content, 'base64').toString('utf8');
          if (current.includes('codespaces.new')) return;
          await github.rest.repos.createOrUpdateFileContents({ owner, repo: repoName, path: 'README.md', message: 'Add Codespaces badge', content: Buffer.from(`${badge}\n\n${current}`).toString('base64'), sha: readme.data.sha });
        } else {
          await github.rest.repos.createOrUpdateFileContents({ owner, repo: repoName, path: 'README.md', message: 'Add Codespaces badge', content: Buffer.from(`${badge}\n`).toString('base64') });
        }
      } catch {
        core.warning('Could not add the Codespaces badge to one repository.');
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

    let repo = null;
    try {
      repo = (await github.rest.repos.get({ owner, repo: trackingRepo })).data;
    } catch (e) {
      if (e.status !== 404) return core.warning('Could not check the tracking repository; roster not recorded.');
      try {
        const type = (await github.rest.users.getByUsername({ username: owner })).data.type;
        if (type !== 'Organization') return core.warning('The tracking repository does not exist. Create a private repository with that name; roster not recorded.');
        repo = (await github.rest.repos.createInOrg({ org: owner, name: trackingRepo, private: true, description: 'ClassRepo student tracking logs' })).data;
      } catch {
        return core.warning('Could not create the tracking repository; roster not recorded.');
      }
    }
    if (!repo.private) return core.warning('The tracking repository is public, so the roster was NOT recorded. Make it private.');

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
