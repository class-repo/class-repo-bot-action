'use strict';
// action.yml, the example workflow educators copy, and scripts/provision.js have to agree with each other. These tests read the
// files as text (the package has no dependencies) and check the things that would otherwise only fail on an educator's machine.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const action = read('action.yml');
const example = read('examples/provision.yml');
const script = read('scripts/provision.js');
const pkg = JSON.parse(read('package.json'));

// The keys directly under a top-level block, e.g. the input names under `inputs:`.
function keysUnder(text, block) {
  const lines = text.split('\n');
  const start = lines.findIndex(l => l === `${block}:`);
  assert.ok(start >= 0, `no ${block}: block`);
  const keys = [];
  for (const line of lines.slice(start + 1)) {
    if (/^\S/.test(line)) break;
    const m = line.match(/^ {2}([A-Za-z0-9_-]+):/);
    if (m) keys.push(m[1]);
  }
  return keys;
}

const withKeys = text => {
  const lines = text.split('\n');
  const start = lines.findIndex(l => /^\s+with:\s*$/.test(l));
  const indent = lines[start].match(/^\s*/)[0].length;
  const keys = [];
  for (const line of lines.slice(start + 1)) {
    if (line.trim() && line.match(/^\s*/)[0].length <= indent) break;
    const m = line.match(/^\s+([a-z][a-z0-9-]*):/);
    if (m) keys.push(m[1]);
  }
  return keys;
};

test('it is a composite action that runs no shell commands of its own', () => {
  assert.match(action, /^\s+using: composite$/m);
  assert.ok(!/^\s+-?\s*run:/m.test(action), 'the action must not contain run: steps');
  assert.ok(!/^\s+shell:/m.test(action));
});

test('every action it uses is pinned to an exact commit', () => {
  const uses = [...action.matchAll(/^\s+uses:\s*(\S+)(.*)$/gm)];
  assert.ok(uses.length >= 2);
  for (const [, u, rest] of uses) {
    assert.match(u, /^[\w.-]+\/[\w.-]+@[0-9a-f]{40}$/, `${u} is not pinned to a commit`);
    // Dependabot keeps a same-line version comment in step when it updates the commit.
    assert.match(rest, /^\s+# v\d+\.\d+\.\d+$/, `${u} should carry its version in a same-line comment`);
  }
});

test('inputs are only ever the whole value of a with:/env: line, never pasted into script text (no injection)', () => {
  for (const line of action.split('\n').filter(l => l.includes('${{ inputs.'))) {
    assert.match(line.trim(), /^[A-Za-z0-9_-]+: \$\{\{ inputs\.[A-Za-z0-9_-]+ \}\}$/, `unsafe use of an input: ${line.trim()}`);
  }
});

test('the inputs it declares are exactly the ones it uses', () => {
  const declared = keysUnder(action, 'inputs').sort();
  const used = [...new Set([...action.matchAll(/\$\{\{ inputs\.([A-Za-z0-9_-]+) \}\}/g)].map(m => m[1]))].sort();
  assert.deepEqual(declared, used);
});

test('every environment variable provision.js reads is set by the action', () => {
  const read_ = [...new Set([...script.matchAll(/\benv\.([A-Z][A-Z0-9_]+)/g)].map(m => m[1]))].filter(n => n !== 'RUNNER_TEMP'); // the runner sets that one
  const envBlock = action.slice(action.indexOf('env:'), action.indexOf('with:', action.indexOf('env:')));
  for (const name of read_) assert.match(envBlock, new RegExp(`^\\s+${name}:`, 'm'), `${name} is read by provision.js but not set by action.yml`);
});

test('the example workflow educators copy passes every input the action declares', () => {
  assert.deepEqual(withKeys(example).sort(), keysUnder(action, 'inputs').sort());
});

test('the example workflow asks for nothing but the ability to prove its identity, and runs no commands', () => {
  assert.match(example, /^permissions: \{\}$/m);
  assert.match(example, /^\s+permissions:\n\s+id-token: write/m);
  assert.deepEqual([...example.matchAll(/^\s+(\w[\w-]*): (?:read|write)\b/gm)].map(m => m[1]), ['id-token']);
  assert.ok(!/^\s+-?\s*run:/m.test(example));
});

test('the example workflow keeps the dispatch input names the server uses', () => {
  assert.match(example, /^\s{6}batch_id:/m);
  assert.match(example, /^\s{6}server_url:/m);
});

test('the example pins the action to a commit (or the placeholder to replace on release) and names the release', () => {
  const m = example.match(/uses: class-repo\/class-repo-bot-action@(\S+) # v(\S+)$/m);
  assert.ok(m, 'the example must use class-repo/class-repo-bot-action@<commit> # vX.Y.Z on one line (Dependabot reads the same-line comment)');
  assert.match(m[1], /^([0-9a-f]{40}|REPLACE_WITH_RELEASE_COMMIT)$/);
  // The version in the comment is what Dependabot tracks, so it must match this release.
  assert.equal(m[2], pkg.version);
});

test('no secret value is ever written into the example', () => {
  for (const name of ['CLASSREPO_APP_ID', 'CLASSREPO_APP_PRIVATE_KEY', 'CLASSREPO_ROSTER_PRIVATE_KEY']) {
    assert.ok(example.includes(`\${{ secrets.${name} }}`), `${name} should come from secrets`);
  }
  assert.ok(!/BEGIN [A-Z ]*PRIVATE KEY/.test(example + action));
});
