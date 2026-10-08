// The other tests use a fake GitHub, which can only be as right as our idea of what the real client offers. This one asks the
// real client: every github.rest.<group>.<method> the bot calls must exist in the Octokit that actions/github-script runs.
// (That is how users.getById, which the real client lacks, slipped past the fake.) Keep @actions/github in step with the
// github-script version pinned in action.yml (github-script v7 uses @actions/github 6).
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { getOctokit } = require('@actions/github');

test('every GitHub method the bot calls exists in the real client', () => {
  const octokit = getOctokit('test-token');
  const source = fs.readFileSync(path.join(__dirname, '..', 'scripts', 'provision.js'), 'utf8');
  const used = [...new Set([...source.matchAll(/github\.rest\.(\w+)\.(\w+)/g)].map(m => `${m[1]}.${m[2]}`))];
  assert.ok(used.length >= 8, 'expected to find the GitHub calls');
  for (const name of used) {
    const [group, method] = name.split('.');
    assert.equal(typeof (octokit.rest[group] || {})[method], 'function', `${name} does not exist in github-script's Octokit`);
  }
  assert.equal(typeof octokit.request, 'function');
});
