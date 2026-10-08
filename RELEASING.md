# Releasing

Educators run this code with their own keys, so a release is a security event. Take it slowly.

## Before you tag

1. Change the code and its tests. Run `npm test`.
2. Raise `version` in `package.json` **and** the `# vX.Y.Z` comment in `examples/provision.yml` (a test checks they match).
3. If the change adds a **secret, input or app permission**, say so at the top of the release notes and, if possible, hold it until it can ship with
   other changes of that kind. Those are the releases educators must act on by hand.
4. If the job format changed, update `server/src/protocol.js` and `docs/PROTOCOL.md` in `class-repo-site`, regenerate the shared example
   (`WRITE_JOB_EXAMPLE=1 npx vitest run test/job-example.test.js` in `server/`), and copy `server/test/fixtures/job-example.json` to
   `test/job-example.json` here. A new **major** protocol: keep serving the previous one for a while.
5. Open a pull request, have someone else read it, merge. (Recommended repository settings: protect `main`, require a review, require signed commits.)

## Tagging

1. On the merge commit, create an **annotated** tag `vX.Y.Z` and push it. Never move or delete a published tag: educators pin commits, and
   Dependabot reads tags. If a release is bad, publish a new one.
2. Publish a GitHub release with notes: what changed, whether educators must edit anything, whether the protocol changed.
3. Update the pinned commit in the `class-repo-bot` template repository's workflow to the new release commit.

Educators who already use the bot get a Dependabot pull request for the new version; their dashboard shows a warning if their version is too old
for what the server now sends.

## The repository must be public

Educators' Dependabot and workflows have to be able to read it.
