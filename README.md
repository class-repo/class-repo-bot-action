# ClassRepo Bot (action)

The code that does ClassRepo's work inside **your own GitHub account**: it creates a private repository for each student from your
template, invites them, and records the roster in your private tracking repository. You do not copy this code around. Your bot
repository (made from the [`class-repo-bot`](https://github.com/class-repo/class-repo-bot) template) contains a 30-line workflow that
*uses this action, pinned to an exact commit*, and GitHub proposes updates to you as pull requests.

```yaml
- uses: class-repo/class-repo-bot-action@<exact commit>   # v3.3.0
  with:
    batch-id: ${{ inputs.batch_id }}
    server-url: ${{ inputs.server_url }}
    app-id: ${{ secrets.CLASSREPO_APP_ID }}
    app-private-key: ${{ secrets.CLASSREPO_APP_PRIVATE_KEY }}
    roster-private-key: ${{ secrets.CLASSREPO_ROSTER_PRIVATE_KEY }}
```

The complete workflow is [`examples/provision.yml`](./examples/provision.yml).

## What the bot will and will not do

The ClassRepo server decides *when* a job runs and *which* students it is for. This bot decides what is **allowed**, because it holds your
Executor App's key. It enforces these rules whatever the server asks:

* Repositories are only ever created **private**.
* Students' repositories are generated only from a **snapshot** this bot made in your own account (`classrepo-snapshot-<code>`, labelled `classrepo-snapshot`),
  never from whatever repository a job names. The snapshot is a frozen private copy of your starter, made once per assignment; it is the one repository
  the bot ever marks as a template. Your allow-list of template owners, if you set one, applies to what the snapshot is copied *from*.
* Students get **at most push access** (or read-only). Never admin, maintain or triage.
* It **never deletes** anything and **never changes a repository's visibility**.
* It **only touches repositories ClassRepo created**: ones with the `classrepo` topic, or generated from the assignment's snapshot. A repository that merely
  has a matching name is left alone.
* A job that asks for anything this version does not understand is **refused whole**, with an "update your bot" message, rather than half done.

Student names, emails and handles arrive encrypted and are opened only with your roster key. Nothing identifying is written to the run's logs
(they may be public): progress is reported as "repository 3 of 40". The roster is only ever written to your **private** tracking repository. If you have none, the bot makes one from
[`class-repo-tracking-template`](https://github.com/class-repo/class-repo-tracking-template) (a README and nothing that can run), turns GitHub Actions off in it
before writing anything, and labels it. It does this early (when you run the setup check, and when an assignment's snapshot is made), so a problem
shows up before any student joins. It works in a personal account as well as an organization.
`docs/PROTOCOL.md` in [`class-repo-site`](https://github.com/class-repo/class-repo-site) describes the job format and what each future feature would cost.

## Trusting this action

Using an action means running its code with the secrets you pass it (here: your Executor App key and roster key). So:

* **It is pinned to an exact commit**, not a moving tag, so it cannot change under you.
* **Updates are pull requests you review.** Dependabot (already configured in the template) opens one when a release is published. The pull
  request shows the version and links to the changes; read them, as you would for any dependency, then merge.
* The action is small: `scripts/provision.js` (the work) and `scripts/roster-crypto.js` (opening encrypted records), using only Node's built-in
  modules, plus two GitHub-maintained actions that are themselves pinned to commits. It runs no shell commands of its own.
* Its tests read `action.yml` and the example workflow and fail if an action is unpinned, an input is pasted into a script, a shell step is added,
  or the workflow asks for more than the ability to prove its identity.
* If your organization restricts which actions may run, allow `class-repo/class-repo-bot-action` pinned by commit.

## Inputs

| Input | Required | |
| :--- | :--- | :--- |
| `batch-id`, `server-url` | yes | Set by the ClassRepo server when it starts the workflow. |
| `app-id`, `app-private-key` | yes | Your Executor App (secrets `CLASSREPO_APP_ID`, `CLASSREPO_APP_PRIVATE_KEY`). |
| `roster-private-key` | no | Your roster key (secret `CLASSREPO_ROSTER_PRIVATE_KEY`). Absent on the first run, which creates it. |
| `tracking-repo` | no | Your private roster repository (default `class-repo-tracking`). |
| `allowed-template-owners` | no | Comma-separated owners whose repositories may be used as templates. |

The workflow needs `permissions: id-token: write` so the run can prove its identity to the ClassRepo server. Nothing else.

## Versions

`v3.x` speaks protocol 3. A **patch** fixes a bug, a **minor** adds a capability without changing what existing jobs do, a **major** changes the
protocol (while ClassRepo is in alpha the server does not keep older formats, so update when asked). When the bot claims a job it tells the server its version, so the server
never sends a job to a bot that cannot do it, and your dashboard shows when yours needs updating. See [RELEASING.md](./RELEASING.md).

## When you do have to edit your workflow yourself

Updating the action changes nothing in your own repository's files. The one case that needs a manual edit is a release that **adds a new secret,
input or app permission**: those releases say so at the top of their notes, and we group such changes together so they are rare.

## `tools/provision.sh`

A manual fallback that creates repositories from your own terminal with your own `gh` login, for when ClassRepo is unavailable. It is **not used by
ClassRepo** and does not have the bot's built-in limits; see the comments at the top of the file.

## Development

```bash
npm test
```

No dependencies. `test/vector.json` and `test/job-example.json` come from the ClassRepo server's repository: the first proves records sealed by the
server open here, the second is a real job the server produces and the bot must carry out.
