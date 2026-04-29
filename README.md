# mitm-tracker

A Charles Proxy-style HTTP(S) interception toolkit with SQLite capture and an
agent-friendly CLI. Built on top of [mitmproxy](https://mitmproxy.org/) and
designed to be operated by either humans or coding agents.

mitm-tracker captures every HTTP/HTTPS flow that passes through the proxy
into a per-session SQLite database (one row per request, in chronological
order), lets you reproduce any captured request as a faithful `curl` command,
overrides API responses with local JSON files (Map Local), and disables HTTP
caching by default so changes take effect immediately on the device.

It targets the iOS simulator workflow — installing the mitmproxy CA, scoping
TLS decryption to specific domains per profile, and surviving the iOS 26
TrustStore changes — but the proxy itself works for anything that respects
the macOS system proxy.

---

## Highlights

- **Profile-scoped configuration.** Each profile has its own SSL list and
  Map Local rules, so different repositories can share the same install
  without leaking config into each other.
- **Map Local from a real flow.** `maplocal from-flow <seq>` clones the
  response body and headers of any captured request, drops them in a JSON
  file you can edit, and serves the result on the next request.
- **Hot-reload of Map Local rules.** Add, edit, enable, disable, or remove
  rules while the proxy is running — the addon re-reads the on-disk
  signature on every request and reloads only when something changed.
- **No-cache by default.** Cache-Control, ETag, Last-Modified, and
  conditional request headers are neutralized on every flow so the iOS
  client always re-fetches and sees mocked responses without force-quit.
  Disable per-session with `--keep-cache` when you actually want to test
  caching.
- **Faithful curl reproduction.** `query curl <seq>` rebuilds the exact
  request that was captured — every header preserved, original case,
  http version explicit, binary bodies dumped to a `--data-binary` file.
- **iOS 26 simulator CA install.** `cert install` writes to the new
  `data/private/var/protected/trustd/private/TrustStore.sqlite3` (sha256)
  while still supporting the legacy keychain path (sha1).
- **Privileged proxy via osascript.** `record start` triggers the native
  macOS authorization dialog (same UX as Charles), groups all
  `networksetup` commands into a single prompt, and restores the original
  proxy on `record stop`.
- **Disk hygiene.** `release --older-than 24h` removes stale capture
  databases while protecting the active and running sessions.

---

## Requirements

- macOS (Intel or Apple Silicon)
- Python 3.11+
- [mitmproxy](https://mitmproxy.org/) installed via Homebrew
- [pipx](https://pipx.pypa.io/) for the editable install
- Xcode command line tools (`xcrun simctl`) for the iOS simulator features

---

## Install

```bash
brew install mitmproxy pipx
pipx ensurepath

git clone https://github.com/quixabeira-rafael/mitm-tracker.git
cd mitm-tracker
pipx install -e ".[dev,tray]"          # `tray` enables the menu bar indicator
```

`pipx install -e .` installs the project in editable mode. The
`mitm-tracker` command becomes available on your `PATH` and code changes in
the source tree take effect on the next invocation.

For the full integrated experience, run the following one-time setup from
the repo of the app you intend to debug:

```bash
cd /path/to/the/app/repo
mitm-tracker setup install
```

That single command — under one authentication prompt — does three things:

1. Registers a per-user LaunchAgent so the **tray** indicator re-opens on
   every login (see [Visual status in the macOS menu bar](#visual-status-in-the-macos-menu-bar)).
2. Configures **Touch ID** as a sudo authentication factor (writes
   `/etc/pam.d/sudo_local` with `auth sufficient pam_tid.so`). After this,
   `record start`/`record stop` prompt for your fingerprint instead of your
   password.
3. **Extends the sudo cache to 60 minutes for `networksetup` only** (writes
   `/etc/sudoers.d/mitm-tracker` with `Defaults!/usr/sbin/networksetup
   timestamp_timeout=60`). A typical debug cycle (start → exercise app →
   stop) needs only one Touch ID tap. The cache is **not** global — other
   `sudo` commands keep their default 5-minute timeout.

Skip components with `--skip-touch-id`, `--skip-sudo-cache`, `--skip-tray`.
Reverse everything with `mitm-tracker setup uninstall`. Inspect with
`mitm-tracker setup status`.

Requires macOS Sonoma (14.0) or later — older versions don't have
`/etc/pam.d/sudo_local`.

Verify the install:

```bash
mitm-tracker --version
mitm-tracker --help
mitm-tracker doctor          # checks deps, OS version, hardware, setup state
```

`mitm-tracker doctor` runs ~14 checks across system (macOS version,
architecture, Python), required tools (`mitmdump`, `xcrun`, `pam_tid.so`),
optional features (rumps, Touch ID config, sudo cache, tray LaunchAgent),
and runtime state (workspace, record session, mitmproxy CA, booted iOS
simulators). Exit code: `0` all green, `2` warnings only, `3` errors.
Each check that's not OK prints a `fix:` hint with the exact command to
resolve it.

### Claude Code skill (optional, available across all projects)

The repository ships a [Claude Code](https://docs.claude.com/en/docs/claude-code)
skill at [`.claude/skills/mitm-tracker/SKILL.md`](.claude/skills/mitm-tracker/SKILL.md).
The skill teaches Claude how to use `mitm-tracker` end-to-end: capture
APIs, mock responses, reproduce as curl, run `doctor`, manage the tray,
plus all the gotchas accumulated from real use (CA-regen trap, zombie
proxy detection, pre-Sonoma Touch ID limits, etc.).

To make the skill available to Claude Code in **any** repo (not just
this one), install it at user level — `mitm-tracker` will symlink it
into `~/.claude/skills/mitm-tracker/`:

```bash
mitm-tracker skill install        # symlink ~/.claude/skills/mitm-tracker -> repo
mitm-tracker skill status         # confirm symlink is managed
mitm-tracker skill uninstall      # remove the symlink (only if we own it)
```

`mitm-tracker setup install` also offers to do this for you — when it
detects `~/.claude` and an interactive terminal, it prompts:

```
Claude Code detected. Install the mitm-tracker skill at user level
(~/.claude/skills/mitm-tracker)? [Y/n]
```

Because the user-level copy is a **symlink** to the repo, `git pull`
keeps your installed skill up-to-date automatically. Use
`--skip-skill` (no prompt, don't install) or `--with-skill` (no prompt,
do install) for non-interactive flows.

If you maintain your own personal copy at `~/.claude/skills/mitm-tracker/`
that **isn't** the symlink we manage, `skill uninstall` leaves it
untouched. Per Claude Code's
[skill discovery](https://code.claude.com/docs/en/skills) precedence
(enterprise > personal > project), running Claude Code inside this repo
also finds the project-level skill at `.claude/skills/`.

---

## First-time setup for an iOS simulator workflow

```bash
# 1. Boot the iOS simulator you want to use (via Xcode or `xcrun simctl boot`).

# 2. Install the mitmproxy CA into the simulator's trust store.
mitm-tracker cert install
mitm-tracker cert status --json   # cert_installed should be true

# 3. Pick a profile and add the hosts you want to TLS-decrypt.
cd /path/to/the/app/repo
mitm-tracker profile create my-app --use
mitm-tracker ssl add "*.api.example.com"
mitm-tracker ssl add "auth.example.com"

# 4. Start a capture session with the macOS proxy enabled.
mitm-tracker record start
# A native macOS dialog will ask for your password — that's expected.
# The proxy is restored automatically on `record stop`.

# 5. Use the simulator. Captured flows accumulate in
#    .mitm-tracker/captures/<timestamp>_<profile>.db
mitm-tracker query recent --json
mitm-tracker query hosts --json
```

When you're done:

```bash
mitm-tracker record stop
```

---

## Working directory layout

`mitm-tracker` operates relative to the current working directory. The first
time you run a command in a repo, it creates `.mitm-tracker/`:

```
<your-repo>/.mitm-tracker/
├── profiles/
│   ├── default/
│   │   ├── ssl.json                # SSL decryption list
│   │   ├── maplocal.json           # Map Local rules
│   │   └── maplocal-bodies/        # response bodies + headers
│   └── my-app/                     # additional profiles
├── runtime/
│   ├── mitmproxy.pid
│   ├── mitmproxy.log
│   ├── state.json                  # active profile, active session, etc.
│   └── proxy_backup.json           # restored on `record stop`
└── captures/
    └── 2026-04-28_172537_my-app.db # one SQLite database per session
```

The active profile and active session are kept in `state.json`. Switch them
with `profile use <name>` and `query use <session>`.

---

## Workflows

### Capture and inspect API traffic

```bash
mitm-tracker record start
# … use the app …
mitm-tracker query recent --limit 50 --json
mitm-tracker query failures --json          # 4xx / 5xx and connection errors
mitm-tracker query slow --threshold-ms 1000 # responses slower than 1s
mitm-tracker query hosts --json             # per-host counts
mitm-tracker query show 42 --json           # full detail of one flow
mitm-tracker query sql "SELECT method, host, COUNT(*) AS n FROM flows GROUP BY 1,2 ORDER BY n DESC"
```

### Reproduce a captured request as curl

```bash
mitm-tracker query curl 42
# Multiline curl with every original header, preserving case.
# Run it as-is in another terminal to hit the real server.

mitm-tracker query curl 42 --single-line   # for log paste
```

Binary bodies are written next to the cwd as `flow_<seq>.body.bin` and
referenced via `--data-binary @file`.

### Override an API response (Map Local)

```bash
# 1. Find the flow you want to mock and clone it.
mitm-tracker query recent --host api.example.com
mitm-tracker maplocal from-flow 42 --description "force users empty list"

# 2. Edit the cloned body — the file path is in the JSON output above.
$EDITOR .mitm-tracker/profiles/my-app/maplocal-bodies/<id>.body

# 3. Hot-reload picks up the change on the next request.
#    No need to restart the proxy.

mitm-tracker maplocal list
mitm-tracker maplocal disable <id>   # turn off without deleting
mitm-tracker maplocal enable <id>
mitm-tracker maplocal remove <id>    # also deletes the body and headers files
```

The addon strips length-dependent headers (`Content-Length`, `ETag`,
`Last-Modified`, `Transfer-Encoding`, `Content-Encoding`) on the synthesized
response, so editing the body never desyncs the wire format. Cache headers
are also rewritten so the client cannot serve a stale copy.

### Switch between historical sessions

```bash
mitm-tracker query sessions --json
mitm-tracker query use 2026-04-28_172537_my-app.db
mitm-tracker query recent --json    # now reads from the chosen session
```

### Multiple profiles

```bash
mitm-tracker profile create staging
mitm-tracker profile create prod-debug
mitm-tracker profile use staging
mitm-tracker ssl add "*.staging.example.com"
mitm-tracker maplocal add "https://api.staging.example.com/users/*" --status 200 --body-file mocks/users.json
```

Each profile has its own SSL list and Map Local rules; the active profile is
recorded in `state.json` and survives across `record start/stop` cycles.

### Free disk space

```bash
mitm-tracker release --older-than 24h --dry-run   # preview
mitm-tracker release --older-than 24h             # actually delete
mitm-tracker release --older-than 7d              # 7-day window
```

The active session and any session with a running mitmdump are always
preserved.

### Visual status in the macOS menu bar

```bash
pipx install -e ".[tray]"        # one-time: enable the optional rumps dep
cd /path/to/the/app/repo
mitm-tracker tray install        # one-time: auto-launch on every login
```

After `tray install`, an icon will appear in the menu bar immediately and
on every subsequent login. The icon mirrors the daemon state:

- 🟢 green — `mitmdump` is running and healthy
- 🔴 red — not recording
- 🟡 yellow — zombie state (`state.json` says running, but the PID is dead);
  run `record stop` to clean up

Click the icon to see the active profile, workspace path, and live PID/port,
and to start/stop the record without leaving the menu bar.

To manage the LaunchAgent later:

```bash
mitm-tracker tray status         # show install / load state and current PID
mitm-tracker tray uninstall      # disable auto-launch (stops it now too)
mitm-tracker tray run            # ad-hoc, foreground (no LaunchAgent)
```

The workspace path is captured at `tray install` time. To switch which
project the tray watches, run `tray install` again from the new workspace.

---

## Command reference

```
mitm-tracker profile {create,use,list,show,delete}
mitm-tracker ssl     {add,remove,list}
mitm-tracker maplocal {add,from-flow,list,show,edit,enable,disable,remove}
mitm-tracker cert    {install,status,simulators}
mitm-tracker record  {start,stop,status,logs}
mitm-tracker query   {recent,failures,slow,hosts,show,sql,curl,sessions,use}
mitm-tracker release [--older-than 24h] [--dry-run] [--no-keep-active]
mitm-tracker tray    {run,install,uninstall,status}  # macOS menu bar indicator (extra: [tray])
mitm-tracker setup   {install,uninstall,status}      # Touch ID + sudo cache + tray + (optional) Claude skill
mitm-tracker skill   {install,uninstall,status}      # Symlink Claude Code skill into ~/.claude/skills/
mitm-tracker doctor                                  # diagnose environment / report fixable issues
```

Every subcommand accepts `--json` and returns a predictable structured
payload. Exit codes:

- `0` — success
- `1` — usage error (invalid argument)
- `2` — invalid state (e.g. `record stop` when nothing is running)
- `3` — system failure (mitmproxy missing, permission denied, etc.)

Errors in `--json` mode go to stderr as `{"error": "<code>", "message": "..."}`.

---

## How TLS decryption is scoped

`mitm-tracker` builds a regex from the SSL list of the active profile and
passes it to mitmproxy as `--allow-hosts`. Only hosts matching the regex are
TLS-decrypted; everything else passes through as raw `CONNECT`. This is how
Charles Proxy's per-host SSL list behaves and is the right balance between
debuggability and not breaking apps with certificate pinning on unrelated
hosts.

Wildcards: `*.example.com` matches `api.example.com`, `v1.api.example.com`,
etc., but not the bare `example.com`. Use a separate entry for the apex
domain if you need it.

---

## Map Local match modes

Each rule pattern is parsed as `scheme://host[:port]/path[?query]`.

- **Host:** `*.example.com` matches any subdomain.
- **Path:** `*` matches one segment, `**` matches any depth.
- **Query string:** four modes, configurable per rule:
  - `ignore` (default) — query string is irrelevant.
  - `exact` — full string equality, including ordering.
  - `contains` — every param in the pattern must be present (extras allowed,
    order free); param values support `*` glob.
  - `equals` — same multiset of params, any order, no extras.

The first enabled rule that matches a request wins.

---

## Run the test suite

```bash
pipx install -e ".[dev]"   # if not already done
cd mitm-tracker
pytest                       # full suite (~350 tests, < 5s)
pytest tests/unit            # unit only
pytest tests/integration -v  # mitmproxy addon integration tests
pytest -k maplocal           # filter by keyword
```

Integration tests use `mitmproxy.test.taddons` and `tflow.tflow()` to drive
the real addon against the in-memory test harness — no network involved.

---

## Project layout

```
src/mitm_tracker/
├── cli.py                 # argparse dispatch and global error handling
├── config.py              # workspace path resolution, profile naming
├── output.py              # JSON / table emit, exit codes
│
├── store.py               # FlowStore (SQLite layer)
├── schema.py              # CREATE TABLE statements and column list
├── addon.py               # TrackerAddon — the mitmproxy hook surface
│
├── proxy_manager.py       # macOS networksetup wrapper, osascript prompt
├── session_manager.py     # state.json + PID lifecycle
├── profile_manager.py     # profile CRUD and active selection
├── ssl_list.py            # JSON-backed SSL decryption list
├── maplocal.py            # JSON + body files for Map Local rules
├── url_matcher.py         # host/path glob and four query-string modes
├── curl_export.py         # rigorous curl reproduction
├── release.py             # capture-database cleanup
├── simulators.py          # xcrun simctl wrapper
├── cert_manager.py        # iOS simulator TrustStore install (sha256/sha1)
│
└── commands/              # one file per top-level subcommand
    ├── profile.py
    ├── ssl.py
    ├── maplocal.py
    ├── cert.py
    ├── record.py
    ├── query.py
    └── release.py
tests/
├── unit/                  # pure unit tests (no network, no real subprocess)
└── integration/           # addon tests via mitmproxy.test
```

---

## Known limitations

- macOS only. The proxy automation uses `networksetup` and `osascript`.
- Physical iOS devices are out of scope for `cert install`. Install the CA
  manually via `mitm.it` in Safari and the Settings app.
- Apps with strict certificate pinning on a host can refuse to talk to the
  proxy even with the CA trusted. Pinning is by design — there is no
  workaround at the mitmproxy layer.
- WebSocket frames are not currently captured (the schema has the column but
  the addon does not populate it yet).
- Map Local rewrites the response only. Request rewriting, throttling, and
  Map Remote are not implemented.

---

## License

MIT.
