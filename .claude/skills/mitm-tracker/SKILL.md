---
name: mitm-tracker
description: Inspect, mock, or reproduce HTTP/HTTPS traffic from a macOS app or iOS Simulator using the mitm-tracker CLI. Use when the user asks to capture network requests, list hosts/APIs the app calls, see what an endpoint returns, override a response with a local file (Map Local), reproduce a captured request as curl, debug TLS-decrypted traffic, set up Touch ID for the proxy, configure the menu-bar tray, or diagnose why mitm-tracker isn't working. Trigger phrases include "what APIs is the app calling", "intercept", "mock this response", "see the request body", "record traffic", "override endpoint", "Map Local", "decrypt HTTPS", "set up Touch ID for record", "tray icon", "mitm-tracker doctor", "why is the proxy broken", or any reference to mitmproxy/Charles Proxy in this workflow.
---

# mitm-tracker

CLI on top of `mitmproxy` that captures HTTP(S) flows into per-session SQLite, scopes TLS decryption per profile, and serves Map Local mocks. Designed to be operated by an agent.

## Mental model (read first)

Five facts that are not obvious from `--help`:

1. **Workspace is the cwd.** `mitm-tracker` resolves `.mitm-tracker/` from `Path.cwd()` with **no walk-up**. Running `query recent` from a subdirectory of a project that has a workspace at the root will silently create a fresh empty workspace there. Always `cd` to the project root that owns the running session before invoking any command. If the user runs a command and gets `no record sessions found` despite a session being active, this is almost always the cause.

2. **`record start` daemonizes.** It spawns `mitmdump` with `start_new_session=True`, returns immediately, and the proxy keeps running across terminal closes, ssh disconnects, etc. Only `record stop`, `kill <pid>`, or a Mac reboot stops it. After a crash the macOS proxy may stay pointed at `127.0.0.1:8080` with nothing listening — `record stop` cleans that up.

3. **SSL list changes do not hot-reload; Map Local rules do.** The SSL list becomes `--allow-hosts` for `mitmdump` at startup. Adding/removing a pattern requires `record stop && record start` to take effect. Map Local edits (rule changes, body file edits, enable/disable) are picked up on the next request automatically.

4. **Wildcards do not match the apex.** `*.example.com` matches `api.example.com`, `v1.api.example.com`, etc., but not the bare `example.com`. Add the apex as a separate entry when both are needed.

5. **The mitmproxy CA can become a stale orphan.** `~/.mitmproxy/mitmproxy-ca-cert.pem` is generated on the first `mitmdump` run and reused forever. If something deletes that file (a manual cleanup, `setup uninstall`, etc.), the next `record start` regenerates the CA with a **new fingerprint** — but the iOS Simulator still trusts the **old** one. Symptom: TLS suddenly fails inside the app even though `cert status` says installed. Fix: re-run `mitm-tracker cert install`. Cross-check with `mitm-tracker doctor` (shows the current CA's SHA256 in the Runtime state group).

## When to invoke this skill

- "What endpoints is this app hitting?" → `query hosts`, `query recent`
- "Why is this request failing / slow?" → `query failures`, `query slow`, `query show <seq>`
- "Reproduce this request outside the app" → `query curl <seq>`
- "Make `/api/users` return an empty list" → `maplocal from-flow <seq>` then edit the body
- "Capture network traffic from the simulator" → `record start`
- "I added a new SSL host but I don't see it decrypted" → restart record (gotcha #3)

## Workflow A — first-time setup in a new project

```bash
cd /path/to/project-root            # workspace anchors here
mitm-tracker doctor                 # show what's missing before configuring
mitm-tracker setup install          # one-time: tray + Touch ID + sudo cache (one prompt)
mitm-tracker doctor                 # confirm everything went green
mitm-tracker cert install           # installs CA into booted simulator(s)
mitm-tracker profile create <name> --use
mitm-tracker ssl add "*.api.example.com"
mitm-tracker ssl add "auth.example.com"
mitm-tracker record start           # Touch ID prompt instead of password (after setup install)
```

The simulator inherits the macOS system proxy automatically — no manual proxy config inside iOS Settings.

`setup install` is idempotent and cheap to re-run; if both Touch ID and sudo cache are already configured, it returns without invoking sudo. After running it once, subsequent `record start`/`record stop` typically share a single fingerprint tap (sudo cache is scoped to `networksetup` for 60 min).

## Workflow B — inspect a running capture

```bash
cd /path/to/project-root            # MUST be the workspace owner
mitm-tracker record status --json   # confirm running, see captured_count
mitm-tracker query recent --limit 20 --json
mitm-tracker query hosts --json
mitm-tracker query failures --json
mitm-tracker query show 42 --json   # full detail of one flow
```

If `query recent` returns `count: 0` but `record status` shows `captured_count > 0`, retry — there is a small SQLite flush lag.

## Workflow C — mock a response (Map Local)

```bash
mitm-tracker query recent --host api.example.com --limit 20
mitm-tracker maplocal from-flow 42 --description "force empty list"
# Output includes: body_path -> .mitm-tracker/profiles/<p>/maplocal-bodies/<id>.body
$EDITOR <body_path>                 # edit the JSON / payload
# Next request hits the rule. No restart needed.

mitm-tracker maplocal list --json
mitm-tracker maplocal disable <id>
mitm-tracker maplocal enable <id>
mitm-tracker maplocal remove <id>   # also deletes body + headers files
```

The addon strips length-dependent headers (`Content-Length`, `ETag`, `Last-Modified`, `Transfer-Encoding`, `Content-Encoding`) on synthesized responses, so editing the body never desyncs the wire format. Cache headers are also rewritten so the client cannot serve a stale copy.

## Workflow D — reproduce a captured request

```bash
mitm-tracker query curl 42                  # multiline, all headers preserved
mitm-tracker query curl 42 --single-line    # single line (for log paste)
mitm-tracker query curl 42 --body-dir /tmp  # binary body dumped here, referenced via @file
```

Header case is preserved exactly; HTTP version is explicit. Run as-is in another terminal to hit the real server.

## Workflow E — clean up

```bash
mitm-tracker record stop                       # restores the macOS proxy
mitm-tracker release --older-than 24h --dry-run
mitm-tracker release --older-than 7d           # actually delete
```

The active session and any session whose `mitmdump` is still running are protected.

## Workflow F — continuous visual status (optional)

```bash
pipx install -e ".[tray]"                      # one-time: enables rumps
cd /path/to/the/app/repo
mitm-tracker tray install                      # one-time: auto-launch on login (writes a LaunchAgent)
```

After `install`, the icon appears immediately and on every subsequent login. Icon: 🟢 running, 🔴 stopped, 🟡 zombie (PID dead but state says running). Menu shows active profile + SSL host count, workspace path, and Start/Stop record actions. Useful for spotting the zombie-state failure mode without polling `record status` manually.

Click "Quit tray" to exit cleanly: if a record session is RUNNING or CRASHED, the tray runs `record stop` first (one Touch ID tap, restores system proxy, kills mitmdump) before tearing itself down. Plain "Stop record" stops the daemon but keeps the tray alive. The tray sets `NSApplicationActivationPolicyAccessory` at runtime so it doesn't appear in the Dock or Cmd-Tab.

Other actions:

- `mitm-tracker tray status` — print install/load state, current PID, watched workspace
- `mitm-tracker tray uninstall` — remove the LaunchAgent (disables auto-launch)
- `mitm-tracker tray run` — open foreground without registering a LaunchAgent
- To switch the watched workspace: `cd <new-repo> && mitm-tracker tray install` (replaces the existing plist)

## Command reference

| Command | Purpose | Key flags |
|---|---|---|
| `profile {create,use,list,show,delete}` | Profile lifecycle (each has own SSL list + Map Local rules) | `--use` on create activates immediately |
| `ssl {add,remove,list}` | Manage TLS-decryption hosts for a profile | `--profile <name>` to target a non-active profile |
| `maplocal {add,from-flow,list,show,edit,enable,disable,remove}` | Local response overrides | `from-flow <seq>` clones a captured response |
| `cert {install,status,simulators}` | Install mitmproxy CA into booted simulator(s) | iOS 26 uses `TrustStore.sqlite3` (sha256); legacy keychain (sha1) still supported |
| `record {start,stop,status,logs}` | Capture session lifecycle | `--keep-cache` to disable the default cache-stripping; `--port N` to override 8080 |
| `query {recent,failures,slow,hosts,show,sql,curl,sessions,use}` | Inspect captured flows | `--json` on every subcommand; `query use <session>` switches active DB |
| `release [--older-than 24h] [--dry-run]` | Delete stale capture databases | `--no-keep-active` to allow deleting the active one |
| `tray {run,install,uninstall,status}` | macOS menu bar indicator (🟢/🔴/🟡); requires `[tray]` extra | `tray install` registers a LaunchAgent for auto-launch on login; `tray run` is foreground only |
| `setup {install,uninstall,status}` | One-shot configurator: tray + Touch ID + 60min sudo cache scoped to `networksetup` | macOS Sonoma+ only. Idempotent. `--skip-touch-id`/`--skip-sudo-cache`/`--skip-tray` for granularity |
| `doctor` | Health check across system, tools, setup state, runtime | Use to diagnose "why doesn't X work" before guessing. Prints `fix:` hints for each non-OK check; exit 0/2/3 by severity |

Every subcommand accepts `--json`. Exit codes: `0` success, `1` usage error, `2` invalid state, `3` system failure.

## SQL escape hatch

`query sql` runs read-only SELECTs against the `flows` table. Useful for token-efficient custom aggregations — only the columns you need:

```bash
mitm-tracker query sql "SELECT host, AVG(duration_total_ms) AS avg_ms, COUNT(*) AS n FROM flows GROUP BY host ORDER BY n DESC"
mitm-tracker query sql "SELECT seq, method, host, path, response_status_code FROM flows WHERE response_status_code >= 400"
```

Useful columns: `seq`, `method`, `host`, `path`, `response_status_code`, `duration_total_ms`, `tls_decrypted`, `error_msg`, `request_body_raw`, `response_body_raw`. The `*_body_raw` columns can be huge; avoid `SELECT *` when you don't need them.

## When something is broken

Run `mitm-tracker doctor` first. It tells you exactly what's missing and gives the command to fix it. Beats guessing.

## Gotchas checklist

- **`no record sessions found`** → wrong cwd. `cd` to the project root that owns the workspace.
- **HTTPS host shows up as `CONNECT` only, no path/body** → host not in the active profile's SSL list, or SSL list was edited without restarting record.
- **App still serves cached responses after a Map Local change** → ensure record was started without `--keep-cache` (the default strips cache). Force-quitting the app is rarely needed because the addon neutralizes `Cache-Control`/`ETag`/`Last-Modified`/conditional headers.
- **`record status` shows `running: false, crashed: true`** → daemon died but proxy state is dirty. Run `record stop` to clean up before `record start`.
- **`query show <seq> --json` is huge** → it dumps `request_body_raw` and `response_body_raw`. Prefer `query sql` selecting only the columns you need, or pipe through `jq` to drop the body fields.
- **Apex domain not matched** → `*.example.com` does not cover `example.com`. Add both.
- **Cert install on a non-booted simulator** → `cert install` only targets booted devices. Boot the simulator first (`xcrun simctl boot <udid>`).
- **App's TLS suddenly broke after a cleanup** → the mitmproxy CA was likely regenerated. Run `mitm-tracker cert install` to push the new CA. See mental model #5.
- **`record stop` returned exit 0 but the system proxy is still on `127.0.0.1:8080`** → no, it doesn't anymore: the new code returns `EXIT_SYSTEM` on partial failure and emits a structured error on stderr that the tray surfaces as `rumps.alert`. If you still see this, the user is running an old build — `pipx reinstall mitm-tracker` and re-run `setup install`.
- **Pre-Sonoma macOS (< 14.0)** → `setup install` will write `/etc/pam.d/sudo_local` but Touch ID will not actually trigger because pre-Sonoma's `/etc/pam.d/sudo` does not include `sudo_local`. `mitm-tracker doctor` warns on the macOS version check; tell the user to upgrade or skip with `--skip-touch-id`.

## Profile-scoped configuration

Each profile owns its own:
- `profiles/<name>/ssl.json` — TLS decryption list
- `profiles/<name>/maplocal.json` — Map Local rules
- `profiles/<name>/maplocal-bodies/` — response bodies + per-rule headers

Switching profiles (`profile use <name>`) does **not** restart the running record. The SSL list of the *currently running* mitmdump is whatever was active at `record start`. To apply a new profile to live capture: `record stop && record start` (after `profile use`).

## JSON-mode contract

All commands accept `--json` and emit a stable shape. Errors in JSON mode go to stderr as `{"error": "<code>", "message": "..."}`. Prefer `--json` when parsing programmatically.
