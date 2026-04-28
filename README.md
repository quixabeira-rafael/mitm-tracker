# mitm-tracker

A Charles-like HTTP(S) proxy with SQLite capture and an agent-friendly CLI.

## Status

Alpha. Under active development. The MVP covers:

- `record` — start/stop/status/logs of a capture session
- `ssl` — manage which domains get TLS-decrypted
- `cert install` — install the mitmproxy CA in booted iOS simulators
- `query` — inspect captured flows from the SQLite session database

## Requirements

- macOS (Apple Silicon or Intel)
- Python 3.11+
- [mitmproxy](https://mitmproxy.org/) on `PATH`
- [pipx](https://pipx.pypa.io/)
- Xcode command line tools (`xcrun simctl`) for iOS simulator features

## Install

```bash
brew install mitmproxy pipx
pipx ensurepath

cd /Users/rafaelquixabeira/Documents/personal/mitm-tracker
pipx install -e ".[dev]"
```

`pipx install -e .` installs the project in editable mode and exposes the
`mitm-tracker` command globally. Code changes inside this repo take effect
immediately on the next invocation.

## Run tests

```bash
pip install -e ".[dev]"
pytest
```

Or, scoped:

```bash
pytest tests/unit
pytest tests/integration -v
pytest -k store
```

## Project layout

```
src/mitm_tracker/        package source
  cli.py                 CLI entry point and dispatch
  config.py              path / repo-root resolution
  store.py               SQLite layer (FlowStore)
  schema.py              CREATE TABLE statements + version
  addon.py               mitmproxy addon (TrackerAddon)
  proxy_manager.py       macOS networksetup wrapper
  session_manager.py     state.json + PID lifecycle
  ssl_list.py            SSL domain list (JSON)
  cert_manager.py        iOS simulator CA install
  simulators.py          xcrun simctl wrapper
  commands/              CLI subcommand implementations
tests/
  unit/                  pure unit tests
  integration/           addon integration tests via mitmproxy.test
```

When `mitm-tracker` runs from another directory, it creates a working
directory `.mitm-tracker/` in the current working directory:

```
<your-repo>/.mitm-tracker/
  runtime/         pid, log, state.json, proxy backup
  ssl.json         SSL list (versioned)
  captures/        one .db per record session
```

## License

MIT.
