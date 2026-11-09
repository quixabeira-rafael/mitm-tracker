from __future__ import annotations

from typing import Any

EXAMPLE_SCRIPT = '''"""Cart fails once with 503; orders arrives 1.5s late."""

CLAIMS = ["https://api.example.com/cart/**"]


def on_request(request):
    if request.path == "/cart" and store.incr("cart_calls") == 1:
        request.respond(503, json={"error": "unavailable"})


def on_response(request, response):
    if request.path == "/orders":
        response.delay = 1500
'''

REFERENCE: dict[str, Any] = {
    "layout": {
        "plan_dir": ".mitm-tracker/profiles/<profile>/tests/<plan>/",
        "files": {
            "plan.json": "{\"title\": ..., \"description\": ...}",
            "<case>.py": "one script per test case; the module docstring is its description",
            "state.json": "key/value store shared by every case of the plan",
        },
        "names": "letters, digits, '_' and '-', max 64 chars",
    },
    "hooks": [
        {
            "signature": "on_request(request)",
            "runs": "before Map Local and the server; can rewrite the request, answer locally, abort, claim, or delay",
        },
        {
            "signature": "on_response(request, response)",
            "runs": "on every response (local, Map Local, or upstream) before the app receives it",
        },
    ],
    "globals": [
        {
            "name": "CLAIMS",
            "type": "list[str]",
            "doc": "literal list of URL patterns (Map Local syntax, scheme required, e.g. https://api.example.com/users/**); matching requests skip Map Local",
        },
        {
            "name": "store",
            "type": "StateStore",
            "doc": "injected global, no import needed; persisted as JSON, thread- and process-safe",
        },
    ],
    "request": [
        {"name": "method", "access": "get/set", "doc": "HTTP method"},
        {"name": "url", "access": "get", "doc": "full URL"},
        {"name": "scheme", "access": "get", "doc": "http or https"},
        {"name": "host", "access": "get/set", "doc": "host name"},
        {"name": "port", "access": "get", "doc": "port number"},
        {"name": "path", "access": "get/set", "doc": "path without the query string (setting keeps the query)"},
        {"name": "query", "access": "mutable", "doc": "query parameters (dict-like)"},
        {"name": "headers", "access": "mutable", "doc": "request headers (dict-like)"},
        {"name": "body", "access": "get/set", "doc": "raw bytes (str accepted on set)"},
        {"name": "text", "access": "get/set", "doc": "body as UTF-8 text"},
        {"name": "json", "access": "get/set", "doc": "body parsed as JSON; setting also sets Content-Type"},
        {"name": "delay", "access": "get/set", "doc": "milliseconds to hold the request before it reaches the server"},
        {"name": "matches(pattern, query_mode='ignore')", "access": "call", "doc": "True when the URL matches a Map Local-style pattern"},
        {"name": "claim()", "access": "call", "doc": "skip Map Local for this request"},
        {"name": "respond(status=200, headers=None, body=None, json=None, delay=0)", "access": "call", "doc": "answer locally (claims the request); the server is never called; delay holds the response in ms"},
        {"name": "abort()", "access": "call", "doc": "drop the connection without a response (claims the request)"},
    ],
    "response": [
        {"name": "status", "access": "get/set", "doc": "status code; setting also updates the reason phrase"},
        {"name": "headers", "access": "mutable", "doc": "response headers (dict-like)"},
        {"name": "body", "access": "get/set", "doc": "raw bytes (str accepted on set)"},
        {"name": "text", "access": "get/set", "doc": "body as UTF-8 text"},
        {"name": "json", "access": "get/set", "doc": "body parsed as JSON; setting also sets Content-Type"},
        {"name": "delay", "access": "get/set", "doc": "milliseconds to hold the response before the app receives it"},
    ],
    "store": [
        {"name": "get(key, default=None)", "doc": "read a value"},
        {"name": "set(key, value)", "doc": "write a JSON-serializable value"},
        {"name": "incr(key, by=1)", "doc": "atomic counter; returns the new value"},
        {"name": "delete(key)", "doc": "remove a key; returns True when it existed"},
        {"name": "clear()", "doc": "remove every key"},
        {"name": "all()", "doc": "snapshot of every key"},
    ],
    "pipeline": [
        "CLAIMS match marks the request as claimed",
        "on_request(request), then request.delay",
        "Map Local, unless the request is claimed",
        "server, unless respond() or abort() was called",
        "on_response(request, response)",
        "response.delay, added to the session --delay",
    ],
    "tracking_headers": {
        "X-Mitm-Test": "<plan>/<case> on every response while a case is active",
        "X-Mitm-Test-Action": "responded | modified | aborted | claimed | passthrough",
    },
    "rules": [
        "Conflict with Map Local: claimed requests (CLAIMS, claim(), respond(), abort()) skip Map Local, so an active case can shadow a Map Local rule; unclaimed requests still get the Map Local mock and on_response edits it. When either behaves unexpectedly, check `test status`, `maplocal list`, and `query show <seq> --json` (mocked/mock_rule_id + the X-Mitm-Test-Action header).",
        "Only one case is active at a time, and only inside a running session: `test apply` fails when the proxy is down, `record start` begins with none, `record stop` clears it.",
        "`test apply` validates first: plan and case exist, the script compiles, defines a hook, and CLAIMS is a literal list of valid patterns.",
        "Script edits hot-reload on the next request; module globals reset on reload, `store` does not.",
        "A hook exception reverts that hook's changes, lets the request through, and is reported by `test status` and `doctor`.",
        "The store is never reset by `apply` or restarts; use `test state clear --test <plan>`.",
        "Hooks must be plain `def`, not `async def`. Scripts run as regular Python inside the proxy process.",
        "URLSession bypasses the macOS system proxy for localhost and private IP literals (192.168.x.x); point simulator apps at a hostname such as <lan-ip>.nip.io.",
    ],
    "example": EXAMPLE_SCRIPT,
}


def render_text() -> str:
    ref = REFERENCE
    lines = ["TEST CASE SCRIPT API", "", "Layout:"]
    lines.append(f"  {ref['layout']['plan_dir']}")
    for name, doc in ref["layout"]["files"].items():
        lines.append(f"    {name:<12} {doc}")
    lines.append(f"  names: {ref['layout']['names']}")
    lines += ["", "Hooks (both optional, plain def):"]
    for hook in ref["hooks"]:
        lines.append(f"  {hook['signature']}")
        lines.append(f"      {hook['runs']}")
    lines += ["", "Module globals:"]
    for item in ref["globals"]:
        lines.append(f"  {item['name']} ({item['type']}): {item['doc']}")
    for section in ("request", "response"):
        lines += ["", f"{section}:"]
        for item in ref[section]:
            lines.append(f"  {item['name']:<38} [{item['access']}] {item['doc']}")
    lines += ["", "store:"]
    for item in ref["store"]:
        lines.append(f"  {item['name']:<38} {item['doc']}")
    lines += ["", "Pipeline (per request):"]
    for index, step in enumerate(ref["pipeline"], start=1):
        lines.append(f"  {index}. {step}")
    lines += ["", "Tracking headers:"]
    for name, doc in ref["tracking_headers"].items():
        lines.append(f"  {name}: {doc}")
    lines += ["", "Rules:"]
    for rule in ref["rules"]:
        lines.append(f"  - {rule}")
    lines += ["", "Example:", ""]
    lines += [f"  {line}" if line else "" for line in ref["example"].splitlines()]
    return "\n".join(lines)
