# iOS demo for test plans

A SwiftUI app that fires `/a`, `/b` and `/c` in parallel and shows, per
endpoint, the arrival order, status, elapsed time, body, and the
`X-Mitm-Test` / `X-Mitm-Test-Action` headers added by the active test case.
Use it to validate test plans visually in the iOS Simulator.

```
examples/ios-demo/
├── MitmDemo.xcodeproj
├── MitmDemo/            # SwiftUI sources
├── server.py            # upstream server for /a, /b, /c
└── test-plan/demo/      # sample test plan (plan.json + one .py per case)
```

## Run it

```bash
# 1. Upstream server (binds 0.0.0.0:18080).
python3 examples/ios-demo/server.py

# 2. Install the sample plan into the active profile.
cp -R examples/ios-demo/test-plan/demo .mitm-tracker/profiles/<profile>/tests/demo

# 3. Build and install the app on a booted simulator.
xcodebuild -project examples/ios-demo/MitmDemo.xcodeproj -scheme MitmDemo \
  -sdk iphonesimulator -destination 'platform=iOS Simulator,name=iPhone 17 Pro' \
  -derivedDataPath /tmp/mitm-demo CODE_SIGNING_ALLOWED=NO build
xcrun simctl install booted /tmp/mitm-demo/Build/Products/Debug-iphonesimulator/MitmDemo.app

# 4. Point the app at the server through a hostname (see the note below).
xcrun simctl spawn booted defaults write dev.mitmtracker.demo baseURL "http://$(ipconfig getifaddr en0).nip.io:18080"

# 5. Proxy + scenarios.
mitm-tracker record start
mitm-tracker test apply --test demo --test-case endpoint_a_slower_than_endpoint_b
# tap "Run A, B and C" in the app
```

**Use a hostname, not an IP.** `URLSession` skips the macOS system proxy for
private IP literals (`192.168.x.x`) and for `localhost`, so those requests
never reach mitm-tracker. `<lan-ip>.nip.io` resolves to the same address and
is proxied normally. The base URL can also be edited in the app.

## Sample cases

| Case | Expected on screen |
|---|---|
| `endpoint_returns_201` | `/a` shows `201` · `modified` |
| `endpoint_returns_400` | `/a` shows `400` with `{"error": "invalid request"}` |
| `endpoint_a_slower_than_endpoint_b` | `/b` arrives #1, `/c` ~1s, `/a` ~2s and last |
| `endpoint_b_local_response` | `/b` shows `202` · `responded` with `"source": "test case"` |
| `endpoint_c_connection_dropped` | `/c` shows `ERR` (`URLError -1005`) |
| `endpoint_b_fails_first_call_only` | first run `/b` is `503`, later runs `200` (reset with `test state clear --test demo`) |
| `endpoint_c_fails_randomly` | `/c` alternates between `200` and `500` |
