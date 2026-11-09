"""Endpoint B returns 503 on the first run only (counter in the plan store)."""


def on_request(request):
    if request.path == "/b" and store.incr("b_calls") == 1:
        request.respond(503, json={"error": "warming up"})
