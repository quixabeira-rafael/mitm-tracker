"""Endpoint B is answered by the proxy; the server is never called."""


def on_request(request):
    if request.path == "/b":
        request.respond(202, json={"endpoint": "b", "source": "test case"})
