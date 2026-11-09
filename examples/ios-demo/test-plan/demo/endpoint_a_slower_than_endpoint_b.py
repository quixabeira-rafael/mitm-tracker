"""Endpoint A arrives 2s after B; C waits 1s before reaching the server."""


def on_request(request):
    if request.path == "/c":
        request.delay = 1000


def on_response(request, response):
    if request.path == "/a":
        response.delay = 2000
