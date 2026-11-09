"""Endpoint C loses its connection."""


def on_request(request):
    if request.path == "/c":
        request.abort()
