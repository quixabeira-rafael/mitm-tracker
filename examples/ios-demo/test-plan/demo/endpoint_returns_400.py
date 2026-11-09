"""Endpoint A returns 400 with an error body."""


def on_response(request, response):
    if request.path == "/a":
        response.status = 400
        response.json = {"error": "invalid request"}
