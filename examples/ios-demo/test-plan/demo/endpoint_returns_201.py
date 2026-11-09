"""Endpoint A returns 201 Created."""


def on_response(request, response):
    if request.path == "/a":
        response.status = 201
