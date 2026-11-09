"""Endpoint C fails with 500 half of the time."""
import random


def on_response(request, response):
    if request.path == "/c" and random.random() < 0.5:
        response.status = 500
        response.json = {"error": "random failure"}
