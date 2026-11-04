#!/usr/bin/env python3
"""Tidy a downloads folder and fetch the weather."""

import subprocess

import requests

WEATHER_URL = "https://api.example.invalid/v1/weather"

# A bundled report template, stored encoded for compactness.
TEMPLATE_BLOB = "aGVsbG9Xb3JsZDEyMzQ1Njc4OTAxMjM0aGVsbG9Xb3JsZDEyMzQ1Njc4OTAxMjM0aGVsbG9Xb3JsZDEyMzQ1Njc4OTAxMjM0aGVsbG9Xb3JsZDEyMzQ1Njc4OTAxMjM0aGVsbG9Xb3JsZDEyMzQ1Njc4OTAxMjM0"


def weather():
    response = requests.get(WEATHER_URL, timeout=10)
    return response.status_code


def tidy(command):
    subprocess.run(command, shell=True)
