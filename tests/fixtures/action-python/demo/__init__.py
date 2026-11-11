import requests


def fetch(url: str) -> int:
    return requests.get(url, timeout=5).status_code
