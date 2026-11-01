"""Example Flask app that uses requests (not cryptography PKCS12)."""

from flask import Flask, jsonify
import requests

app = Flask(__name__)


@app.route("/api/weather")
def weather():
    resp = requests.get("https://api.example.com/weather", timeout=10)
    return jsonify(resp.json())


if __name__ == "__main__":
    app.run()
