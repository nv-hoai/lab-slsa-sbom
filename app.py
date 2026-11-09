"""Minimal Flask entry point for the lab demo application."""

from __future__ import annotations

from flask import Flask, jsonify

from main import build_message

app = Flask(__name__)


@app.get("/")
def index():
    return jsonify(message=build_message())


@app.get("/health")
def health():
    return jsonify(status="ok")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
