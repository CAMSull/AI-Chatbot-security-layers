#!/usr/bin/env python3
"""
Terminal chat client for the layered-security Azure AI chatbot.

Talks to the FastAPI backend (app/main.py) over HTTP, exactly as any other
client would - so every security layer (auth, rate limiting, input
validation, content moderation, output filtering) is exercised the same way
it would be for a real client.

Usage:
    python cli.py                       # connects to http://127.0.0.1:8000
    python cli.py --url http://host:port --api-key sk_demo_123

The API key can also be supplied via the CHATBOT_API_KEY environment
variable so it doesn't need to be typed into shell history.
"""
from __future__ import annotations

import argparse
import os
import sys

import requests


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Terminal client for the secure Azure AI chatbot demo.")
    parser.add_argument("--url", default=os.environ.get("CHATBOT_URL", "http://127.0.0.1:8000"))
    parser.add_argument("--api-key", default=os.environ.get("CHATBOT_API_KEY", "dev-local-key"))
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    session = requests.Session()
    session.headers.update({"X-API-Key": args.api_key, "Content-Type": "application/json"})

    try:
        health = session.get(f"{args.url}/health", timeout=5)
        health.raise_for_status()
        mock = health.json().get("mock_mode")
        print(f"Connected to {args.url} (mock_mode={mock})")
    except requests.RequestException as exc:
        print(f"Could not reach backend at {args.url}: {exc}", file=sys.stderr)
        sys.exit(1)

    print("Type your message and press Enter. Ctrl+C or 'exit' to quit.\n")

    conversation_id = None
    while True:
        try:
            user_input = input("you> ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nGoodbye.")
            break

        if not user_input:
            continue
        if user_input.lower() in {"exit", "quit"}:
            print("Goodbye.")
            break

        try:
            resp = session.post(
                f"{args.url}/chat",
                json={"message": user_input, "conversation_id": conversation_id},
                timeout=30,
            )
        except requests.RequestException as exc:
            print(f"[connection error] {exc}")
            continue

        if resp.status_code == 200:
            data = resp.json()
            conversation_id = data.get("conversation_id") or conversation_id
            print(f"bot> {data['reply']}\n")
        else:
            try:
                detail = resp.json().get("error", resp.text)
            except ValueError:
                detail = resp.text
            print(f"[blocked - HTTP {resp.status_code}] {detail}\n")


if __name__ == "__main__":
    main()
