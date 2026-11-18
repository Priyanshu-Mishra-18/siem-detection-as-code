"""
Read-only check that the Gemini API key works.

Sends one short prompt to Gemini and prints the reply. Changes nothing.
If the model name is not available to your key, it prints the Flash models
your key can use instead.

Usage (from the repository root, with the venv active):
    python scripts/gemini_check.py

Settings come from the .env file:
    GEMINI_API_KEY   required
    GEMINI_MODEL     optional, default gemini-3.8-flash (free tier)
"""

import sys
from pathlib import Path

from google import genai
from google.genai import errors

ENV_FILE = Path(__file__).resolve().parent.parent / ".env"
DEFAULT_MODEL = "gemini-3.8-flash"


def load_env(path: Path) -> dict:
    if not path.exists():
        sys.exit(f"ERROR: {path} not found.")
    env = {}
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            env[key.strip()] = value.strip()
    return env


def main() -> None:
    env = load_env(ENV_FILE)
    key = env.get("GEMINI_API_KEY")
    if not key:
        sys.exit("ERROR: GEMINI_API_KEY missing from .env")
    model = env.get("GEMINI_MODEL", DEFAULT_MODEL)

    client = genai.Client(api_key=key)
    print(f"Model: {model}")
    try:
        response = client.models.generate_content(
            model=model,
            contents="In one sentence, what does a SIEM do?",
        )
    except errors.APIError as exc:
        print(f"ERROR from Gemini: {exc.code} {exc.message}")
        if exc.code == 404:
            print("Flash models available to your key:")
            for m in client.models.list():
                if "flash" in m.name:
                    print(f"  {m.name.removeprefix('models/')}")
        sys.exit(1)

    print(f"Reply: {response.text.strip()}")
    print("OK: the Gemini API key works.")


if __name__ == "__main__":
    main()
