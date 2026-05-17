"""Configuration loader — relays + settings.

Two files, both JSON, both human-editable:
  relays.json    -> list of {name,host,port,region}
  settings.json  -> {psk_hex, last_game_id, capture_backend}

Located next to the executable so portable installs work.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path

LOG = logging.getLogger("lagx.config")

DEFAULT_PSK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

DEFAULT_RELAYS = [
    {"name": "Local (test)", "host": "127.0.0.1", "port": 51820, "region": "LOCAL"},
]

DEFAULT_SETTINGS = {
    "psk_hex": DEFAULT_PSK,
    "last_game_id": "valorant",
    "capture_backend": "auto",
    "n_paths": 1,           # 1 = single best route; 2-3 = multi-path duplication
}


def app_dir() -> Path:
    """Where config files live. Next to the .exe in a PyInstaller bundle, else cwd."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent.parent


def load_relays() -> list[dict]:
    p = app_dir() / "relays.json"
    if not p.exists():
        LOG.info("relays.json missing; writing default at %s", p)
        p.write_text(json.dumps(DEFAULT_RELAYS, indent=2))
        return list(DEFAULT_RELAYS)
    try:
        data = json.loads(p.read_text())
        if not isinstance(data, list):
            raise ValueError("relays.json must be a JSON array")
        for r in data:
            if not all(k in r for k in ("name", "host", "port")):
                raise ValueError(f"relay entry missing required keys: {r}")
        return data
    except Exception as e:
        LOG.error("relays.json invalid (%s); using defaults", e)
        return list(DEFAULT_RELAYS)


def load_settings() -> dict:
    p = app_dir() / "settings.json"
    if not p.exists():
        p.write_text(json.dumps(DEFAULT_SETTINGS, indent=2))
        return dict(DEFAULT_SETTINGS)
    try:
        return {**DEFAULT_SETTINGS, **json.loads(p.read_text())}
    except Exception as e:
        LOG.error("settings.json invalid (%s); using defaults", e)
        return dict(DEFAULT_SETTINGS)


def save_settings(s: dict) -> None:
    p = app_dir() / "settings.json"
    p.write_text(json.dumps(s, indent=2))
