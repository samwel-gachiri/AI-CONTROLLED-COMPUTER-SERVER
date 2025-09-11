#!/usr/bin/env python3
"""
Updates module: provides version info endpoint used by the desktop AutoUpdater
"""

from typing import Dict, Any
import json
import os

try:
    from app_version import APP_VERSION
except Exception:
    APP_VERSION = "1.0.0"


def get_app_version_info() -> Dict[str, Any]:
    """Return version info for the desktop app updater.

    Looks for a server_version.json in the working directory with keys:
    {
      "version": "1.0.1",
      "notes": "...",
      "download_url": "https://.../AI_Assistant_1.0.1_win.zip",
      "mandatory": false
    }
    Falls back to current app version with empty download_url if not found.
    """
    try:
        cfg_path = os.path.join(os.getcwd(), 'server_version.json')
        if os.path.exists(cfg_path):
            with open(cfg_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, dict) and 'version' in data:
                    return data
    except Exception as e:
        print(f"Error reading server_version.json: {e}")

    return {
        'version': APP_VERSION,
        'notes': 'No updates available',
        'download_url': '',
        'mandatory': False
    }


def handle_updates_route(path: str):
    """Simple router helper to be used by a custom HTTP server.

    Returns a tuple (matched: bool, body: dict, status: int)
    """
    if path == '/api/app/version':
        return True, get_app_version_info(), 200
    return False, {}, 404
#!/usr/bin/env python3
"""
Updates API Blueprint
Exposes the desktop updater endpoint consumed by the app's AutoUpdater.

Contract:
GET /api/app/version -> {
  "version": "1.0.0",
  "notes": "...",
  "download_url": "https://.../package.zip",
  "mandatory": false
}

Version metadata is loaded from server_version.json located at the project root.
If not found or invalid, falls back to the current app version and an empty URL.
"""
from __future__ import annotations

from flask import Blueprint, jsonify
import json
import os

updates_bp = Blueprint("updates", __name__)


def _load_json(path: str):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _load_app_version() -> str:
    # Try import from project root; fallback to default
    try:
        from app_version import APP_VERSION  # type: ignore
        return str(APP_VERSION)
    except Exception:
        return "1.0.0"


def _find_server_version() -> dict:
    # Candidate paths: project_root/server_version.json, CWD, and local
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates = [
        os.path.join(project_root, "server_version.json"),
        os.path.join(os.getcwd(), "server_version.json"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "server_version.json"),
    ]
    for path in candidates:
        if os.path.exists(path):
            data = _load_json(path)
            if isinstance(data, dict) and data.get("version"):
                return data
    # Fallback: no update advertised
    return {
        "version": _load_app_version(),
        "notes": "No updates available",
        "download_url": "",
        "mandatory": False,
    }


@updates_bp.get("/api/app/version")
def get_version():
    data = _find_server_version()
    # Basic normalization
    data.setdefault("notes", "")
    data.setdefault("download_url", "")
    data.setdefault("mandatory", False)
    return jsonify(data)
