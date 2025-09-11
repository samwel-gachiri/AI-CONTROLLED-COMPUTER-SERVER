#!/usr/bin/env python3
"""
Server entrypoint composing enterprise auth endpoints and updates endpoint.

Run: python -m server.main [port]
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
from typing import Any, Dict
import json
import sys

from .updates import handle_updates_route

#!/usr/bin/env python3
"""
Unified Server Entry Point

This file starts the production server by composing the enterprise auth app
with the updates API so the desktop client has both authentication and updater
endpoints available on the same base URL.

- Reuses the Flask app from server/enterprise_auth_server.py to preserve all
  existing authentication, user, sharing, and admin APIs.
- Registers the updates blueprint from server/updates.py to serve
  GET /api/app/version used by the desktop AutoUpdater.

Run:
python server/main.py  (defaults to host=0.0.0.0, port=5000)

Environment:
- PORT: override the port
- HOST: override the host
"""
from __future__ import annotations

import os
import sys

class SimpleRouterHandler(BaseHTTPRequestHandler):
    """Minimal HTTP server for local development.

    In production, replace with your enterprise auth server framework and
    mount the updates route at GET /api/app/version using server.updates.
    """

    def _send_json(self, obj: Dict[str, Any], status: int = 200):
        try:
            body = json.dumps(obj).encode('utf-8')
        except Exception:
            body = json.dumps({'error': 'serialization error'}).encode('utf-8')
            status = 500
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # Updates endpoint
        matched, body, status = handle_updates_route(path)
        if matched:
            self._send_json(body, status)
            return

        # TODO: mount enterprise auth routes here
        if path == '/status':
            self._send_json({'status': 'ok'})
            return

        self._send_json({'error': 'not found'}, 404)


def main():
    port = 5000
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass
    httpd = HTTPServer(('localhost', port), SimpleRouterHandler)
    print(f"Enterprise server running at http://localhost:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        httpd.shutdown()


if __name__ == '__main__':
    main()

# Ensure server package import works when running from project root
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Import the existing enterprise app
try:
    from server.enterprise_auth_server import app as enterprise_app  # type: ignore
except Exception as e:
    # Fallback: try relative import style if the above fails
    try:
        from enterprise_auth_server import app as enterprise_app  # type: ignore
    except Exception as e2:
        raise RuntimeError(f"Failed to import enterprise_auth_server.app: {e} / {e2}")

# Import updates blueprint
try:
    from server.updates import updates_bp  # type: ignore
except Exception:
    from updates import updates_bp  # type: ignore

# Register updates endpoints on the enterprise app
enterprise_app.register_blueprint(updates_bp)


if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port_str = os.environ.get("PORT", "5000")
    try:
        port = int(port_str)
    except ValueError:
        port = 5000
    # Enable threaded to handle polling endpoints and long-poll friendly
    enterprise_app.run(host=host, port=port, threaded=True)
