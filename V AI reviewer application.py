from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from reviewer import ai_enabled, review_code

BASE_DIR = Path(__file__).resolve().parent
INDEX_FILE = BASE_DIR / "web" / "index.html"
MAX_BODY = 1_000_000


class ReviewHandler(BaseHTTPRequestHandler):
    server_version = "ReviewAI/0.1"

    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _text(self, status: int, text: str, content_type: str = "text/plain; charset=utf-8") -> None:
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path in ("/", "/index.html"):
            try:
                page = INDEX_FILE.read_text(encoding="utf-8")
            except OSError:
                self._text(500, "UI not found")
                return
            self._text(200, page, "text/html; charset=utf-8")
        elif path == "/api/info":
            self._json(200, {
                "aiEnabled": ai_enabled(),
                "model": os.environ.get("REVIEWAI_MODEL", "gpt-4o-mini"),
            })
        elif path == "/healthz":
            self._text(200, "ok")
        else:
            self._text(404, "Not found")

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        if path != "/api/review":
            self._text(404, "Not found")
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._json(400, {"error": "invalid content length"})
            return
        if length <= 0:
            self._json(400, {"error": "empty request body"})
            return
        if length > MAX_BODY:
            self._json(413, {"error": "request body too large"})
            return

        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._json(400, {"error": "invalid JSON body"})
            return
        if not isinstance(payload, dict):
            self._json(400, {"error": "invalid JSON body"})
            return

        code = payload.get("code", "")
        if not isinstance(code, str) or not code.strip():
            self._json(400, {"error": "code is required"})
            return

        filename = payload.get("filename", "")
        language = payload.get("language", "")
        use_ai = payload.get("useAI")
        if not isinstance(use_ai, bool):
            use_ai = None

        try:
            result = review_code(
                code=code,
                filename=filename if isinstance(filename, str) else "",
                language=language if isinstance(language, str) else "",
                use_ai=use_ai,
            )
        except Exception as exc:
            self._json(500, {"error": f"review failed: {exc}"})
            return

        self._json(200, result)

    def log_message(self, fmt: str, *args) -> None:
        print(f"{self.address_string()} - {fmt % args}")


def main() -> None:
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8000"))
    server = ThreadingHTTPServer((host, port), ReviewHandler)
    mode = "static + optional LLM" if ai_enabled() else "static analysis"
    print(f"ReviewAI ({mode}) listening on http://localhost:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
