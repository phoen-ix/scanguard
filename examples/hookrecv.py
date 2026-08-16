"""A webhook sink for the scanguard harness.

Records whatever scanguard posts to it and serves it back for inspection, so the
notification path can be checked end to end: interpreted plugin code, spawning a
goroutine, making an outbound HTTP call out of the Traefik container.

  POST /ban    scanguard's generic webhook
  POST /ntfy   scanguard's chat notification
  GET  /received   everything received so far, as JSON
  DELETE /received clear the log
"""

import http.server
import json
import socketserver
import threading

received = []
lock = threading.Lock()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _respond(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        try:
            parsed = json.loads(raw)
        except ValueError:
            parsed = None

        with lock:
            received.append({
                "path": self.path,
                "contentType": self.headers.get("Content-Type", ""),
                "headers": {k.lower(): v for k, v in self.headers.items()},
                "raw": raw,
                "json": parsed,
            })
        self._respond(200, {"ok": True})

    def do_GET(self):
        if self.path.startswith("/received"):
            with lock:
                self._respond(200, received)
            return
        self._respond(404, {"error": "not found"})

    def do_DELETE(self):
        with lock:
            received.clear()
        self._respond(200, {"ok": True})

    def log_message(self, *args):
        pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    Server(("", 8080), Handler).serve_forever()
