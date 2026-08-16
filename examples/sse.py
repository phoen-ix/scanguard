"""Minimal Server-Sent Events backend for the scanguard streaming gate.

Emits one event every 400ms for four seconds. If scanguard's ResponseWriter
wrapper has swallowed http.Flusher, every event arrives at once when the
connection closes instead of trickling in — which is the failure mode of
traefik#10269 and the reason this backend exists.
"""

import http.server
import socketserver
import time

TICKS = 10
INTERVAL = 0.4


class Handler(http.server.BaseHTTPRequestHandler):
    # HTTP/1.0 semantics: the body ends when the connection closes, so no
    # Content-Length and no manual chunk framing are needed.
    protocol_version = "HTTP/1.0"

    def do_GET(self):
        if self.path.startswith("/sse"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.end_headers()
            for i in range(TICKS):
                try:
                    self.wfile.write(("data: tick %d\n\n" % i).encode())
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    return
                time.sleep(INTERVAL)
            return

        body = b"sse backend\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    Server(("", 80), Handler).serve_forever()
