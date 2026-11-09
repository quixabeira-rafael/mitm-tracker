import argparse
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def _respond(self):
        name = self.path.split("?", 1)[0].strip("/") or "root"
        length = int(self.headers.get("Content-Length") or 0)
        payload = json.dumps({
            "endpoint": name,
            "method": self.command,
            "path": self.path,
            "body": self.rfile.read(length).decode() if length else "",
            "served_at": round(time.time(), 3),
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = do_PUT = do_DELETE = _respond


def main() -> None:
    parser = argparse.ArgumentParser(description="Upstream server for the mitm-tracker iOS demo.")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=18080)
    args = parser.parse_args()
    print(f"serving on http://{args.host}:{args.port}")
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
