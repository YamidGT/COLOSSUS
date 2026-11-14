"""Credential-free, fixed-origin wheel registry for isolated Python builders."""

import html
import http.client
import json
import re
import socket
import threading
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

FILE = re.compile(
    r"/packages/[a-f0-9]{2}/[a-f0-9]{2}/[a-f0-9]{56,64}/[A-Za-z0-9_.+!-]+\.whl(?:\.metadata)?"
)
PACKAGE = re.compile(r"/simple/([a-z0-9]+(?:[-._][a-z0-9]+)*)/")
MAX_FILE = 32 * 1024 * 1024
MAX_TOTAL = 200 * 1024 * 1024
lock = threading.Lock()
stats = {"requests": 0, "bytes": 0, "denied": 0}
origins = {}


class OriginConnection(http.client.HTTPSConnection):
    def connect(self):
        # Docker's embedded loopback DNS is unavailable in this gVisor profile.
        # Addresses are fixed by the trusted launcher; TLS still checks origin names.
        if self.host not in origins:
            raise ValueError("Origin was not resolved by the launcher")
        last_error = None
        for address in origins[self.host]:
            try:
                stream = socket.create_connection((address, 443), timeout=self.timeout)
                try:
                    self.sock = self._context.wrap_socket(stream, server_hostname=self.host)
                except BaseException:
                    stream.close()
                    raise
                return
            except OSError as exc:
                last_error = exc
        raise last_error or OSError("No origin address")


class WheelIndex(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []

    def handle_starttag(self, tag, attributes):
        if tag != "a":
            return
        attrs = dict(attributes)
        url = urlsplit(attrs.get("href") or "")
        if (
            url.scheme != "https"
            or url.netloc != "files.pythonhosted.org"
            or url.query
            or not FILE.fullmatch(url.path)
            or not url.path.endswith(".whl")
            or not re.fullmatch(r"sha256=[a-f0-9]{64}", url.fragment)
        ):
            return
        preserved = {
            key: value
            for key, value in attrs.items()
            if key
            in {
                "data-requires-python",
                "data-yanked",
                "data-dist-info-metadata",
                "data-core-metadata",
            }
        }
        properties = " ".join(
            f'{key}="{html.escape(value or "", quote=True)}"' for key, value in preserved.items()
        )
        href = html.escape("/files" + url.path + "#" + url.fragment, quote=True)
        self.links.append(
            f'<a href="{href}" {properties}>{html.escape(url.path.rsplit("/", 1)[-1])}</a>'
        )


def fetch(host, path, limit):
    # No user-selected origin, redirect, authentication header or CONNECT tunnel.
    if host not in {"pypi.org", "files.pythonhosted.org"}:
        raise ValueError("Unsupported origin")
    connection = OriginConnection(host, timeout=30)
    try:
        connection.request(
            "GET", path, headers={"User-Agent": "COLOSSUS-wheel-proxy/1", "Accept": "text/html"}
        )
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError("Registry unavailable")
        body = bytearray()
        while chunk := response.read(65536):
            body.extend(chunk)
            with lock:
                stats["bytes"] += len(chunk)
                exceeded = stats["bytes"] > MAX_TOTAL
            if len(body) > limit or exceeded:
                raise ValueError("Registry transfer limit")
        return bytes(body)
    finally:
        connection.close()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, body, content_type="application/octet-stream"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        with lock:
            stats["requests"] += 1
            limited = stats["requests"] > 512 or stats["bytes"] >= MAX_TOTAL
        if limited or len(self.path) > 2048:
            self.reply(429, b"Registry budget exhausted")
            return
        if self.path == "/health":
            self.reply(200, b"ready")
            return
        if self.path == "/stats":
            with lock:
                body = json.dumps(stats).encode()
            self.reply(200, body, "application/json")
            return
        try:
            if PACKAGE.fullmatch(self.path):
                parser = WheelIndex()
                parser.feed(fetch("pypi.org", self.path, 4 * 1024 * 1024).decode())
                self.reply(
                    200,
                    ("<!DOCTYPE html>\n" + "\n".join(parser.links)).encode(),
                    "text/html; charset=utf-8",
                )
                return
            if self.path.startswith("/files/") and FILE.fullmatch(self.path.removeprefix("/files")):
                body = fetch("files.pythonhosted.org", self.path.removeprefix("/files"), MAX_FILE)
                self.reply(200, body)
                return
        except (OSError, ValueError, http.client.HTTPException):
            self.reply(502, b"Registry response failed or exceeded limits")
            return
        with lock:
            stats["denied"] += 1
        self.reply(403, b"Only Python wheel registry paths are allowed")


class Server(ThreadingHTTPServer):
    daemon_threads = True
    slots = threading.BoundedSemaphore(8)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        request.settimeout(45)
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


if __name__ == "__main__":
    origins = json.loads(Path("/app/origins.json").read_text())
    Server(("0.0.0.0", 8080), Handler).serve_forever()
