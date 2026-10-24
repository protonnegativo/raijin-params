"""Local lab for bench/run.sh: two small sites whose hidden query and form parameters change the response.

usage: python3 lab.py <port>=shop [<port>=app]

It listens on 127.0.0.1 only. Every page is the same on every request (arjun skips a page that changes
by itself), and a hidden parameter adds a line to the body when it is present, whatever its value.

shop (noisy): a catalog where almost every page has the same plain parameters.
  /product/1 ... /product/30   page, currency, format
  /article/1 ... /article/15   page, print
  /search                      q, sort, page

app (findings): a small app with parameters an attacker wants, plus a few plain ones.
  /fetch, /preview             url, callback
  /login                       next (GET), username and password (POST)
  /logout                      next
  /download                    file
  /render                      template, lang
  /tools/ping                  host, cmd
  /api/user, /api/order        id
  /account                     user_id, tab
  /admin                       debug, admin
  /report                      format, sort
  /about                       ref
"""
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlsplit

SHOP = {}
for n in range(1, 31):
    SHOP[f"/product/{n}"] = {"GET": ["page", "currency", "format"]}
for n in range(1, 16):
    SHOP[f"/article/{n}"] = {"GET": ["page", "print"]}
SHOP["/search"] = {"GET": ["q", "sort", "page"]}

APP = {
    "/fetch": {"GET": ["url", "callback"]},
    "/preview": {"GET": ["url", "callback"]},
    "/login": {"GET": ["next"], "POST": ["username", "password"]},
    "/logout": {"GET": ["next"]},
    "/download": {"GET": ["file"]},
    "/render": {"GET": ["template", "lang"]},
    "/tools/ping": {"GET": ["host", "cmd"]},
    "/api/user": {"GET": ["id"]},
    "/api/order": {"GET": ["id"]},
    "/account": {"GET": ["user_id", "tab"]},
    "/admin": {"GET": ["debug", "admin"]},
    "/report": {"GET": ["format", "sort"]},
    "/about": {"GET": ["ref"]},
}

SITES = {"shop": SHOP, "app": APP}


def handler(routes):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def log_message(self, *a):
            pass

        def page(self, method, params):
            u = urlsplit(self.path)
            route = routes.get(u.path)
            if u.path == "/":
                links = "".join(f'<li><a href="{p}">{p}</a></li>' for p in routes)
                return 200, f"<html><head><title>index</title></head><body><ul>{links}</ul></body></html>"
            if route is None:
                return 404, "<html><body>not found</body></html>"
            if method not in route:
                return 405, "<html><body>method not allowed</body></html>"
            lines = [f"<p>{name} is on</p>" for name in route[method] if params.get(name, [""])[0] != ""]
            body = "<p>" + "lorem ipsum " * 40 + "</p>"
            return 200, f"<html><head><title>{u.path}</title></head><body><h1>{u.path}</h1>{body}{''.join(lines)}</body></html>"

        def send(self, status, body):
            data = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            self.send(*self.page("GET", parse_qs(urlsplit(self.path).query)))

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n).decode("utf-8", "replace")
            self.send(*self.page("POST", parse_qs(raw)))

    return H


def main():
    servers = []
    for arg in sys.argv[1:]:
        port, site = arg.split("=")
        s = ThreadingHTTPServer(("127.0.0.1", int(port)), handler(SITES[site]))
        servers.append(s)
    for s in servers[:-1]:
        Thread(target=s.serve_forever, daemon=True).start()
    try:
        servers[-1].serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
