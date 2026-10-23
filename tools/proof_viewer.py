#!/usr/bin/env python3
"""Loopback-only presentation server. Every upload is checked by the existing CLI."""
import argparse, functools, http.server, json, os, secrets, subprocess, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
LIMIT = 64 * 1024 * 1024

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checker', type=Path, required=True)
    parser.add_argument('--port', type=int, default=0)
    args = parser.parse_args()
    checker = args.checker.resolve(strict=True)
    token = secrets.token_urlsafe(24)
    with tempfile.TemporaryDirectory(prefix='realm-playground-') as directory:
        samples = Path(directory)/'samples'
        subprocess.run([str(checker), 'demo', '--output', str(samples)], check=True, stdout=subprocess.DEVNULL)
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def reply(self, status, data, mime='application/json'):
                self.send_response(status)
                self.send_header('Content-Type', mime)
                self.send_header('Content-Length', str(len(data)))
                self.send_header('Cache-Control', 'no-store')
                self.send_header('X-Content-Type-Options', 'nosniff')
                self.send_header('Referrer-Policy', 'no-referrer')
                self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
                self.end_headers()
                self.wfile.write(data)
            def allowed(self):
                origin = f'http://127.0.0.1:{self.server.server_port}'
                return self.headers.get('Host') == origin[7:] and self.headers.get('Origin', origin) == origin
            def do_GET(self):
                if not self.allowed(): return self.reply(403, b'{"error":"local origin required"}')
                paths = {'/': ROOT/'viewer/index.html', '/app.js': ROOT/'viewer/app.js', '/style.css': ROOT/'viewer/style.css', '/logo.svg': ROOT/'assets/realm-mark.svg'}
                mime = {'/':'text/html; charset=utf-8', '/app.js':'text/javascript; charset=utf-8', '/style.css':'text/css; charset=utf-8', '/logo.svg':'image/svg+xml'}
                if self.path == '/session': return self.reply(200, json.dumps({'token': token, 'checker':'existing realm-artifact CLI', 'version':1}).encode())
                if self.path in ['/samples/valid.realm','/samples/tampered.realm','/samples/incomplete.realm']:
                    return self.reply(200, (samples/self.path.rsplit('/',1)[1]).read_bytes(), 'application/octet-stream')
                if self.path in paths: return self.reply(200, paths[self.path].read_bytes(), mime[self.path])
                self.reply(404, b'{"error":"not found"}')
            def do_POST(self):
                if not self.allowed() or self.headers.get('X-Realm-Token') != token:
                    return self.reply(403, b'{"error":"local session required"}')
                if self.path != '/api/check': return self.reply(404, b'{"error":"not found"}')
                if self.headers.get('Transfer-Encoding'): return self.reply(400, b'{"error":"chunked input not supported"}')
                try: size = int(self.headers.get('Content-Length', '-1'))
                except ValueError: size = -1
                if not 0 < size <= LIMIT: return self.reply(413, b'{"error":"upload a nonempty artifact of at most 64 MiB"}')
                try:
                    self.connection.settimeout(10)
                    data = self.rfile.read(size)
                    if len(data) != size: return self.reply(400, b'{"error":"truncated upload"}')
                    with tempfile.NamedTemporaryFile(dir=directory, suffix='.realm') as file:
                        file.write(data);file.flush()
                        result = subprocess.run([str(checker), 'verify', file.name, '--json'], capture_output=True, timeout=10)
                    report = json.loads(result.stdout)
                    if report.get('schema') != 'realm.artifact-check.v1' or result.returncode not in (0,1,3,4,5): raise ValueError('unexpected checker result')
                    self.reply(200, json.dumps({'checker_exit': result.returncode, 'report': report}).encode())
                except (OSError, ValueError, subprocess.TimeoutExpired):
                    self.reply(502, b'{"error":"checker did not complete; no result established"}')
        class LocalServer(http.server.HTTPServer):
            def get_request(self):
                connection, address = super().get_request()
                connection.settimeout(10)
                return connection, address
        server = LocalServer(('127.0.0.1', args.port), Handler)
        server.timeout = 1
        print(f'REALM Proof Viewer: http://127.0.0.1:{server.server_port}', flush=True)
        print('Local presentation of Rust checker results. Ctrl-C stops; uploads are temporary.', flush=True)
        try: server.serve_forever()
        except KeyboardInterrupt: pass
        finally: server.server_close()
if __name__ == '__main__': main()
