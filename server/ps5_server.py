#!/usr/bin/env python3
"""
ASCEND — PS5 Research Platform
Simple blanket DNS + HTTP server.
Run as administrator: python ps5_server.py
"""

import http.server, json, os, socket, ssl, struct, sys, tempfile, threading, time
from datetime import datetime

import re as _re
def _strip(msg): return _re.sub(r'\[/?(bold|dim|red|green|yellow|cyan|magenta|white|blue|italic|underline|strike|blink|reverse|bright_\w+|on_\w+)[^\]]*\]','',str(msg))

def _safe(text):
    # Rich Console on Windows CP1252 cannot encode some glyphs; make the string
    # printable by replacing the PS5/emoji markers with ASCII equivalents.
    # Coerce to str first in case a Panel object is passed.
    text = str(text)
    return (text
        .replace('\u2588', '#')
        .replace('\u2550', '-')
        .replace('\u2551', '|')
        .replace('\u2552', '+')
        .replace('\u2553', '[[')
        .replace('\u2554', ']]')
        .replace('\u2555', '{{')
        .replace('\u2556', '}}')
        .replace('\u2557', '{{')
        .replace('\u2558', '}}')
        .replace('\u2559', '[+')
        .replace('\u255a', '+]')
        .replace('\u255b', '{{')
        .replace('\u255c', '}}')
        .replace('\u255d', '{{')
        .replace('\u255e', '}}')
        .replace('\u25a0', '#')
        .replace('\u25bc', 'v')
        .replace('\u25b2', '^')
        .replace('\u2191', '^')
        .replace('\u2193', 'v')
        .replace('\u2713', 'V')
        .replace('\u2717', 'X')
        .replace('\u26a1', '!!!')
        .replace('\u26d4', 'X')
        .replace('\U0001f4a5', 'S')
        .replace('\U0001f512', 'W')
        .encode('utf-8', errors='replace').decode('utf-8')
    )

def _panel(body, **kw):
    return Panel(_safe(body), **kw)


def p(msg):
    # Print plain, CP1252-safe output so the server boots without a traceback
    # even when run from a CMD window with a non-UTF-8 codepage.
    try:
        print(_strip(_safe(msg)), flush=True)
    except Exception:
        # A glyph outside the console code page must NEVER break server logic.
        # _safe() only maps a fixed set of box/emoji glyphs; '→' and '—' pass
        # through, and the DNS loop wraps its whole body in a bare `except: pass`
        # BEFORE s.sendto(), so a failed print used to silently drop the answer.
        try:
            print(_strip(_safe(msg)).encode('ascii', 'replace').decode('ascii'),
                  flush=True)
        except Exception:
            pass


class Panel:
    def __init__(self, body, **kw):
        self._b = _safe(body)
    def __str__(self):
        return _strip(self._b)

DIRECTORY = os.path.dirname(os.path.abspath(__file__))
PAGE      = "ov_probe.html"
RESULTS     = []
INTERESTING = []

# ── serve the probe at most once per client per cooldown ─────────────────────
# Every guide navigation lands on PAGE, so a user clicking through the guide
# re-ran the whole probe on every single page, and the allocations accumulated in
# one browser until the renderer was killed (observed 2026-10-08: 5 full heavy
# runs for the console in 41 seconds, then a crash on the last canvas case).
# A COUNTER with an ?again=1 bypass was the first attempt and it failed: the
# bypass is carried in the URL, so a reload of that URL bypassed the stub every
# time and the loop survived. What cannot be defeated by a URL is a COOLDOWN -
# one probe per client per 45 seconds, no exceptions, nothing to bypass.
PROBE_ONCE = {}          # ip -> time of the last probe serve
PROBE_COOLDOWN = 45.0    # seconds
STUB_HEAD = (
    b"<!doctype html><meta charset=utf-8><title>ASCEND - probe resting</title>"
    b"<body style=\"background:#0a0a0a;color:#00ff41;font:14px monospace;padding:22px\">"
    b"<h2>ASCEND: the probe is resting.</h2>"
    b"<p>This page deliberately does nothing. It exists so that clicking through the "
    b"guide cannot re-run the probe on every page - five full runs in 41 seconds is "
    b"what took the browser down, not any single case.</p>"
    b"<p style=\"color:#0ff;font-size:17px\">"
)


def stub_page(seconds_left):
    """The resting page, with the remaining cooldown spelled out so the wait is
    obvious instead of looking like a fault."""
    return (STUB_HEAD
            + ("About %d seconds left of the 45-second cooldown. "
               "After that, load the guide once and the probe runs."
               % max(1, int(seconds_left))).encode()
            + b"</p></body>")

BANNER = r"""
     ___   ____  ____  ___ _  _ ____
    / _ \ / ___||  _ \|_ _| \| |  _ \
   / /_\ \\__ \ | |_) || ||  ` | | | |
  / ___  \___) ||  __/ | || |\  | |_| |
 /_/   \_\____/ |_|   |___|_| \_|____/
"""

def ts(): return datetime.now().strftime("%H:%M:%S")

def get_ip():
    # Prefer 192.168.137.x (ICS), fall back to any LAN IP
    ips = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ip = info[4][0]
            if ':' not in ip and not ip.startswith('127.'): ips.add(ip)
    except: pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8",80)); ips.add(s.getsockname()[0]); s.close()
    except: pass
    for ip in ips:
        if ip.startswith('192.168.137.'): return ip
    for ip in ips:
        if ip.startswith('192.168.'): return ip
    return list(ips)[0] if ips else '127.0.0.1'

SERVE_IP = get_ip()

# ── DNS — blanket redirect everything to SERVE_IP ──────────
def dns_response(data, ip):
    if len(data) < 12: return b""
    tid = data[0:2]
    if struct.unpack(">H", data[4:6])[0] == 0: return b""
    off = 12
    while off < len(data) and data[off] != 0: off += 1 + data[off]
    off += 1
    if off + 4 > len(data): return b""
    qtype = struct.unpack(">H", data[off:off+2])[0]
    q = data[12:]
    if qtype == 1:
        ip_b = bytes(int(x) for x in ip.split("."))
        h = struct.pack(">HHHHHH", struct.unpack(">H",tid)[0], 0x8180, 1, 1, 0, 0)
        a = b"\xc0\x0c"+struct.pack(">H",1)+struct.pack(">H",1)+struct.pack(">I",30)+struct.pack(">H",4)+ip_b
        return h + q + a
    else:
        h = struct.pack(">HHHHHH", struct.unpack(">H",tid)[0], 0x8183, 1, 0, 0, 0)
        return h + q

def dns_nxdomain(data):
    if len(data) < 12: return b""
    tid = data[0:2]
    q = data[12:]
    h = struct.pack(">HHHHHH", struct.unpack(">H",tid)[0], 0x8183, 1, 0, 0, 0)
    return h + q

def get_domain(data):
    try:
        off, d = 12, ""
        while data[off] != 0:
            l = data[off]; d += data[off+1:off+1+l].decode(errors='replace')+'.'; off += 1+l
        return d.rstrip('.')
    except: return '?'

GUIDE_DOMAINS = [
    'manuals.playstation.net',
    'sv.ipfilter.jp',
    'document.playstation.net',
    'github.com',
    'www.github.com',
]

# added 2026-10-08: a click inside the guide opened no page at all. The guide's own
# links are Sony WEB PAGES (the console asked for www.playstation.com the moment the
# link was clicked) and those hosts fell through to BLOCK_MARKERS, so they got
# NXDOMAIN and the WebKit view had nothing to load. Web-page hosts are now served our
# probe exactly like the manual is. API, store, CDN, update and telemetry hosts all
# have a different first label, so they stay blocked below.
GUIDE_LINK_LABELS = ('www', 'support', 'manuals', 'document', 'help')

BLOCKED_DOMAINS = [
    'playstation.com', 'www.playstation.com',
    'playstation.net', 'manuals.playstation.net', 'document.playstation.net',
    'sony.com', 'www.sony.com',
    'psn.com', 'store.playstation.com',
    'account.sony.com', 'id.sony.com',
    'auth.api.sony.com',
    'telemetry-console.api.playstation.com',
    'registry.np.ac.playstation.net',
    'np.ac.playstation.net',
    'api.playstation.com',
    'update.playstation.net',
    'get2play.com',
    'playstation.net',
    'ps4.playstation.com',
    'ps5.playstation.com',
    'status.playstation.com',
    # added 2026-10-08: remaining Sony/PSN infrastructure so the console cannot
    # reach update / telemetry / account hosts. NOTE the guide domains above are
    # matched FIRST in run_dns(), so blocking playstation.net here does not stop
    # manuals.playstation.net from being served by us.
    'scea.com',
    'scei.co.jp',
    'sony.co.jp',
    'sonyentertainmentnetwork.com',
    'psnow.com',
    'gaikai.com',
]

# A name is blocked if it matches a list entry by suffix, OR if it merely
# CONTAINS a PlayStation/Sony marker. The substring rule exists because CDN
# aliases keep the vendor name in the MIDDLE of the hostname, e.g.
#   gst.prod.dl.playstation.net.edgesuite.net
# ends in .edgesuite.net, so the suffix rule let it resolve and the console could
# still reach Sony's CDN. NOTE: run_dns() checks GUIDE_DOMAINS first, so the
# substring rule can never stop manuals.playstation.net from being served by us.
BLOCK_MARKERS = ('playstation', 'sonyentertainmentnetwork', 'scea.com', 'sony.net', 'sony.com')

def is_guide(dom):
    # the manual itself, plus the other hosts the guide is served from
    for gd in GUIDE_DOMAINS:
        if dom == gd or dom.endswith('.' + gd):
            return True
    # and the web pages the guide links to. Only a WEB PAGE host qualifies:
    # anything Sony runs as an API, store, CDN, update or telemetry host has a
    # different first label and is still blocked by is_blocked().
    first = dom.split('.')[0]
    if first in GUIDE_LINK_LABELS and 'playstation' in dom:
        return True
    return False

def is_blocked(dom):
    for bd in BLOCKED_DOMAINS:
        if dom == bd or dom.endswith('.' + bd):
            return True
    for mk in BLOCK_MARKERS:
        if mk in dom:
            return True
    return False

# ── blocked-query log suppression ─────────────────────────────
# The console retries telemetry hosts continuously, which buried the console in
# [DNS→BLOCK] lines. Each blocked DOMAIN is now reported once, then suppressed,
# and a one-line rollup prints every BLOCK_ROLLUP_SEC seconds instead.
BLOCK_SEEN  = set()
BLOCK_COUNT = [0]
BLOCK_LAST  = [time.time()]
BLOCK_ROLLUP_SEC = 15

def blocked_note(dom):
    BLOCK_COUNT[0] += 1
    if dom not in BLOCK_SEEN:
        BLOCK_SEEN.add(dom)
        p(f"[dim]{ts()}[/dim] [red][DNS→BLOCK][/red] {dom[:60]}  "
          f"[dim](first occurrence - repeats hidden)[/dim]")
        return
    now = time.time()
    if now - BLOCK_LAST[0] >= BLOCK_ROLLUP_SEC:
        BLOCK_LAST[0] = now
        p(f"[dim]{ts()}[/dim] [red][DNS→BLOCK][/red] "
          f"{BLOCK_COUNT[0]} blocked total, {len(BLOCK_SEEN)} distinct domains "
          f"[dim](hidden)[/dim]")

def forward_dns(data):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.sendto(data, ('1.1.1.1', 53))
        r, _ = s.recvfrom(4096)
        s.close()
        return r
    except: return None

def run_dns():
    # Try binding to ICS interface first, fall back to all interfaces
    for bind_ip in [SERVE_IP, '0.0.0.0']:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((bind_ip, 53))
            p(f"[green][DNS]  :53 bound to {bind_ip} — guide domains → {SERVE_IP}, blocked → NXDOMAIN, others → 1.1.1.1[/green]")
            break
        except OSError as e:
            p(f"[yellow][DNS]  Cannot bind {bind_ip}:53 — {e}[/yellow]")
            s = None
    else:
        p("[red][DNS]  Could not bind port 53 on any interface — kill other DNS servers first[/red]")
        return

    while True:
        try:
            data, addr = s.recvfrom(512)
            dom = get_domain(data)
            if is_guide(dom):
                resp = dns_response(data, SERVE_IP)
                p(f"[dim]{ts()}[/dim] [green][DNS→US][/green] {addr[0]} → {dom[:50]}")
            elif is_blocked(dom):
                resp = dns_nxdomain(data)
                blocked_note(dom)
            else:
                resp = forward_dns(data)
                if resp is None:
                    resp = dns_nxdomain(data)
                p(f"[dim]{ts()}[/dim] [dim][DNS→1.1.1.1][/dim] {addr[0]} → {dom[:40]}")
            if resp: s.sendto(resp, addr)
        except: pass

# ── HTTP — serves files by path, falls back to PAGE ─────────
MIME = {
    '.html': 'text/html; charset=utf-8',
    '.js':   'application/javascript',
    '.css':  'text/css',
    '.json': 'application/json',
    '.lua':  'text/plain',
    '.txt':  'text/plain',
    '.md':   'text/plain',
    '.png':  'image/png',
    '.ico':  'image/x-icon',
    '.jpg':  'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif':  'image/gif',
    '.webp': 'image/webp',
    '.bmp':  'image/bmp',
    '.tif':  'image/tiff',
    '.tiff': 'image/tiff',
    '.avif': 'image/avif',
    '.svg':  'image/svg+xml',
    '.woff': 'font/woff',
    '.woff2':'font/woff2',
    '.ttf':  'font/ttf',
    '.otf':  'font/otf',
    '.xml':  'application/xml',
    '.xsl':  'application/xml',
}

def load_file(filename):
    path = os.path.join(DIRECTORY, filename)
    ext  = os.path.splitext(filename)[1].lower()
    mime = MIME.get(ext, 'text/html; charset=utf-8')
    with open(path, 'rb') as f:
        data = f.read()
    if mime.startswith('text/html'):
        data = data.replace(b'%%SERVER_IP%%', SERVE_IP.encode())
    return data, mime

class Handler(http.server.BaseHTTPRequestHandler):

    def do_GET(self):
        upgrade = self.headers.get('Upgrade','').lower()
        if upgrade == 'websocket':
            p(f"[dim]{ts()}[/dim] [cyan][WS?][/cyan] upgrade request: path={self.path!r} key={self.headers.get('Sec-WebSocket-Key','?')[:8]}")

        if self.path in ('/ping', '/log', '/cors_ping'):
            self._send(200, 'text/plain', b'ok')
            return

        if upgrade == 'websocket':
            import hashlib, base64, struct as _struct
            key = self.headers.get('Sec-WebSocket-Key','')
            p(f"[dim]{ts()}[/dim] [cyan][WS][/cyan] handling upgrade, key={key[:8]}")
            accept = base64.b64encode(
                hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()
            ).decode()
            self.wfile.write((
                'HTTP/1.1 101 Switching Protocols\r\n'
                'Upgrade: websocket\r\n'
                'Connection: Upgrade\r\n'
                f'Sec-WebSocket-Accept: {accept}\r\n'
                '\r\n'
            ).encode())
            self.wfile.flush()
            p(f"[dim]{ts()}[/dim] [bold green][WS][/bold green] PS5 WebSocket CONNECTED on :443!")
            # Prevent http.server from closing the socket when handler returns
            self.close_connection = False
            sock = self.connection
            sock.settimeout(120)

            def ws_send(s, data):
                if isinstance(data, str): data = data.encode()
                n = len(data)
                hdr = b'\x81'
                if n < 126: hdr += bytes([n])
                elif n < 65536: hdr += b'\x7e' + _struct.pack('>H', n)
                else: hdr += b'\x7f' + _struct.pack('>Q', n)
                s.sendall(hdr + data)

            try:
                ws_send(sock, 'ASCEND_WS_OK')
                while True:
                    b0 = sock.recv(1)
                    if not b0: break
                    b1 = sock.recv(1)
                    if not b1: break
                    b1 = b1[0]
                    masked = b1 & 0x80
                    length = b1 & 0x7f
                    if length == 126: length = _struct.unpack('>H', sock.recv(2))[0]
                    elif length == 127: length = _struct.unpack('>Q', sock.recv(8))[0]
                    mask = sock.recv(4) if masked else b'\x00\x00\x00\x00'
                    payload = bytearray()
                    while len(payload) < length:
                        chunk = sock.recv(length - len(payload))
                        if not chunk: break
                        payload.extend(chunk)
                    if masked:
                        for i in range(len(payload)): payload[i] ^= mask[i % 4]
                    opcode = b0[0] & 0x0f
                    if opcode == 8: break
                    if opcode == 9:
                        sock.sendall(b'\x8a' + bytes([len(payload)]) + bytes(payload))
                    elif opcode == 1:
                        msg = payload.decode(errors='replace')
                        p(f"[dim]{ts()}[/dim] [bold green][WS←][/bold green] {msg[:400]}")
                        ws_send(sock, 'ACK:' + msg[:200])
            except Exception as e:
                p(f"[dim]{ts()}[/dim] [yellow][WS][/yellow] closed: {e}")
            return

        if self.path == '/redirect_test':
            self.send_response(302)
            self.send_header('Location', 'file:///proc/version')
            self.send_header('Content-Length', '0')
            self.end_headers()
            p(f"[dim]{ts()}[/dim] [yellow][REDIRECT][/yellow] sent 302 → file:///proc/version")
            return

        # Strip query string
        raw_path = self.path.split('?')[0].lstrip('/')

        # Resolve filename: use requested file if it exists, else fall back to PAGE
        if raw_path == '':
            filename = PAGE  # blank root → first page
        elif raw_path == 'index.html':
            filename = 'index.html'
        else:
            # Serve any file that exists in DIRECTORY (basename only: no traversal)
            candidate = os.path.basename(raw_path)  # block path traversal
            if os.path.isfile(os.path.join(DIRECTORY, candidate)):
                filename = candidate
            else:
                filename = PAGE  # fallback

        # At most one probe per client per cooldown. No flag, no query string and
        # no URL can bypass this, which is the point: the bypass attempt failed.
        if filename == PAGE:
            ip   = self.client_address[0]
            last = PROBE_ONCE.get(ip, 0.0)
            now  = time.time()
            if last and (now - last) < PROBE_COOLDOWN:
                left = PROBE_COOLDOWN - (now - last)
                self._send(200, 'text/html; charset=utf-8', stub_page(left))
                p(f"[dim]{ts()}[/dim] [yellow][STUB][/yellow] "
                  f"[cyan]{ip}[/cyan] served the resting page - "
                  f"[dim]{left:.0f}s of a {PROBE_COOLDOWN:.0f}s cooldown left[/dim]")
                return
            PROBE_ONCE[ip] = now

        try:
            data, mime = load_file(filename)
            self._send(200, mime, data)
            p(f"[dim]{ts()}[/dim] [magenta][PAGE][/magenta] "
              f"[cyan]{self.client_address[0]}[/cyan] loaded {filename} "f"[dim]host={self.headers.get('Host','?')}[/dim]")
        except Exception as e:
            self._send(404, 'text/plain', f'Not found: {filename} ({e})'.encode())

    def do_POST(self):
        self._send(200, 'application/json', b'{"ok":true}')
        try:
            n    = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(min(n, 65536))
            d    = json.loads(body)
            # Always write raw POST to log file so nothing is lost
            with open(os.path.join(DIRECTORY, 'ascend_raw.log'), 'a', encoding='utf-8') as lf:
                lf.write(f"{ts()} {self.path} {body.decode(errors='replace')[:400]}\n")
        except Exception as e:
            p(f"[red][POST] parse error: {e}[/red]")
            return

        # ── /result or /log — mirror every PS5 screen message ──────────
        if self.path in ('/log', '/result'):
            msg = str(d.get('msg', d.get('tag','') + ' ' + str(d)))[:500]
            if not msg.strip(): return
            if any(x in msg for x in ['CRASH','CRITICAL','kernel','kexp']):
                print(ts() + ' !! PS5 ' + msg, flush=True)
            elif any(x in msg for x in ['mismatch','INTERESTING','JIT','HIT']):
                print(ts() + ' ** PS5 ' + msg, flush=True)
            elif any(x in msg for x in ['ok','pass','PASS','connected','OK']):
                print(ts() + ' >> PS5 ' + msg, flush=True)
            else:
                print(ts() + '    PS5 ' + msg, flush=True)
            return

        # ── /report or /probe — structured findings ─────────
        if self.path not in ('/report', '/probe'): return
        try:
            rid  = str(d.get('id',''))[:80]
            stat = str(d.get('status', d.get('sev', d.get('crit', ''))))[:20]
            text = str(d.get('text', d.get('msg', str(d))))[:500]
            hot  = bool(d.get('interesting', d.get('crit', False)))

            if rid == '_start':
                ua = str(d.get('ua', text))[:200]
                p(Panel(
                    f"[bold green]PS5 CONNECTED[/bold green]\n[dim]{ua[:120]}[/dim]",
                    border_style="green"))
                return

            if rid in ('_done','_fuzz','_jitdone'):
                p(Panel(
                    f"[bold green]SESSION COMPLETE[/bold green]\n{text}",
                    border_style="yellow" if INTERESTING else "green"))
                if INTERESTING:
                    p(Panel(
                        "\n".join(
                            f"{'[CRIT]' if r['status']=='crit' else '[HOT]'} "
                            f"[bold]{r['id']}[/bold] -> {r['text'][:120]}"
                            for r in INTERESTING
                        ),
                        title="[bold yellow]ALL FINDINGS[/bold yellow]",
                        border_style="yellow"))
                INTERESTING.clear()
                return

            RESULTS.append(d)
            if hot: INTERESTING.append(d)

            if stat == 'crit':
                print(ts() + ' !! CRITICAL -- ' + rid + '\n   ' + text[:300], flush=True)
            elif stat == 'hot':
                print(ts() + ' ** INTERESTING  ' + rid + ' -> ' + text[:150], flush=True)
            elif stat == 'ok':
                print(ts() + '    PASS       ' + rid + ' -> ' + text[:100], flush=True)
            else:
                print(ts() + '    FAIL       ' + rid + ' -> ' + text[:100], flush=True)

        except Exception as e:
            p(f"[red][REPORT] {e}[/red]")

    def do_OPTIONS(self):
        self._send(200, 'text/plain', b'')

    def handle_one_request(self):
        # Log every raw request method+path for debugging
        try:
            super().handle_one_request()
        except Exception as e:
            p(f"[red][REQ] error: {e}[/red]")

    def _send(self, code, ctype, body):
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a): pass

def make_cert():
    # Persist cert so PS5 doesn't need to re-accept after every restart
    cp = os.path.join(DIRECTORY, 'ascend_cert.pem')
    kp = os.path.join(DIRECTORY, 'ascend_key.pem')
    if os.path.isfile(cp) and os.path.isfile(kp):
        p("[green][SSL] reusing saved cert (PS5 already accepted it)[/green]")
        return cp, kp
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        import datetime as dt, ipaddress
        key = rsa.generate_private_key(65537, 2048, default_backend())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'manuals.playstation.net')])
        cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(dt.datetime.now(dt.timezone.utc))
            .not_valid_after(dt.datetime.now(dt.timezone.utc)+dt.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName([
                x509.IPAddress(ipaddress.IPv4Address(SERVE_IP)),
                x509.DNSName("*"),
                x509.DNSName("*.playstation.net"),
                x509.DNSName("*.playstation.com"),
                x509.DNSName("manuals.playstation.net"),
                x509.DNSName("document.playstation.net"),
                x509.DNSName("localhost"),
            ]),critical=False)
            .sign(key, hashes.SHA256(), default_backend()))
        with open(cp,"wb") as f: f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(kp,"wb") as f: f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
        p("[yellow][SSL] new cert generated — PS5 must accept it once[/yellow]")
        return cp, kp
    except Exception as e:
        p(f"[yellow][SSL] {e}[/yellow]"); return None, None

class ThreadingHTTPSServer(http.server.ThreadingHTTPServer):
    pass

def run_https(cert, key):
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        httpd = ThreadingHTTPSServer(("0.0.0.0", 443), Handler)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        p("[green][HTTPS] :443 listening[/green]")
        httpd.serve_forever()
    except Exception as e: p(f"[red][HTTPS] {e}[/red]")

def run_http():
    for port in [80, 8080]:
        try:
            httpd = http.server.HTTPServer(("0.0.0.0", port), Handler)
            p(f"[green][HTTP]  :{port} listening[/green]")
            httpd.serve_forever()
            return
        except PermissionError:
            if port==80: p("[yellow][HTTP]  Port 80 needs admin, trying 8080...[/yellow]")
        except OSError as e:
            p(f"[red][HTTP]  :{port} — {e}[/red]")

def run_ws(cert_path, key_path):
    """Standalone TLS WebSocket server on port 8765."""
    import hashlib, base64, struct as _ws_struct
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(('0.0.0.0', 8765))
    except OSError as e:
        p(f"[yellow][WSS]  :8765 bind failed: {e}[/yellow]"); return
    srv.listen(8)
    p("[green][WSS]  :8765 listening (WebSocket)[/green]")

    def ws_send(conn, data):
        if isinstance(data, str): data = data.encode()
        n = len(data)
        hdr = b'\x81'
        if n < 126: hdr += bytes([n])
        elif n < 65536: hdr += b'\x7e' + _ws_struct.pack('>H', n)
        else: hdr += b'\x7f' + _ws_struct.pack('>Q', n)
        conn.sendall(hdr + data)

    def handle_ws(raw_sock, addr):
        try:
            conn = ctx.wrap_socket(raw_sock, server_side=True)
        except Exception as e:
            p(f"[yellow][WSS]  TLS fail {addr[0]}: {e}[/yellow]"); raw_sock.close(); return
        try:
            # Read HTTP upgrade request
            req = b''
            while b'\r\n\r\n' not in req:
                chunk = conn.recv(4096)
                if not chunk: return
                req += chunk
            req_str = req.decode(errors='replace')
            ws_key = ''
            for line in req_str.split('\r\n'):
                if line.lower().startswith('sec-websocket-key:'):
                    ws_key = line.split(':', 1)[1].strip()
            accept = base64.b64encode(
                hashlib.sha1((ws_key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()
            ).decode()
            resp = (
                'HTTP/1.1 101 Switching Protocols\r\n'
                'Upgrade: websocket\r\n'
                'Connection: Upgrade\r\n'
                f'Sec-WebSocket-Accept: {accept}\r\n'
                '\r\n'
            ).encode()
            conn.sendall(resp)
            p(f"[dim]{ts()}[/dim] [bold green][WSS][/bold green] PS5 WebSocket CONNECTED from {addr[0]}!")
            ws_send(conn, 'ASCEND_WSS_OK')
            conn.settimeout(120)
            while True:
                b0 = conn.recv(1)
                if not b0: break
                b1 = conn.recv(1)
                if not b1: break
                b1 = b1[0]
                masked = b1 & 0x80
                length = b1 & 0x7f
                if length == 126: length = _ws_struct.unpack('>H', conn.recv(2))[0]
                elif length == 127: length = _ws_struct.unpack('>Q', conn.recv(8))[0]
                mask = conn.recv(4) if masked else b'\x00\x00\x00\x00'
                payload = bytearray()
                while len(payload) < length:
                    chunk = conn.recv(length - len(payload))
                    if not chunk: break
                    payload.extend(chunk)
                if masked:
                    for i in range(len(payload)): payload[i] ^= mask[i % 4]
                opcode = b0[0] & 0x0f
                if opcode == 8: break
                if opcode == 9:
                    conn.sendall(b'\x8a' + bytes([len(payload)]) + bytes(payload))
                elif opcode == 1:
                    msg = payload.decode(errors='replace')
                    p(f"[dim]{ts()}[/dim] [bold green][WSS←][/bold green] {msg[:400]}")
                    ws_send(conn, 'ACK:' + msg[:200])
        except Exception as e:
            p(f"[dim]{ts()}[/dim] [yellow][WSS][/yellow] {addr[0]} closed: {e}")
        finally:
            try: conn.close()
            except: pass

    while True:
        try:
            raw, addr = srv.accept()
            threading.Thread(target=handle_ws, args=(raw, addr), daemon=True).start()
        except Exception as e:
            p(f"[red][WSS]  accept error: {e}[/red]")

# ── MAIN ───────────────────────────────────────────────────
p(f"[bold cyan]{BANNER}[/bold cyan]")
p(Panel(
    "[bold white]ASCEND — TARGETED EXPLOIT PROBES[/bold white]\n"
    "[dim]DNS · HTTP · HTTPS · Live Results[/dim]",
    border_style="cyan"
))
p(Panel(
    f"[bold green]SERVE IP DETECTED: {SERVE_IP}[/bold green]\n\n"
    f"[bold]On PS5:[/bold]\n"
    f"  Settings → Network → Set Up Internet Connection\n"
    f"  → Custom → WiFi → DNS: Manual\n"
    f"  → Primary DNS:   [bold yellow]{SERVE_IP}[/bold yellow]\n"
    f"  → Secondary DNS: [bold yellow]8.8.8.8[/bold yellow]\n"
    f"  → MTU: Auto → Proxy: Do Not Use → Done\n\n"
    f"[bold]Then:[/bold] Settings → User's Guide → scroll bottom → click link\n\n"
    f"[bold]Serving:[/bold] {PAGE} (red page)",
    title="[bold cyan]SETUP[/bold cyan]",
    border_style="cyan"
))

p("[dim]Generating SSL cert...[/dim]")
cert, key = make_cert()
if cert: p("[green]SSL ready[/green]")

threading.Thread(target=run_dns, daemon=True).start()
time.sleep(0.3)
if cert:
    threading.Thread(target=run_https, args=(cert,key), daemon=True).start()
    threading.Thread(target=run_ws, args=(cert,key), daemon=True).start()
    time.sleep(0.3)

p(Panel(
    f"[bold green]ASCEND ONLINE[/bold green]\n"
    f"[dim]DNS :53 (blanket) · HTTP :80 · HTTPS :443 · WSS :8765[/dim]\n"
    f"[dim]Every PS5 request → our server → {PAGE}[/dim]\n"
    f"[dim]Waiting for PS5...[/dim]",
    border_style="green"
))
p("")

run_http()

