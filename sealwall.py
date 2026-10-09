#!/usr/bin/env python3
"""sealwall: policy + tamper-evident audit proxy for MCP stdio servers.
Usage: sealwall.py --policy policy.json [--log audit.jsonl] -- <mcp server command>
       sealwall.py --policy policy.json --http-upstream https://host/mcp [--listen 8787]
       sealwall.py verify|seal|report|tail|keygen ...   (see README)"""
import sys, json, re, time, hashlib, hmac, fnmatch, subprocess, threading, argparse, os, csv, html, secrets, urllib.parse

if hasattr(sys.stdin, "reconfigure"):
    try: sys.stdin.reconfigure(encoding="utf-8", errors="replace")
    except Exception: pass
if hasattr(sys.stdout, "reconfigure"):
    try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception: pass

INJECTION = [
    r"ignore (all )?(previous|prior) instructions",
    r"disregard .{0,30}instructions",
    r"you are now",
    r"do not tell the user",
    r"send .{0,40}(\.ssh|id_rsa|password|api[_ ]key)",
]

def digest(ev):
    return hashlib.sha256(json.dumps(ev, sort_keys=True).encode("utf-8")).hexdigest()

class Audit:
    def __init__(s, path):
        s.path, s.lock, s.prev = path, threading.Lock(), "0" * 64
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        s.prev = json.loads(line).get("hash", s.prev)

    def write(s, **ev):
        with s.lock:
            ev.update(ts=round(time.time(), 3), prev=s.prev)
            ev["hash"] = digest(ev)
            s.prev = ev["hash"]
            with open(s.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(ev, ensure_ascii=False) + "\n")

def verify(path, keyfile=None):
    if not os.path.exists(path):
        print(f"Audit log not found: {path}")
        return 1
    prev, hashes = "0" * 64, []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for i, l in enumerate(f, 1):
            line = l.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except ValueError:
                print(f"TAMPERED: invalid JSON at line {i}")
                return 1
            h = ev.pop("hash", None)
            if ev.get("prev") != prev or digest(ev) != h:
                print(f"TAMPERED at line {i}")
                return 1
            prev = h
            hashes.append(h)
    print("Audit log intact")
    if keyfile:
        if not os.path.exists(keyfile):
            print(f"Key file not found: {keyfile}"); return 1
        seal_path = path + ".seal"
        if not os.path.exists(seal_path):
            print("No seal file found (run: sealwall seal LOG --key KEYFILE)"); return 1
        with open(seal_path, "r", encoding="utf-8") as sf:
            sl = json.load(sf)
        count = int(sl.get("count", -1))
        want = hmac.new(_key(keyfile), f"{count}:{sl.get('head')}".encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(want, str(sl.get("hmac", ""))):
            print("SEAL INVALID: wrong key or seal modified"); return 1
        if count < 0 or count > len(hashes) or (count > 0 and hashes[count - 1] != sl.get("head")):
            print("SEAL MISMATCH: log was truncated or rewritten after sealing"); return 1
        print(f"Seal valid: first {count} entries match the signed head")
    return 0

def _key(keyfile):
    if not os.path.exists(keyfile):
        raise FileNotFoundError(f"Key file not found: {keyfile}")
    with open(keyfile, "rb") as f: return f.read().strip()

def seal(path, keyfile):
    if verify(path) != 0: return 1
    with open(path, "r", encoding="utf-8") as f:
        hashes = [json.loads(l)["hash"] for l in f if l.strip()]
    head, n = (hashes[-1] if hashes else "0" * 64), len(hashes)
    sig = hmac.new(_key(keyfile), f"{n}:{head}".encode(), hashlib.sha256).hexdigest()
    with open(path + ".seal", "w", encoding="utf-8") as f:
        json.dump({"count": n, "head": head, "hmac": sig, "ts": round(time.time(), 3)}, f)
    print(f"Sealed {n} entries -> {path}.seal  (store the key and seal OFF this machine)")
    return 0

PATH_KEYS = {"path", "paths", "file", "files", "filename", "filepath", "dir", "directory", "folder", "source", "destination", "src", "dst", "dest", "target", "cwd", "uri", "root", "location"}

def _is_path_key(key):
    k = str(key).lower().replace("-", "_")
    return k in PATH_KEYS or any(part in PATH_KEYS for part in k.split("_"))

def _walk(o, key="", depth=0):
    if depth > 50: return
    if isinstance(o, str): yield key, o
    elif isinstance(o, dict):
        for k, v in o.items(): yield from _walk(v, str(k).lower(), depth + 1)
    elif isinstance(o, list):
        for v in o: yield from _walk(v, key, depth + 1)

def _is_path(key, v):
    if not isinstance(v, str): return False
    v_s = v.strip()
    if re.match(r"^[a-z][a-z0-9+.-]*://", v_s, re.I) and not v_s.lower().startswith("file://"): return False
    return _is_path_key(key) or v_s.startswith(("/", "~", "./", "../", "\\", "file://")) or bool(re.match(r"^[A-Za-z]:[\\/]", v_s))

def _norm(p):
    p = p.strip()
    if p.lower().startswith("file://"):
        u = urllib.parse.urlparse(p)
        p = urllib.parse.unquote(u.path)
        if sys.platform == "win32" and re.match(r"^/[A-Za-z]:", p):
            p = p[1:]
    p = os.path.realpath(os.path.abspath(os.path.expanduser(os.path.expandvars(p))))  # resolves symlinks and ..
    return os.path.normcase(p)

def _within(p, root):
    root = os.path.normcase(os.path.normpath(root))
    try: return os.path.commonpath([p, root]) == root
    except ValueError: return False

def path_violation(pol, args):
    allow, deny = pol.get("allow_paths") or [], pol.get("deny_paths") or []
    if not allow and not deny: return None
    allow, deny = [_norm(x) for x in allow], [_norm(x) for x in deny]
    for key, v in _walk(args):
        if not isinstance(v, str) or len(v) > 4096: continue
        if "\x00" in v: return f"path '{v}' contains invalid null byte"
        is_pkey = _is_path_key(key)
        v_s = v.strip()
        if not is_pkey and ("\n" in v or not _is_path(key, v)): continue
        if is_pkey and "\n" in v_s: return f"path '{v}' contains invalid newline characters"
        p = _norm(v_s)
        if any(_within(p, d) for d in deny): return f"path '{v}' is in a denied location"
        if allow and not any(_within(p, a) for a in allow): return f"path '{v}' is outside allowed paths"
    return None

import ipaddress

URL_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.I)
URL_KEYS = {"url", "uri", "href", "link", "endpoint", "target"}
INTERNAL_NAMES = ("localhost", "*.localhost", "*.local", "*.internal", "metadata.google.internal")
NUMERIC_HOST = re.compile(r"(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}", re.I)

def _host_match(host, pat):
    pat = str(pat).lower().strip(".")
    return host == pat[2:] or host.endswith(pat[1:]) if pat.startswith("*.") else host == pat

def url_violation(pol, args):
    """Argument-level URL policy. Parses once, rejects anything ambiguous (userinfo, backslash in authority,
    control chars, obfuscated IPs) so the proxy and the real HTTP client cannot disagree about the host."""
    allow, deny = pol.get("allow_hosts") or [], pol.get("deny_hosts") or []
    block_internal = pol.get("block_private_hosts", True)
    for key, v in _walk(args):
        if not isinstance(v, str) or len(v) > 4096: continue
        u = v.strip()
        if u.lower().startswith("file://"): continue
        has_scheme = bool(URL_RE.match(u))
        if not has_scheme and not (key in URL_KEYS and allow): continue
        if re.search(r"[\x00-\x20\x7f]", u): return f"URL '{v[:80]}' contains whitespace or control characters"
        if not has_scheme: u = "http://" + u.lstrip("/")
        scheme, rest = u.split("://", 1)
        if allow and scheme.lower() not in ("http", "https"): return f"URL scheme '{scheme}' not allowed"
        auth = re.split(r"[/?#]", rest, maxsplit=1)[0]
        if "\\" in auth: return "backslash in URL authority (parser-differential risk)"
        if "@" in auth: return "userinfo ('@') in URL authority (parser-differential risk)"
        try: host = (urllib.parse.urlsplit(u).hostname or "").lower().rstrip(".")
        except ValueError: return "malformed URL"
        if not host: return "URL has no host"
        try: host = host.encode("idna").decode("ascii")
        except UnicodeError: return "invalid internationalized host"
        try:
            ip = ipaddress.ip_address(host)
            ip = getattr(ip, "ipv4_mapped", None) or ip
            if block_internal and (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
                return f"URL host {host} is a private/internal address"
        except ValueError:
            if NUMERIC_HOST.fullmatch(host): return f"obfuscated numeric host '{host}'"
            if block_internal and any(_host_match(host, p) for p in INTERNAL_NAMES): return f"URL host {host} is an internal name"
        if any(_host_match(host, p) for p in deny): return f"URL host {host} is denied"
        if allow and not any(_host_match(host, p) for p in allow): return f"URL host {host} is not in allow_hosts"
    return None

def _matches(tool, pats): return any(fnmatch.fnmatch(tool, p) for p in (pats or []))

def classify(pol, text):
    """Optional external classifier hook: policy {"classifier": ["python", "my_clf.py"]}. Exit code != 0 means unsafe. Fails closed."""
    cmd = pol.get("classifier")
    if not cmd: return False
    try: return subprocess.run(cmd, input=text, text=True, capture_output=True, timeout=pol.get("classifier_timeout", 10)).returncode != 0
    except Exception: return True

def decide(pol, tool, args):
    blob = json.dumps(args, ensure_ascii=False)
    for rx in pol.get("deny_args", []):
        if re.search(rx, blob, re.I):
            return "deny", f"argument matches {rx}"
    if pol.get("block_secrets", True):
        for rx in SECRETS:
            if re.search(rx, blob): return "deny", "secret/credential detected in arguments"
    pv = path_violation(pol, args)
    if pv: return "deny", pv
    uv = url_violation(pol, args)
    if uv: return "deny", uv
    for r in pol.get("rules", []):
        if fnmatch.fnmatch(tool, r["tool"]):
            return r["action"], r.get("reason", "rule " + r["tool"])
    return pol.get("default", "deny"), "default policy"

def ask_human(tool, args, timeout=15.0):
    safe_tool = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", str(tool))
    safe_args = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", json.dumps(args, ensure_ascii=False)[:150])
    msg = f"\n[sealwall] ALLOW tool call '{safe_tool}' with args {safe_args}? [y/N] (timeout {int(timeout)}s): "
    if sys.platform == "win32":
        try:
            import msvcrt
            sys.stderr.write(msg)
            sys.stderr.flush()
            start = time.time()
            buf = []
            while time.time() - start < timeout:
                if msvcrt.kbhit():
                    ch = msvcrt.getwche()
                    if ch in ("\r", "\n"):
                        sys.stderr.write("\n")
                        sys.stderr.flush()
                        return "".join(buf).strip().lower() == "y"
                    elif ch == "\b":
                        if buf:
                            buf.pop()
                    else:
                        buf.append(ch)
                time.sleep(0.05)
            sys.stderr.write("\n[sealwall] Approval timed out -> Denied\n")
            sys.stderr.flush()
            return False
        except Exception:
            return False
    else:
        try:
            import select
            with open("/dev/tty", "r+", encoding="utf-8") as t:
                t.write(msg)
                t.flush()
                r, _, _ = select.select([t], [], [], timeout)
                if r:
                    ans = t.readline().strip().lower()
                    return ans == "y"
                t.write("\n[sealwall] Approval timed out -> Denied\n")
                t.flush()
                return False
        except Exception:
            return False

SECRETS = [r"AKIA[0-9A-Z]{16}", r"gh[pousr]_[A-Za-z0-9]{36,}", r"-----BEGIN [A-Z ]*PRIVATE KEY-----", r"xox[baprs]-[A-Za-z0-9-]{10,}",
           r"sk-[A-Za-z0-9_-]{20,}", r"AIza[0-9A-Za-z_-]{35}"]

def redact(o):
    """Replace secrets inside strings of a JSON-like object (both keys and values). Returns (new_obj, count)."""
    if isinstance(o, str):
        n = 0
        for rx in SECRETS:
            o, k = re.subn(rx, "[REDACTED:secret]", o); n += k
        return o, n
    if isinstance(o, dict):
        out, n = {}, 0
        for k, v in o.items():
            new_k, ck = redact(str(k))
            new_v, cv = redact(v)
            out[new_k] = new_v
            n += (ck + cv)
        return out, n
    if isinstance(o, list):
        out, n = [], 0
        for v in o:
            x, c = redact(v); out.append(x); n += c
        return out, n
    return o, 0

TOOL_POISON = INJECTION + [
    r"<important>", r"before (using|calling) this tool", r"(read|cat|open|send) .{0,40}(\.ssh|\.env|id_rsa|\.aws|credentials)",
    r"do not (mention|reveal|tell|show)", r"~/\.(ssh|aws)",
]

def tool_sig(t):
    keep = {k: t.get(k) for k in ("name", "description", "inputSchema")}
    return hashlib.sha256(json.dumps(keep, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()

class Guard:
    """Transport-independent policy engine, shared by the stdio and HTTP proxies."""
    def __init__(s, pol, audit, interactive=False, ask_timeout=15.0, pins_path=None, accept_changes=False):
        s.pol, s.audit, s.interactive, s.ask_timeout = pol, audit, interactive, ask_timeout
        s.pins_path, s.accept_changes = pins_path, accept_changes
        s.pins, s.blocked, s.pending, s.lock = {}, {}, {}, threading.Lock()
        s.tainted, s.taint_src = False, None  # session taint: set once an untrusted-source tool has run
        if pins_path and os.path.exists(pins_path):
            with open(pins_path, encoding="utf-8") as f: s.pins = json.load(f)

    @staticmethod
    def _k(rid): return json.dumps(rid, sort_keys=True)

    def request(s, m):
        """Returns (forward, reply): message to send upstream (or None) and an immediate reply for the client (or None)."""
        if not isinstance(m, dict):
            # JSON-RPC batches are not supported (removed from MCP spec): reject, fail closed.
            s.audit.write(event="batch_rejected", reason="non-object JSON-RPC message")
            items = m if isinstance(m, list) else []
            errs = [{"jsonrpc": "2.0", "id": i.get("id"), "error": {"code": -32600, "message": "Blocked by sealwall: batch requests not supported"}}
                    for i in items if isinstance(i, dict) and "id" in i]
            return None, (errs or None)
        method = m.get("method")
        if method == "tools/call":
            p = m.get("params") if isinstance(m.get("params"), dict) else {}
            tool, args = str(p.get("name", "")), p.get("arguments") or {}
            if tool in s.blocked: act, why = "deny", s.blocked[tool]
            else: act, why = decide(s.pol, tool, args)
            if act == "allow" and s.tainted and _matches(tool, s.pol.get("sinks")):
                act = s.pol.get("taint_action", "ask")
                why = f"session tainted by untrusted source '{s.taint_src}'; sink '{tool}' needs review"
            if act == "ask":
                if s.interactive:
                    act = "allow" if ask_human(tool, args, timeout=s.ask_timeout) else "deny"
                    why += " (human review)"
                else:
                    act, why = "deny", why + " (human review: fail-closed)"
            s.audit.write(event="tool_call", tool=tool, args=args, decision=act, reason=why)
            if act == "deny":
                return None, {"jsonrpc": "2.0", "id": m.get("id"), "error": {"code": -32001, "message": f"Blocked by sealwall: {why}"}}
            if not s.tainted and _matches(tool, s.pol.get("sources")):
                s.tainted, s.taint_src = True, tool
                s.audit.write(event="session_tainted", tool=tool)
            with s.lock:
                if len(s.pending) > 10000: s.pending.clear()
                s.pending[s._k(m.get("id"))] = ("call", tool)
        elif method == "tools/list":
            with s.lock:
                if len(s.pending) > 10000: s.pending.clear()
                s.pending[s._k(m.get("id"))] = ("list", None)
        return m, None

    def response(s, m):
        if not isinstance(m, dict) or ("result" not in m and "error" not in m): return m
        with s.lock: entry = s.pending.pop(s._k(m.get("id")), None)
        if entry is None: return m
        kind, tool = entry
        if kind == "call":
            if "result" in m:
                text = json.dumps(m["result"], ensure_ascii=False)
                hits = [rx for rx in INJECTION if re.search(rx, text, re.I)]
                if classify(s.pol, text): hits.append("external-classifier")
                if s.pol.get("redact_secrets", True):
                    m["result"], nred = redact(m["result"])
                    if nred: s.audit.write(event="secrets_redacted", tool=tool, count=nred)
                s.audit.write(event="tool_result", tool=tool, status="success", flagged=bool(hits), patterns=hits)
                if hits:
                    m["result"] = {"isError": True, "content": [{"type": "text", "text": "[sealwall] Output withheld: possible prompt injection"}]}
            else:
                s.audit.write(event="tool_result", tool=tool, status="error", error=m.get("error"))
        elif kind == "list" and isinstance(m.get("result"), dict):
            keep = []
            for t in m["result"].get("tools", []):
                if not isinstance(t, dict): continue
                name, sig = str(t.get("name", "")), tool_sig(t)
                text = json.dumps(t, ensure_ascii=False)
                hits = [rx for rx in TOOL_POISON if re.search(rx, text, re.I)]
                if classify(s.pol, text): hits.append("external-classifier")
                pinned = s.pins.get(name)
                if hits:
                    why = "possible tool poisoning in definition"
                    s.blocked[name] = why; s.audit.write(event="tool_blocked", tool=name, reason=why, patterns=hits)
                elif pinned and pinned != sig and not s.accept_changes:
                    why = "tool definition changed since it was pinned (possible rug pull)"
                    s.blocked[name] = why; s.audit.write(event="tool_blocked", tool=name, reason=why)
                else:
                    s.blocked.pop(name, None)
                    if pinned != sig:
                        s.pins[name] = sig; s.audit.write(event="tool_pinned", tool=name, sig=sig)
                    keep.append(t)
            m["result"]["tools"] = keep
            if s.pins_path:
                with s.lock:
                    tmp = s.pins_path + ".tmp"
                    with open(tmp, "w", encoding="utf-8") as f: json.dump(s.pins, f, indent=1)
                    try: os.replace(tmp, s.pins_path)
                    except OSError: pass
        return m

def run_stdio(guard, cmd):
    out_lock = threading.Lock()
    srv = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, encoding="utf-8", errors="replace", bufsize=1)

    def emit(obj):
        text = obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False)
        with out_lock:
            sys.stdout.write(text + "\n"); sys.stdout.flush()

    def client_to_server():
        try:
            for line in sys.stdin:
                try: m = json.loads(line)
                except ValueError:
                    srv.stdin.write(line); srv.stdin.flush(); continue
                fwd, reply = guard.request(m)
                if reply is not None: emit(reply)
                if fwd is not None:
                    srv.stdin.write(line); srv.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
        finally:
            try: srv.stdin.close()
            except (BrokenPipeError, OSError): pass

    threading.Thread(target=client_to_server, daemon=True).start()
    try:
        for line in srv.stdout:
            try: m = json.loads(line)
            except ValueError:
                emit(line.rstrip("\r\n")); continue
            emit(guard.response(m))
    except (BrokenPipeError, OSError):
        pass
    finally:
        try: srv.wait(timeout=2)
        except subprocess.TimeoutExpired: srv.kill()

def make_http_handler(guard, upstream):
    if not str(upstream).lower().startswith(("http://", "https://")):
        raise ValueError("Invalid upstream URL: must use http:// or https://")
    import urllib.request, urllib.error
    from http.server import BaseHTTPRequestHandler
    FWD = ("Content-Type", "Accept", "Authorization", "Mcp-Session-Id", "MCP-Protocol-Version", "Last-Event-ID")

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def _send(self, code, body=b"", ctype="application/json", extra=None):
            self.send_response(code)
            self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(body)))
            for k, v in (extra or {}).items(): self.send_header(k, v)
            self.end_headers(); self.wfile.write(body)
        def do_GET(self): self._send(405, b'{"error":"sealwall: GET streams not supported (fail closed)"}')
        do_DELETE = do_GET
        def do_POST(self):
            try:
                clen = int(self.headers.get("Content-Length") or 0)
                if clen < 0 or clen > 10 * 1024 * 1024:
                    return self._send(413, b'{"error":"payload too large"}')
            except (ValueError, TypeError):
                return self._send(400, b'{"error":"invalid Content-Length"}')
            body = self.rfile.read(clen)
            try: m = json.loads(body.decode("utf-8"))
            except ValueError: return self._send(400, b'{"error":"invalid JSON"}')
            fwd, reply = guard.request(m)
            if reply is not None: return self._send(200, json.dumps(reply, ensure_ascii=False).encode("utf-8"))
            if fwd is None: return self._send(202)
            hdrs = {k: self.headers[k] for k in FWD if self.headers.get(k)}
            hdrs["Accept-Encoding"] = "identity"
            req = urllib.request.Request(upstream, data=body, headers=hdrs, method="POST")
            try: resp = urllib.request.urlopen(req, timeout=60)
            except urllib.error.HTTPError as e: resp = e
            except Exception as e: return self._send(502, json.dumps({"error": f"upstream unreachable: {e}"}).encode())
            raw, ctype = resp.read(10 * 1024 * 1024 + 1), resp.headers.get("Content-Type", "application/json")
            if len(raw) > 10 * 1024 * 1024:
                return self._send(502, b'{"error":"upstream response too large"}')
            extra = {}
            if resp.headers.get("Mcp-Session-Id"):
                extra["Mcp-Session-Id"] = resp.headers["Mcp-Session-Id"].replace("\r", "").replace("\n", "")
            extra = extra or None
            if "text/event-stream" in ctype:
                out = []
                for line in raw.decode("utf-8", "replace").split("\n"):
                    if line.startswith("data:"):
                        try: line = "data: " + json.dumps(guard.response(json.loads(line[5:])), ensure_ascii=False)
                        except ValueError: pass
                    out.append(line)
                raw = "\n".join(out).encode("utf-8")
            elif raw.strip():
                try: raw = json.dumps(guard.response(json.loads(raw.decode("utf-8"))), ensure_ascii=False).encode("utf-8")
                except ValueError: pass
            self._send(getattr(resp, "status", 200), raw, ctype.split(";")[0] if "event-stream" not in ctype else ctype, extra)
    return H

def serve_http(guard, upstream, port):
    from http.server import ThreadingHTTPServer
    srv = ThreadingHTTPServer(("127.0.0.1", port), make_http_handler(guard, upstream))
    sys.stderr.write(f"[sealwall] http://127.0.0.1:{port}/ -> {upstream}\n")
    try: srv.serve_forever()
    except KeyboardInterrupt: pass

def load_events(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return [json.loads(l) for l in f if l.strip()]

CONTROLS = [
    ("Every agent action is logged with arguments and outcome", "SOC 2 CC7.2 (monitoring), HIPAA 164.312(b) (audit controls)"),
    ("Default-deny tool policy and path allowlists", "SOC 2 CC6.1 / CC6.3 (logical access), HIPAA 164.312(a)(1) (access control)"),
    ("Log tamper detection (hash chain, optional HMAC seal)", "SOC 2 CC7.2, HIPAA 164.312(c)(1) (integrity)"),
    ("Human approval for sensitive actions", "SOC 2 CC6.1, ISO 27001 A.8.2 (privileged access)"),
]

def report(path, out="sealwall-report.html", csv_out=None):
    ev = load_events(path)
    calls = [e for e in ev if e["event"] == "tool_call"]
    denied = [e for e in calls if e["decision"] == "deny"]
    flagged = [e for e in ev if e["event"] == "tool_result" and e.get("flagged")]
    blocked = [e for e in ev if e["event"] == "tool_blocked"]
    import io, contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf): ok = verify(path) == 0
    t = lambda x: time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(x["ts"]))
    esc = lambda x: html.escape(str(x))
    rows = lambda items, f: "".join(f"<tr>{''.join(f'<td>{esc(c)}</td>' for c in f(e))}</tr>" for e in items[:300]) or "<tr><td colspan=4>None</td></tr>"
    stats = [("Tool calls", len(calls)), ("Allowed", len(calls) - len(denied)), ("Blocked", len(denied)), ("Outputs withheld", len(flagged)), ("Tools removed", len(blocked))]
    doc = f"""<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>sealwall report</title>
<style>:root{{--bg:#fff;--fg:#111;--mut:#667;--bd:#ddd}}@media(prefers-color-scheme:dark){{:root{{--bg:#0f172a;--fg:#e2e8f0;--mut:#94a3b8;--bd:#334155}}}}
body{{font:15px system-ui;background:var(--bg);color:var(--fg);max-width:960px;margin:2rem auto;padding:0 1rem}}
.g{{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:.6rem}}.c{{border:1px solid var(--bd);border-radius:8px;padding:.7rem}}.c b{{font-size:1.6rem;display:block}}
table{{border-collapse:collapse;width:100%;display:block;overflow-x:auto}}td,th{{border-bottom:1px solid var(--bd);padding:.35rem .5rem;text-align:left;font-size:13px}}.m{{color:var(--mut)}}</style>
<h1>sealwall audit report</h1><p class=m>Log: {esc(path)} &middot; {len(ev)} events &middot; generated {time.strftime('%Y-%m-%d %H:%M')}</p>
<p><b>Chain integrity:</b> {'intact' if ok else 'FAILED - log was modified'}</p>
<div class=g>{''.join(f'<div class=c><b>{v}</b>{k}</div>' for k, v in stats)}</div>
<h2>Blocked calls</h2><table><tr><th>Time<th>Tool<th>Reason<th>Arguments</tr>{rows(denied, lambda e: (t(e), e['tool'], e['reason'], json.dumps(e['args'])[:120]))}</table>
<h2>Withheld outputs</h2><table><tr><th>Time<th>Tool<th>Patterns</tr>{rows(flagged, lambda e: (t(e), e['tool'], ', '.join(e.get('patterns', []))))}</table>
<h2>Tools removed or blocked</h2><table><tr><th>Time<th>Tool<th>Reason</tr>{rows(blocked, lambda e: (t(e), e['tool'], e['reason']))}</table>
<h2>Controls this log supports</h2><table><tr><th>Control<th>Related framework items</tr>{''.join(f'<tr><td>{esc(a)}<td>{esc(b)}</tr>' for a, b in CONTROLS)}</table>
<p class=m>This report is supporting evidence only. It is not a compliance certification, and mappings are informational.</p>"""
    with open(out, "w", encoding="utf-8") as f: f.write(doc)
    if csv_out:
        def _csv_cell(val):
            s = str(val if val is not None else "")
            return ("'" + s) if s.startswith(("=", "+", "-", "@", "\t", "\r")) else s
        with open(csv_out, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f); w.writerow(["time", "event", "tool", "decision", "reason", "flagged"])
            for e in ev: w.writerow([t(e), _csv_cell(e.get("event")), _csv_cell(e.get("tool", "")), _csv_cell(e.get("decision", e.get("status", ""))), _csv_cell(e.get("reason", "")), _csv_cell(e.get("flagged", ""))])
    print(f"Report written: {out}" + (f", {csv_out}" if csv_out else ""))
    return 0

def tail(path, follow=True):
    col = {"deny": "\033[31m", "allow": "\033[32m"}
    pos = 0
    while True:
        if os.path.exists(path):
            with open(path, encoding="utf-8", errors="replace") as f:
                f.seek(pos)
                for l in f:
                    if not l.strip(): continue
                    e = json.loads(l); d = e.get("decision", "")
                    flag = " FLAGGED" if e.get("flagged") else ""
                    print(f"{col.get(d, '')}{time.strftime('%H:%M:%S', time.localtime(e['ts']))} {e['event']:<13} {e.get('tool', ''):<16} {d}{flag} {e.get('reason', '')}\033[0m", flush=True)
                pos = f.tell()
        if not follow: return 0
        time.sleep(0.5)

def cli_tools(argv):
    ap = argparse.ArgumentParser(prog="sealwall " + argv[0])
    ap.add_argument("log", nargs="?"); ap.add_argument("--key"); ap.add_argument("--out", default="sealwall-report.html")
    ap.add_argument("--csv"); ap.add_argument("--no-follow", action="store_true")
    a = ap.parse_args(argv[1:]); c = argv[0]
    if c == "keygen":
        k = a.key or a.log or "sealwall.key"
        with open(k, "w", encoding="utf-8") as f: f.write(secrets.token_hex(32))
        try: os.chmod(k, 0o600)
        except OSError: pass
        print(f"Key written: {k}"); return 0
    if not a.log: ap.error("log path required")
    if c == "verify": return verify(a.log, a.key)
    if c == "seal":
        if not a.key: ap.error("--key required")
        return seal(a.log, a.key)
    if c == "report": return report(a.log, a.out, a.csv)
    return tail(a.log, not a.no_follow)

def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("verify", "seal", "report", "tail", "keygen"):
        sys.exit(cli_tools(sys.argv[1:]))
    ap = argparse.ArgumentParser(description="sealwall: MCP firewall and audit logger")
    ap.add_argument("--policy", required=True, help="Path to policy.json")
    ap.add_argument("--log", default="audit.jsonl", help="Path to audit.jsonl")
    ap.add_argument("--interactive", action="store_true", help="Enable interactive terminal prompts for 'ask' policy actions")
    ap.add_argument("--ask-timeout", type=float, default=15.0, help="Approval timeout in seconds (default: 15s)")
    ap.add_argument("--pins", help="Tool-definition pin file (default: <log>.pins.json)")
    ap.add_argument("--accept-changes", action="store_true", help="Re-pin tools whose definitions changed")
    ap.add_argument("--http-upstream", help="Remote MCP URL (streamable HTTP); runs a local proxy instead of wrapping stdio")
    ap.add_argument("--listen", type=int, default=8787, help="Local port for --http-upstream (default 8787)")
    ap.add_argument("cmd", nargs=argparse.REMAINDER, help="MCP server command to wrap")
    a = ap.parse_args()
    cmd = [c for c in a.cmd if c != "--"]
    if not cmd and not a.http_upstream:
        ap.error("Provide an MCP server command after '--' or --http-upstream URL")
    with open(a.policy, "r", encoding="utf-8") as pf:
        pol = json.load(pf)
    guard = Guard(pol, Audit(a.log), a.interactive, a.ask_timeout, a.pins or a.log + ".pins.json", a.accept_changes)
    if a.http_upstream: serve_http(guard, a.http_upstream, a.listen)
    else: run_stdio(guard, cmd)

if __name__ == "__main__":
    main()
