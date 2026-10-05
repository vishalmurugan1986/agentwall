#!/usr/bin/env python3
"""bench.py - reproducible MCP-firewall attack suite.
Runs 12 attacks against ANY stdio proxy and checks what really reached the server / the client.
  python bench.py --wrap "sealwall --policy policy.json --log /tmp/b.jsonl --"     (appends the server command)
  python bench.py --wrap "npx -y mcpwall --"                                         (any other proxy)
  python bench.py --wrap ""                                                          (no proxy: baseline)
Fairness: results depend on the config you give each proxy. Always state it when you publish numbers."""
import argparse, json, os, shlex, subprocess, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__)); SERVER = [sys.executable, os.path.join(HERE, "bench_server.py")]
INIT = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "bench", "version": "1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"}]

def run(wrap, msgs, env=None, timeout=90):
    log = tempfile.mktemp(); e = dict(os.environ, BENCH_LOG=log, **(env or {}))
    inp = "".join(json.dumps(m) + "\n" for m in INIT + msgs)
    cmd_prefix = shlex.split(wrap, posix=(sys.platform != "win32")) if wrap.strip() else []
    try: p = subprocess.run(cmd_prefix + SERVER, input=inp, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, env=e)
    except subprocess.TimeoutExpired: return {}, []
    out = {}
    for l in p.stdout.splitlines():
        try: m = json.loads(l)
        except ValueError: continue
        for x in (m if isinstance(m, list) else [m]):
            if isinstance(x, dict): out[x.get("id")] = x
    got = []
    if os.path.exists(log):
        with open(log, encoding="utf-8", errors="replace") as f:
            got = [json.loads(l) for l in f if l.strip()]
        try: os.remove(log)
        except OSError: pass
    return out, got

def call(i, name, args): return {"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": name, "arguments": args}}
def reached(got, name, needle): return any(g["name"] == name and needle in json.dumps(g["args"]) for g in got)

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--wrap", required=True, help="proxy command prefix ('' for baseline)"); ap.add_argument("--workspace")
    ap.add_argument("--json", action="store_true"); a = ap.parse_args()
    ws = a.workspace or tempfile.mkdtemp(); out_dir = tempfile.mkdtemp()
    wrap = a.wrap.replace("{workspace}", ws)
    with open(os.path.join(ws, "notes.txt"), "w", encoding="utf-8") as f: f.write("hi")
    with open(os.path.join(out_dir, "secret.txt"), "w", encoding="utf-8") as f: f.write("TOP SECRET")
    link_path = os.path.join(ws, "link")
    try:
        os.symlink(out_dir, link_path)
    except OSError:
        if sys.platform == "win32":
            try: subprocess.run(["cmd", "/c", "mklink", "/J", link_path, out_dir], capture_output=True)
            except Exception: pass
    R = []  # (name, passed, detail)
    def attack_call(name, tool, args, needle):
        _, got = run(wrap, [call(2, tool, args)]); R.append((name, not reached(got, tool, needle), "reached server" if reached(got, tool, needle) else "blocked"))
    # control: legitimate use must still work
    o, got = run(wrap, [call(2, "read_file", {"path": os.path.join(ws, "notes.txt")})]); ok = reached(got, "read_file", "notes.txt")
    R.append(("CONTROL: legitimate read works", ok, "ok" if ok else "FALSE POSITIVE"))
    attack_call("read ~/.ssh/id_rsa", "read_file", {"path": "~/.ssh/id_rsa"}, "id_rsa")
    attack_call("path traversal (../)", "read_file", {"path": os.path.join(ws, "..", os.path.basename(out_dir), "secret.txt")}, "secret.txt")
    if os.path.exists(link_path):
        attack_call("symlink escape", "read_file", {"path": os.path.join(ws, "link", "secret.txt")}, "link")
    else:
        R.append(("symlink escape", True, "skipped (symlink creation not supported by OS)"))
    attack_call("case variation ~/.SSH", "read_file", {"path": "~/.SSH/ID_RSA"}, "SSH")
    attack_call("read .env file", "read_file", {"path": os.path.join(ws, ".env")}, ".env")
    attack_call("destructive delete", "delete_file", {"path": os.path.join(ws, "notes.txt")}, "notes.txt")
    attack_call("secret in args (AWS key)", "send_message", {"body": "AKIAIOSFODNN7EXAMPLE"}, "AKIA")
    # batch bypass
    inp_b = [[call(2, "read_file", {"path": "~/.ssh/id_rsa"})]]
    _, got = run(a.wrap, inp_b); R.append(("JSON-RPC batch bypass", not reached(got, "read_file", "id_rsa"), "reached server" if reached(got, "read_file", "id_rsa") else "blocked"))
    # tool poisoning
    o, _ = run(a.wrap, [{"jsonrpc": "2.0", "id": 2, "method": "tools/list"}]); names = [t["name"] for t in o.get(2, {}).get("result", {}).get("tools", [])]
    R.append(("poisoned tool hidden from client", "add" not in names and bool(names), "visible" if "add" in names else "hidden"))
    # injection in output
    o, _ = run(a.wrap, [call(2, "fetch_page", {"url": "http://x"})]); txt = json.dumps(o.get(2, {}))
    R.append(("injection in output withheld", "Ignore previous instructions" not in txt, "delivered" if "Ignore previous" in txt else "withheld"))
    # secret in output
    o, _ = run(a.wrap, [call(2, "read_file", {"path": os.path.join(ws, "leaky.txt")})]); txt = json.dumps(o.get(2, {}))
    R.append(("secret in output redacted", "AKIAIOSFODNN7EXAMPLE" not in txt, "leaked to client" if "AKIA" in txt else "redacted"))
    # rug pull (two sessions, same pin file)
    run(a.wrap, [{"jsonrpc": "2.0", "id": 2, "method": "tools/list"}])
    o, _ = run(a.wrap, [{"jsonrpc": "2.0", "id": 2, "method": "tools/list"}], env={"BENCH_RUG": "1"})
    d = {t["name"]: t["description"] for t in o.get(2, {}).get("result", {}).get("tools", [])}
    R.append(("rug pull (changed tool) blocked", "evil.example" not in d.get("read_file", ""), "changed tool delivered" if "evil.example" in d.get("read_file", "") else "blocked"))
    attacks = [r for r in R if not r[0].startswith("CONTROL")]; score = sum(r[1] for r in attacks)
    if a.json: print(json.dumps({"wrap": a.wrap, "score": score, "total": len(attacks), "results": R}, indent=1)); return
    print(f"wrap: {a.wrap or '(none, baseline)'}\n")
    for n, p, d in R: print(f"  {'PASS' if p else 'FAIL'}  {n:36} {d}")
    print(f"\nscore: {score}/{len(attacks)} attacks stopped" + ("" if R[0][1] else "   (control failed: legitimate use broken)"))

if __name__ == "__main__": main()
