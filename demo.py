"""sealwall demo: poisoned tool removed, path allowlist, injection withheld, tamper detection."""
import subprocess, json, os, sys, tempfile
here = os.path.dirname(os.path.abspath(__file__))
tmp = tempfile.mkdtemp(); work = os.path.join(tmp, "work"); os.makedirs(work)
pol = {"default": "deny", "allow_paths": [work], "deny_args": [r"\.ssh", r"\.env"],
       "rules": [{"tool": "read_*", "action": "allow"}, {"tool": "fetch_*", "action": "allow"}, {"tool": "add", "action": "allow"},
                 {"tool": "send_*", "action": "ask", "reason": "outbound communication"}, {"tool": "delete_*", "action": "deny", "reason": "destructive action"}]}
pp, log = os.path.join(tmp, "policy.json"), os.path.join(tmp, "audit.jsonl")
json.dump(pol, open(pp, "w"))
aw = [sys.executable, os.path.join(here, "sealwall.py")]
def session(msgs):
    inp = "".join(json.dumps(m) + "\n" for m in msgs)
    p = subprocess.run(
        aw + ["--policy", pp, "--log", log, "--", sys.executable, os.path.join(here, "demo_server.py")],
        input=inp,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return {json.loads(l)["id"]: json.loads(l) for l in p.stdout.splitlines() if l.strip()}
call = lambda i, n, a: {"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": n, "arguments": a}}
print("[1] Agent asks the server which tools exist", flush=True)
r = session([{"jsonrpc": "2.0", "id": 0, "method": "tools/list"}])[0]
print("    server offers 2 tools: read_file, add (poisoned)", flush=True)
print("    sealwall passes on:", [t["name"] for t in r["result"]["tools"]], "<- 'add' removed (hidden instructions)\n", flush=True)
calls = [("read_file", {"path": os.path.join(work, "notes.txt")}), ("read_file", {"path": os.path.join(work, "..", "secret.txt")}),
         ("read_file", {"path": "~/.ssh/id_rsa"}), ("delete_file", {"path": os.path.join(work, "notes.txt")}), ("send_email", {"to": "a@b.com"}), ("fetch_page", {"url": "http://x.com"})]
print("[2] Agent calls tools", flush=True)
res = session([call(i + 1, n, a) for i, (n, a) in enumerate(calls)])
for i, (n, a) in enumerate(calls):
    x = res[i + 1]; msg = (x.get("error") or {}).get("message") or x["result"]["content"][0]["text"]
    print(f"    {n:12} -> {msg.replace(work, '<work>')[:78]}", flush=True)
print("\n[3] Verifying hash chain integrity", flush=True)
subprocess.run(aw + ["verify", log])
print("\n[4] Simulating log tampering (edit one decision)", flush=True)
with open(log, "r", encoding="utf-8") as f:
    txt = f.read().replace('"deny"', '"allow"', 1)
with open(log, "w", encoding="utf-8") as f:
    f.write(txt)
subprocess.run(aw + ["verify", log])
