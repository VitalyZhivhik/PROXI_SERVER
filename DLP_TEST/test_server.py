"""
DLP Test Server — HTTP file exchange for testing DLP in closed network.

Traffic flow:
  VM browser --[HTTP via proxy]--> mitmproxy:8080 --[HTTP]--> this server:9090
  mitmproxy intercepts, analyzes with DLP rules, blocks or passes.

Run:    python test_server.py
Access: http://SERVER_IP:9090 (from VM through DLP proxy)

No HTTPS needed — DLP proxy intercepts all traffic.
"""

import os
import json
import socket
from pathlib import Path
from datetime import datetime

from flask import (
    Flask, request, render_template_string, redirect,
    url_for, send_from_directory, jsonify,
)

HOST = "0.0.0.0"
PORT = 9090
UPLOAD_DIR = Path("test_uploads")
UPLOAD_DIR.mkdir(exist_ok=True)
SAMPLES_DIR = Path("test_samples")

app = Flask(__name__)
app.secret_key = "dlp-test-key"
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024

_events: list[dict] = []

def _log_event(action, ip, details=""):
    _events.insert(0, {"time": datetime.now().strftime("%H:%M:%S"),
                        "action": action, "ip": ip, "details": details[:200]})
    if len(_events) > 200: _events.pop()

def _get_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80)); ip = s.getsockname()[0]; s.close()
        return ip
    except: return "127.0.0.1"

# ── Test files ────────────────────────────────────────────────────────────────
def _create_test_files():
    SAMPLES_DIR.mkdir(exist_ok=True)
    files = {
        "clean_report.txt": (
            "Quarterly Report Q1 2026\n\n"
            "Revenue: 12.5M RUB\nExpenses: 8.3M RUB\nProfit: 4.2M RUB\n\n"
            "This file has NO confidential data. DLP should PASS it.\n"
        ),
        "confidential_personal.txt": (
            "STAFF LIST - FOR OFFICIAL USE ONLY\n"
            "Dlya sluzhebnogo polzovaniya\n\n"
            "1. Ivanov Petr Sergeevich\n"
            "   Passport: 4512 345678\n"
            "   SNILS: 123-456-789 01\n"
            "   Phone: +7 (903) 123-45-67\n"
            "   INN: 7707083893\n\n"
            "2. Kozlova Maria Andreevna\n"
            "   Passport: 4510 987654\n"
            "   SNILS: 987-654-321 09\n"
            "   Email: kozlova@company.ru\n"
            "   Phone: +7 (916) 765-43-21\n\n"
            "WARNING: Contains personal data!\n"
            "DLP system MUST BLOCK upload of this file.\n"
        ),
        "payment_data.txt": (
            "Payment Details\n\n"
            "Recipient: OOO Test Company\n"
            "INN: 7707083893\n"
            "Account: 40702810938000012345\n"
            "Bank: PAO Sberbank\n"
            "BIK: 044525225\n"
            "Card: 4276 3800 1234 5678\n"
        ),
        "dsp_document.txt": (
            "APPROVED\nGeneral Director _________\n\n"
            "СОВЕРШЕННО СЕКРЕТНО\nЭкземпляр единственный\n\n"
            "ORDER #42\nOn information security measures\n\n"
            "Для служебного пользования\n"
        ),
        "mixed_data.txt": (
            "Meeting Protocol 15.03.2026\n\n"
            "Participants:\n"
            "- Sidorov Alexey Vladimirovich (director)\n"
            "- Petrova Olga Nikolaevna (accountant)\n\n"
            "Decision: approve the budget.\n"
            "Contact Petrova: +7 (495) 111-22-33, petrova@company.ru\n"
        ),
    }
    for name, content in files.items():
        p = SAMPLES_DIR / name
        if not p.exists():
            p.write_text(content, encoding="utf-8")
    print(f"[Samples] {len(files)} test files in {SAMPLES_DIR}/")

# ── HTML Template ─────────────────────────────────────────────────────────────
STYLE = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0a0e17;color:#e0e6f0;min-height:100vh}
.nav{background:#0f1623;border-bottom:1px solid #2a3050;padding:14px 24px;display:flex;align-items:center;gap:20px;flex-wrap:wrap}
.nav .logo{color:#6cb4ee;font-weight:700;font-size:1.1em}
.nav a{color:#7a8599;font-size:.9em;text-decoration:none;padding:6px 14px;border-radius:6px}
.nav a:hover{color:#e0e6f0;background:rgba(108,180,238,.1)}
.nav a.act{color:#6cb4ee;background:rgba(108,180,238,.15)}
.c{max-width:1000px;margin:0 auto;padding:24px}
h2{color:#6cb4ee;margin-bottom:16px}
.card{background:#111827;border:1px solid #1e2740;border-radius:12px;padding:24px;margin-bottom:20px}
.card h3{color:#6cb4ee;margin-bottom:12px}
.row{margin-bottom:14px}
.row label{display:block;color:#7a8599;font-size:.88em;margin-bottom:6px}
input[type=text],input[type=file],textarea,select{background:#0a0e17;border:1px solid #2a3050;border-radius:8px;padding:10px 14px;color:#e0e6f0;font-size:14px;width:100%}
textarea{resize:vertical;min-height:100px}
.btn{display:inline-block;padding:10px 22px;border-radius:8px;font-size:.95em;border:1px solid transparent;cursor:pointer;font-weight:600;text-decoration:none}
.btn-p{background:#1d4ed8;color:#fff;border-color:#3b82f6}
.btn-s{background:#15803d;color:#fff;border-color:#22c55e}
.btn-d{background:#7f1d1d;color:#fca5a5;border-color:#991b1b}
table{width:100%;border-collapse:collapse}
th{background:#151c2c;color:#6cb4ee;padding:10px 14px;text-align:left;font-size:.82em;text-transform:uppercase}
td{padding:10px 14px;border-bottom:1px solid #1e2740;font-size:.9em}
code{background:#151c2c;border:1px solid #2a3050;padding:2px 8px;border-radius:4px;color:#7dd3fc;font-size:.88em}
.badge{display:inline-block;padding:3px 10px;border-radius:10px;font-size:.78em;font-weight:600}
.b-ok{background:#052e16;color:#4ade80;border:1px solid #166534}
.b-err{background:#450a0a;color:#fca5a5;border:1px solid #991b1b}
.b-w{background:#422006;color:#fbbf24;border:1px solid #92400e}
.alert{padding:12px 18px;border-radius:8px;margin-bottom:16px;font-size:.9em}
.a-info{background:#0c1929;color:#7dd3fc;border:1px solid #1e3a5f}
.a-ok{background:#052e16;color:#4ade80;border:1px solid #166534}
.fc{display:flex;align-items:center;gap:12px;padding:12px 16px;background:#0d1220;border:1px solid #1e2740;border-radius:8px;margin-bottom:8px}
.fc:hover{border-color:#6cb4ee}
.foot{color:#3a4555;font-size:.8em;text-align:center;padding:24px 0}
"""

def _nav(act=""):
    links = [("/","home","Home"),("/upload","upload","Upload"),
             ("/download","download","Download"),("/text","text","Text"),
             ("/api-test","api","API"),("/log","log","Log")]
    items = "".join(f'<a href="{h}" class="{"act" if act==k else ""}">{l}</a>' for h,k,l in links)
    return f'<nav class="nav"><span class="logo">DLP Test Server</span>{items}</nav>'

def _page(title, act, body):
    return f"""<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8">
<title>{title}</title><style>{STYLE}</style></head>
<body>{_nav(act)}<div class="c">{body}</div>
<div class="foot">DLP Test Server HTTP | {_get_ip()}:{PORT}</div></body></html>"""

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    ip = _get_ip()
    body = f"""
<h2>DLP Test Server</h2>
<p style="color:#7a8599;margin-bottom:20px">HTTP file exchange — all traffic goes through DLP proxy</p>
<div class="alert a-info">
  Server: <code>{ip}:{PORT}</code> | Open <code>http://{ip}:{PORT}</code> from VM browser (through DLP proxy)
</div>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
  <div class="card"><h3>Upload Files</h3>
    <p style="color:#7a8599;margin-bottom:12px">Upload a file — DLP will analyze content and block if confidential.</p>
    <a href="/upload" class="btn btn-p">Upload</a></div>
  <div class="card"><h3>Download Files</h3>
    <p style="color:#7a8599;margin-bottom:12px">Download test files with various confidential data levels.</p>
    <a href="/download" class="btn btn-s">Download</a></div>
  <div class="card"><h3>Send Text</h3>
    <p style="color:#7a8599;margin-bottom:12px">Submit text via form — DLP checks POST body for PII.</p>
    <a href="/text" class="btn btn-p">Send Text</a></div>
  <div class="card"><h3>API Test</h3>
    <p style="color:#7a8599;margin-bottom:12px">Send JSON via API — test DLP analysis of JSON POST.</p>
    <a href="/api-test" class="btn btn-p">API Test</a></div>
</div>
<div class="card" style="margin-top:8px"><h3>Test Scenarios</h3>
<table><thead><tr><th>Scenario</th><th>Action</th><th>Expected DLP</th></tr></thead><tbody>
<tr><td><span class="badge b-ok">Clean</span></td><td>Upload <code>clean_report.txt</code></td><td>PASS</td></tr>
<tr><td><span class="badge b-err">Personal Data</span></td><td>Upload <code>confidential_personal.txt</code></td><td>BLOCK (FIO+passport+SNILS+phone)</td></tr>
<tr><td><span class="badge b-err">Payment</span></td><td>Upload <code>payment_data.txt</code></td><td>BLOCK (INN+card+account)</td></tr>
<tr><td><span class="badge b-err">DSP</span></td><td>Upload <code>dsp_document.txt</code></td><td>BLOCK (secret classification)</td></tr>
<tr><td><span class="badge b-w">Mixed</span></td><td>Upload <code>mixed_data.txt</code></td><td>Depends on score</td></tr>
<tr><td><span class="badge b-err">Text form</span></td><td>Enter: INN 7707083893, passport 4512 345678</td><td>BLOCK</td></tr>
</tbody></table></div>"""
    return _page("Home", "home", body)


@app.route("/upload", methods=["GET", "POST"])
def upload():
    msg = ""
    if request.method == "POST":
        f = request.files.get("file")
        comment = request.form.get("comment", "")
        if f and f.filename:
            safe = f"{datetime.now().strftime('%H%M%S')}_{f.filename}"
            f.save(str(UPLOAD_DIR / safe))
            sz = (UPLOAD_DIR / safe).stat().st_size
            _log_event("upload", request.remote_addr, f"{f.filename} ({sz}B)")
            msg = f'<div class="alert a-ok">File "{f.filename}" uploaded ({sz} bytes)</div>'
        else:
            msg = '<div class="alert" style="background:#450a0a;color:#fca5a5;border:1px solid #991b1b">No file selected</div>'

    files_html = ""
    for p in sorted(UPLOAD_DIR.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
        if p.is_file():
            sz = p.stat().st_size
            files_html += f"<tr><td><code>{p.name}</code></td><td>{sz//1024}KB</td><td>{datetime.fromtimestamp(p.stat().st_mtime).strftime('%H:%M:%S')}</td></tr>"

    body = f"""
<h2>Upload Files</h2>{msg}
<div class="card"><h3>Upload a file</h3>
<p style="color:#7a8599;margin-bottom:16px">File sent via HTTP POST multipart. DLP proxy intercepts and analyzes.</p>
<form method="POST" enctype="multipart/form-data">
  <div class="row"><label>File:</label><input type="file" name="file" required></div>
  <div class="row"><label>Comment:</label><input type="text" name="comment" placeholder="optional"></div>
  <button type="submit" class="btn btn-p">Upload</button>
</form></div>
<div class="card"><h3>Uploaded Files</h3>
{'<table><thead><tr><th>File</th><th>Size</th><th>Time</th></tr></thead><tbody>'+files_html+'</tbody></table>' if files_html else '<p style="color:#7a8599">No files yet</p>'}
</div>"""
    return _page("Upload", "upload", body)


@app.route("/download")
def download_list():
    descs = {
        "clean_report.txt": ("Clean report — no PII", "b-ok", "SAFE"),
        "confidential_personal.txt": ("FIO+passport+SNILS+phone", "b-err", "PII"),
        "payment_data.txt": ("INN+card+account", "b-err", "PAYMENT"),
        "mixed_data.txt": ("FIO+phone+email (borderline)", "b-w", "MIXED"),
        "dsp_document.txt": ("Secret classification + DSP", "b-err", "DSP"),
    }
    cards = ""
    for p in sorted(SAMPLES_DIR.iterdir()):
        if p.is_file():
            d, bc, bl = descs.get(p.name, ("Test file","b-ok","FILE"))
            cards += f'''<div class="fc"><div style="font-size:1.6em">📄</div>
<div style="flex:1"><div style="font-weight:600">{p.name}</div>
<div style="color:#7a8599;font-size:.82em">{d} — {p.stat().st_size//1024}KB</div></div>
<span class="badge {bc}">{bl}</span>
<a href="/download/{p.name}" class="btn btn-s" style="font-size:.85em;padding:6px 14px">Download</a></div>'''
    body = f"""<h2>Download Test Files</h2>
<div class="alert a-info">Download files here, then upload them back through <a href="/upload" style="color:#7dd3fc">Upload</a> — DLP will analyze.</div>
{cards}"""
    return _page("Download", "download", body)


@app.route("/download/<fn>")
def download_file(fn):
    _log_event("download", request.remote_addr, fn)
    return send_from_directory(str(SAMPLES_DIR.resolve()), fn, as_attachment=True)


@app.route("/text", methods=["GET", "POST"])
def text_form():
    msg = ""
    if request.method == "POST":
        subj = request.form.get("subject", "")
        body_text = request.form.get("body", "")
        _log_event("text", request.remote_addr, f"{subj[:50]} | {len(body_text)}ch")
        msg = f'<div class="alert a-ok">Text submitted ({len(body_text)} chars)</div>'

    body = f"""<h2>Send Text</h2>{msg}
<div class="card"><h3>Submit text data</h3>
<p style="color:#7a8599;margin-bottom:16px">Text sent via HTTP POST. DLP checks body for PII/DSP.</p>
<form method="POST">
  <div class="row"><label>Subject:</label><input type="text" name="subject" placeholder="e.g. Leave request"></div>
  <div class="row"><label>Text:</label><textarea name="body" rows="8" placeholder="Enter text...&#10;&#10;Try: INN 7707083893, passport 4512 345678&#10;Or: Для служебного пользования"></textarea></div>
  <button type="submit" class="btn btn-p">Submit</button>
</form></div>
<div class="card"><h3>Quick Tests</h3>
<p style="color:#7a8599;margin-bottom:12px">Click to fill test data:</p>
<div style="display:flex;gap:8px;flex-wrap:wrap">
<button class="btn btn-d" style="font-size:.82em" onclick="document.querySelector('[name=body]').value='Ivanov Petr Sergeevich\\nPassport: 4512 345678\\nSNILS: 123-456-789 01\\nPhone: +7 (903) 123-45-67'">PII (FIO+passport+SNILS)</button>
<button class="btn btn-d" style="font-size:.82em" onclick="document.querySelector('[name=body]').value='INN 7707083893\\nCard: 4276 3800 1234 5678\\nAccount: 40702810938000012345'">Payment data</button>
<button class="btn btn-d" style="font-size:.82em" onclick="document.querySelector('[name=body]').value='СОВЕРШЕННО СЕКРЕТНО\\nДля служебного пользования\\nOrder on reorganization...'">DSP classification</button>
<button class="btn" style="font-size:.82em;background:#1e2740;color:#7a8599" onclick="document.querySelector('[name=body]').value='Hello!\\nQ1 report is ready.\\nRevenue: 12.5M RUB.'">Clean text</button>
</div></div>"""
    return _page("Text", "text", body)


@app.route("/api-test")
def api_test():
    body = """<h2>API Test</h2>
<div class="card"><h3>Send JSON via API</h3>
<p style="color:#7a8599;margin-bottom:16px">POST JSON to <code>/api/submit</code>. DLP analyzes body.</p>
<div class="row"><label>JSON:</label>
<textarea id="jd" rows="8" style="font-family:monospace;font-size:13px">{
  "type": "employee_data",
  "name": "Kozlov Dmitry Sergeevich",
  "passport": "4510 123456",
  "phone": "+7 (916) 555-44-33",
  "inn": "7707083893"
}</textarea></div>
<button class="btn btn-p" onclick="sendApi()">Send POST</button>
<div id="res" style="margin-top:16px"></div></div>
<script>
async function sendApi(){
  const d=document.getElementById('res');
  d.innerHTML='<div class="alert a-info">Sending...</div>';
  try{
    const r=await fetch('/api/submit',{method:'POST',headers:{'Content-Type':'application/json'},body:document.getElementById('jd').value});
    const j=await r.json();
    d.innerHTML='<div class="alert '+(r.ok?'a-ok':'')+'">HTTP '+r.status+'<pre style="margin-top:8px">'+JSON.stringify(j,null,2)+'</pre></div>';
  }catch(e){d.innerHTML='<div class="alert" style="background:#450a0a;color:#fca5a5">Error: '+e+'</div>';}
}
</script>"""
    return _page("API", "api", body)


@app.route("/api/submit", methods=["POST"])
def api_submit():
    try: data = request.get_json(force=True)
    except: data = request.form.to_dict()
    _log_event("api", request.remote_addr, f"keys: {list(data.keys()) if isinstance(data,dict) else '?'}")
    return jsonify({"ok": True, "keys": list(data.keys()) if isinstance(data,dict) else [],
                     "size": len(json.dumps(data, default=str)), "time": datetime.now().isoformat()})


@app.route("/api/info")
def api_info():
    return jsonify({"server": "DLP Test", "ip": _get_ip(), "port": PORT,
                     "uploads": len(list(UPLOAD_DIR.iterdir())), "events": len(_events)})


@app.route("/log")
def log_page():
    rows = ""
    for e in _events[:100]:
        bc = {"upload":"b-w","download":"b-ok","text":"b-w","api":"b-w"}.get(e["action"],"b-ok")
        rows += f'<tr><td>{e["time"]}</td><td><span class="badge {bc}">{e["action"]}</span></td><td><code>{e["ip"]}</code></td><td style="color:#7a8599">{e["details"]}</td></tr>'
    body = f"""<h2>Event Log</h2>
<div class="card">{'<table><thead><tr><th>Time</th><th>Action</th><th>Client IP</th><th>Details</th></tr></thead><tbody>'+rows+'</tbody></table>' if rows else '<p style="color:#7a8599">No events yet</p>'}</div>"""
    return _page("Log", "log", body)


# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    ip = _get_ip()
    print("=" * 55)
    print("  DLP Test Server — HTTP")
    print("=" * 55)
    _create_test_files()
    print()
    print(f"  Address:  http://{ip}:{PORT}")
    print(f"  Uploads:  {UPLOAD_DIR.resolve()}")
    print(f"  Samples:  {SAMPLES_DIR.resolve()}")
    print()
    print(f"  On VM open: http://{ip}:{PORT}")
    print(f"  Traffic goes through DLP proxy on port 8080")
    print()
    print("  Ctrl+C to stop")
    print("=" * 55)
    app.run(host=HOST, port=PORT, debug=False, threaded=True)
