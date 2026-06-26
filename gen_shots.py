#!/usr/bin/env python3
"""Generate report screenshots: highlighted vulnerable code + Semgrep terminal cards."""
import os
from PIL import Image, ImageDraw, ImageFont
from pygments import highlight
from pygments.lexers import PythonLexer, HtmlLexer, get_lexer_by_name
from pygments.formatters import ImageFormatter

BASE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.join(BASE, "supportdesk-app")
OUT = os.path.join(BASE, "shots")
os.makedirs(OUT, exist_ok=True)

MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
MONO_B = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"

# ---------------------------------------------------------------- code shots
def lexer_for(fn):
    if fn.endswith(".py"):
        return PythonLexer()
    if fn.endswith(".html"):
        return HtmlLexer()
    return get_lexer_by_name("text")

def code_shot(out_name, src_file, start, end, hl_abs, title):
    """Render source lines [start,end] (1-based, inclusive) with hl_abs lines highlighted."""
    path = os.path.join(APP, src_file)
    with open(path, encoding="utf-8") as f:
        lines = f.read().split("\n")
    snippet = "\n".join(lines[start - 1:end])
    hl_rel = [a - start + 1 for a in hl_abs]
    fmt = ImageFormatter(
        font_name=MONO,
        font_size=30,
        line_numbers=True,
        line_number_start=start,
        line_number_bg="#161b22",
        line_number_fg="#8b949e",
        line_number_separator=True,
        hl_lines=hl_rel,
        hl_color="#5a1e1e",
        style="github-dark",
        line_pad=6,
        image_pad=18,
    )
    body_png = os.path.join(OUT, "_tmp_code.png")
    with open(body_png, "wb") as f:
        f.write(highlight(snippet, lexer_for(src_file), fmt))
    body = Image.open(body_png).convert("RGB")

    # title bar
    bar_h = 132
    W = max(body.width, 1100)
    canvas = Image.new("RGB", (W, body.height + bar_h), "#0d1117")
    d = ImageDraw.Draw(canvas)
    tf = ImageFont.truetype(MONO_B, 30)
    sf = ImageFont.truetype(MONO, 22)
    # window dots
    for i, c in enumerate(["#ff5f56", "#ffbd2e", "#27c93f"]):
        d.ellipse([24 + i * 34, 26, 48 + i * 34, 50], fill=c)
    d.text((150, 24), src_file, font=tf, fill="#e6edf3")
    d.text((24, 74), title, font=sf, fill="#ff7b72")
    # red marker strip
    d.rectangle([0, bar_h - 6, W, bar_h - 2], fill="#5a1e1e")
    canvas.paste(body, (0, bar_h))
    canvas.save(os.path.join(OUT, out_name))
    print("code  ", out_name, canvas.size)

# ---------------------------------------------------------------- semgrep card
def wrap(text, width):
    words, lines, cur = text.split(), [], ""
    for w in words:
        if len(cur) + len(w) + 1 <= width:
            cur = (cur + " " + w).strip()
        else:
            lines.append(cur); cur = w
    if cur:
        lines.append(cur)
    return lines

def semgrep_card(out_name, file_label, blocks, sev="ERROR"):
    """blocks: list of dicts {rule, msg, url, codelines:[(num,text)]}"""
    W = 1500
    pad = 28
    fr = ImageFont.truetype(MONO, 24)
    fb = ImageFont.truetype(MONO_B, 24)
    fs = ImageFont.truetype(MONO, 21)
    lh = 34
    # measure height
    rows = 3  # header dots + path + blank
    for b in blocks:
        rows += 1  # rule
        rows += 1  # blocking
        rows += len(wrap(b["msg"], 96))
        rows += 1  # details
        rows += 1  # blank
        rows += len(b["codelines"])
        rows += 1  # blank
    H = pad * 2 + 60 + rows * lh
    img = Image.new("RGB", (W, H), "#0d1117")
    d = ImageDraw.Draw(img)
    for i, c in enumerate(["#ff5f56", "#ffbd2e", "#27c93f"]):
        d.ellipse([24 + i * 30, 22, 44 + i * 30, 42], fill=c)
    d.text((150, 20), "Terminal — semgrep scan --config auto", font=fb, fill="#8b949e")
    y = 64
    d.text((pad, y), file_label, font=fb, fill="#58a6ff"); y += lh + 6
    for b in blocks:
        d.text((pad + 14, y), "❯❯❱ " + b["rule"], font=fb, fill="#d29922"); y += lh
        d.text((pad + 50, y), "❰❰ Blocking ❱❱", font=fr, fill="#f85149"); y += lh
        for ln in wrap(b["msg"], 96):
            d.text((pad + 50, y), ln, font=fs, fill="#c9d1d9"); y += lh
        d.text((pad + 50, y), "Details: " + b["url"], font=fs, fill="#6e7681"); y += lh + 6
        for num, txt in b["codelines"]:
            d.text((pad + 50, y), f"{num:>5}┆ ", font=fr, fill="#6e7681")
            d.text((pad + 50 + 9 * 14, y), txt, font=fr, fill="#79c0ff"); y += lh
        y += 10
    img = img.crop((0, 0, W, min(H, y + pad)))
    img.save(os.path.join(OUT, out_name))
    print("semgrep", out_name, img.size)


def text_terminal(out_name, text, title, fg="#c9d1d9", font_size=22):
    """Render plain text to a terminal-style PNG (auto-sized)."""
    f = ImageFont.truetype(MONO, font_size)
    fb = ImageFont.truetype(MONO_B, font_size)
    lines = text.split("\n")
    cw = f.getlength("M")
    lh = font_size + 10
    pad = 28
    W = int(max(900, (max(len(l) for l in lines) + 4) * cw))
    H = pad * 2 + 56 + len(lines) * lh
    img = Image.new("RGB", (W, H), "#0d1117")
    d = ImageDraw.Draw(img)
    for i, c in enumerate(["#ff5f56", "#ffbd2e", "#27c93f"]):
        d.ellipse([24 + i * 30, 22, 44 + i * 30, 42], fill=c)
    d.text((150, 20), title, font=fb, fill="#8b949e")
    y = 64
    for ln in lines:
        col = fg
        if "Findings:" in ln or "Scan completed" in ln or "Code Findings" in ln:
            col = "#3fb950"
        elif ln.strip().startswith("•"):
            col = "#58a6ff"
        elif "❱" in ln or "Blocking" in ln:
            col = "#d29922"
        d.text((pad, y), ln, font=f, fill=col)
        y += lh
    img.save(os.path.join(OUT, out_name))
    print("text  ", out_name, img.size)


if __name__ == "__main__":
    # ---- CODE SHOTS ----
    code_shot("tp01_code.png", "models.py", 115, 120, [117, 118], "SQL Injection - user input concatenated into SQL (search_tickets)")
    code_shot("tp02_code.png", "app.py", 157, 167, [162, 164], "Remote Code Execution - user input passed to eval() (sla_score)")
    code_shot("tp03_code.png", "app.py", 185, 192, [190, 191], "OS Command Injection - host concatenated into os.popen (ping)")
    code_shot("tp04_code.png", "templates/ticket.html", 31, 45, [35], "Stored XSS - comment body rendered with |safe (autoescape bypass)")
    code_shot("tp05_code.png", "app.py", 115, 123, [120, 123], "Path Traversal (read) - filename concatenated into file path (download_attachment)")
    code_shot("tp06_code.png", "app.py", 137, 154, [150, 151, 152], "Arbitrary File Upload - attacker-controlled filename written to disk (upload_attachment)")
    code_shot("tp07_code.png", "app.py", 207, 213, [208, 209, 212], "Broken Access Control - no admin role check (admin_reports)")
    code_shot("tp08_code.png", "app.py", 93, 102, [98, 99, 101], "IDOR - ticket fetched by id with no ownership check (view_ticket)")
    code_shot("tp09_code.png", "utils.py", 6, 15, [7, 11], "Weak Password Hashing - unsalted MD5 (hash_password / verify_password)")
    code_shot("tp10_code.png", "app.py", 19, 25, [20], "Hardcoded Secret - Flask SECRET_KEY committed in source")
    code_shot("tp11_code.png", "app.py", 216, 220, [220], "Debug Mode + Public Bind - debug=True, host=0.0.0.0 in production")
    code_shot("tp12_code.png", "templates/ticket.html", 13, 44, [14, 25, 39], "Missing CSRF Token - state-changing POST forms (escalate/upload/comment)")
    # FPs
    code_shot("fp01_code.png", "models.py", 123, 138, [131, 135], "FALSE POSITIVE: SQLi flagged, but status is whitelisted via STATUS_COLUMNS (tickets_by_status)")
    code_shot("fp02_code.png", "app.py", 195, 204, [201, 203], "FALSE POSITIVE: command-injection flagged, but host validated by is_valid_ip (ping_internal)")
    code_shot("fp03_code.png", "app.py", 126, 134, [131, 132], "FALSE POSITIVE: path-traversal sink, but resolve_within enforces containment (preview_attachment)")
    code_shot("util_resolve_code.png", "utils.py", 18, 31, [18, 26, 29], "Validators that neutralise the false positives: is_valid_ip + resolve_within")

    # ---- SEMGREP CARDS ----
    semgrep_card("tp01_semgrep.png", "models.py", [
        {"rule": "python.sqlalchemy.security.sqlalchemy-execute-raw-query",
         "msg": "Avoiding SQL string concatenation: untrusted input concatenated with raw SQL query can result in SQL Injection. Use a prepared/parameterized statement.",
         "url": "https://sg.run/2b1L", "codelines": [(118, "rows = conn.execute(sql).fetchall()")]},
    ])
    semgrep_card("tp02_semgrep.png", "app.py", [
        {"rule": "python.flask.security.injection.user-eval.eval-injection",
         "msg": "Detected user data flowing into eval. This is code injection and should be avoided.",
         "url": "https://sg.run/5QpX", "codelines": [(164, "score = eval(formula)")]},
        {"rule": "python.lang.security.audit.eval-detected.eval-detected",
         "msg": "Detected the use of eval(). eval() can be dangerous if used to evaluate dynamic content that can be input from outside the program.",
         "url": "https://sg.run/ZvrD", "codelines": [(164, "score = eval(formula)")]},
    ])
    semgrep_card("tp03_semgrep.png", "app.py", [
        {"rule": "python.lang.security.dangerous-system-call.dangerous-system-call",
         "msg": "Found user-controlled data used in a system call. This could allow a malicious actor to execute commands. Use the 'subprocess' module instead.",
         "url": "https://sg.run/k0W7", "codelines": [(191, 'output = os.popen("ping -n 1 " + host).read()')]},
    ])
    semgrep_card("tp09_semgrep.png", "utils.py", [
        {"rule": "python.lang.security.audit.md5-used-as-password.md5-used-as-password",
         "msg": "It looks like MD5 is used as a password hash. MD5 is not considered a secure password hash. Use a suitable password hashing function such as scrypt (hashlib.scrypt).",
         "url": "https://sg.run/5DwD", "codelines": [(7, "return hashlib.md5(password.encode()).hexdigest()")]},
    ])
    semgrep_card("tp10_semgrep.png", "app.py", [
        {"rule": "python.flask.security.audit.hardcoded-config.avoid_hardcoded_config_SECRET_KEY",
         "msg": "Hardcoded variable SECRET_KEY detected. Use environment variables or config files instead.",
         "url": "https://sg.run/Ekde", "codelines": [(20, 'app.config["SECRET_KEY"] = "sd-prod-7f1a9c3e2b"')]},
    ])
    semgrep_card("tp11_semgrep.png", "app.py", [
        {"rule": "python.flask.security.audit.debug-enabled.debug-enabled",
         "msg": "Detected Flask app with debug=True. Do not deploy to production with this flag enabled as it will leak sensitive information and expose the Werkzeug debugger.",
         "url": "https://sg.run/dKrd", "codelines": [(220, 'app.run(debug=True, host="0.0.0.0", port=5050)')]},
        {"rule": "python.flask.security.audit.app-run-param-config.avoid_app_run_with_bad_host",
         "msg": "Running flask app with host 0.0.0.0 could expose the server publicly.",
         "url": "https://sg.run/eLby", "codelines": [(220, 'app.run(debug=True, host="0.0.0.0", port=5050)')]},
    ])
    semgrep_card("tp12_semgrep.png", "templates/ticket.html", [
        {"rule": "python.django.security.django-no-csrf-token.django-no-csrf-token",
         "msg": "Manually-created forms in templates should specify a csrf_token to prevent CSRF attacks. (Also reported on login.html line 8.)",
         "url": "https://sg.run/N0Bp", "codelines": [(14, '<form method="post" action="/tickets/{{ ticket.id }}/escalate">'),
                                                     (25, '<form method="post" action="/tickets/{{ ticket.id }}/upload" ...>'),
                                                     (39, '<form method="post" action="/tickets/{{ ticket.id }}/comment">')]},
    ])
    semgrep_card("fp01_semgrep.png", "models.py", [
        {"rule": "python.lang.security.audit.formatted-sql-query.formatted-sql-query",
         "msg": "Detected possible formatted SQL query. Use parameterized queries instead.",
         "url": "https://sg.run/EkWw", "codelines": [(136, "rows = conn.execute(sql).fetchall()")]},
        {"rule": "python.sqlalchemy.security.sqlalchemy-execute-raw-query",
         "msg": "Avoiding SQL string concatenation: untrusted input concatenated with raw SQL query can result in SQL Injection.",
         "url": "https://sg.run/2b1L", "codelines": [(136, "rows = conn.execute(sql).fetchall()")]},
    ])
    semgrep_card("fp02_semgrep.png", "app.py", [
        {"rule": "python.lang.security.dangerous-system-call.dangerous-system-call",
         "msg": "Found user-controlled data used in a system call. This could allow a malicious actor to execute commands.",
         "url": "https://sg.run/k0W7", "codelines": [(203, 'output = os.popen("ping -n 1 " + host).read()')]},
    ])

    # ---- FULL SCAN SUMMARY (real values from the scan) ----
    summary = (
        "$ semgrep scan --config auto .\n"
        "\n"
        "┌──────────────────┐\n"
        "│ 22 Code Findings │\n"
        "└──────────────────┘\n"
        "\n"
        "  app.py                 14 findings  (SECRET_KEY, eval, os.popen x2, raw-html x6,\n"
        "                                       debug=True, host 0.0.0.0)\n"
        "  models.py               3 findings  (raw SQL concat x1, formatted SQL x2)\n"
        "  utils.py                1 finding   (md5 used as password)\n"
        "  templates/login.html    1 finding   (missing csrf token)\n"
        "  templates/ticket.html   3 findings  (missing csrf token x3)\n"
        "\n"
        "  Language      Rules   Files\n"
        " ───────────────────────────\n"
        "  <multilang>      60      13\n"
        "  html              1       5\n"
        "  python          243       3\n"
        "\n"
        "┌──────────────┐\n"
        "│ Scan Summary │\n"
        "└──────────────┘\n"
        "✅ Scan completed successfully.\n"
        " • Findings: 22 (22 blocking)\n"
        " • Rules run: 304\n"
        " • Targets scanned: 13\n"
        " • Parsed lines: ~98.7%\n"
        "Ran 304 rules on 13 files: 22 findings.\n"
    )
    text_terminal("semgrep_full_scan.png", summary, "Terminal — Semgrep SAST scan (Scaler Support Desk)")
    print("DONE")
