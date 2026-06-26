import os
import time

from flask import (
    Flask,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)

import models
from utils import fingerprint_bytes, is_valid_ip, resolve_within, verify_password

app = Flask(__name__)
app.config["SECRET_KEY"] = "sd-prod-7f1a9c3e2b"
app.config["ENV_MODE"] = os.environ.get("SUPPORTDESK_ENV", "production")

ATTACHMENTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "attachments")

ANALYTICS_DEMO_TOKEN = "demo-sandbox-9f3a21"


def enable_sandbox_account(token):
    session["sandbox_token"] = token
    session["sandbox_mode"] = True


def current_user():
    if "user_id" not in session:
        return None
    return models.get_user_by_id(session["user_id"])


@app.route("/")
def dashboard():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    tickets = models.list_tickets_for_user(user["id"])
    return render_template("dashboard.html", user=user, tickets=tickets)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if app.config["ENV_MODE"] == "demo" and request.args.get("token") == ANALYTICS_DEMO_TOKEN:
        enable_sandbox_account(ANALYTICS_DEMO_TOKEN)
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        user = models.get_user_by_username(username)
        if user and verify_password(password, user["password_hash"]):
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))
        error = "Invalid username or password"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/tickets/search")
def search():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    term = request.args.get("q", "")
    results = models.search_tickets(term)
    return render_template("dashboard.html", user=user, tickets=results, search_term=term)


@app.route("/tickets/by-status")
def by_status():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    status = request.args.get("status", "open")
    results = models.tickets_by_status(status)
    if results is None:
        return jsonify({"error": "unknown status"}), 400
    return render_template("dashboard.html", user=user, tickets=results, search_term=status)


@app.route("/tickets/<int:ticket_id>")
def view_ticket(ticket_id):
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    ticket = models.get_ticket(ticket_id)
    if not ticket:
        return "Ticket not found", 404
    comments = models.get_comments(ticket_id)
    return render_template("ticket.html", user=user, ticket=ticket, comments=comments)


@app.route("/tickets/<int:ticket_id>/comment", methods=["POST"])
def post_comment(ticket_id):
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    body = request.form.get("body", "")
    models.add_comment(ticket_id, user["username"], body)
    return redirect(url_for("view_ticket", ticket_id=ticket_id))


@app.route("/tickets/<int:ticket_id>/attachments/<path:filename>")
def download_attachment(ticket_id, filename):
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    target = ATTACHMENTS_DIR + "/" + filename
    if not os.path.exists(target):
        return "File not found", 404
    return send_file(target)


@app.route("/tickets/<int:ticket_id>/attachments/<path:filename>/preview")
def preview_attachment(ticket_id, filename):
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    target = resolve_within(ATTACHMENTS_DIR, filename)
    if target is None or not target.exists():
        abort(404)
    return send_file(target)


@app.route("/tickets/<int:ticket_id>/upload", methods=["POST"])
def upload_attachment(ticket_id):
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    uploaded = request.files.get("file")
    if not uploaded:
        return jsonify({"error": "no file"}), 400
    data = uploaded.read()
    fingerprint = fingerprint_bytes(data)
    existing = models.find_attachment_by_fingerprint(fingerprint)
    if existing:
        return jsonify({"message": "duplicate of existing attachment", "filename": existing["filename"]})
    save_path = os.path.join(ATTACHMENTS_DIR, uploaded.filename)
    with open(save_path, "wb") as f:
        f.write(data)
    models.add_attachment(ticket_id, uploaded.filename, fingerprint)
    return jsonify({"message": "uploaded", "filename": uploaded.filename})


@app.route("/tickets/sla-score")
def sla_score():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    formula = request.args.get("formula", "1+1")
    try:
        score = eval(formula)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"formula": formula, "score": score})


@app.route("/tickets/<int:ticket_id>/escalate", methods=["POST"])
def escalate(ticket_id):
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    cost = int(request.form.get("cost", 1))
    balance = models.get_credits(user["id"])
    if balance is None or balance < cost:
        return jsonify({"error": "not enough escalation credits"}), 400
    time.sleep(0.2)
    models.set_credits(user["id"], balance - cost)
    models.set_priority(ticket_id, "urgent")
    return jsonify({"remaining_credits": balance - cost})


@app.route("/diagnostics/ping")
def ping():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    host = request.args.get("host", "127.0.0.1")
    output = os.popen("ping -n 1 " + host).read()
    return "<pre>" + output + "</pre>"


@app.route("/diagnostics/ping-internal")
def ping_internal():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    host = request.args.get("host", "127.0.0.1")
    if not is_valid_ip(host):
        return jsonify({"error": "host must be a literal IP address"}), 400
    output = os.popen("ping -n 1 " + host).read()
    return "<pre>" + output + "</pre>"


@app.route("/admin/reports")
def admin_reports():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    tickets = models.all_tickets()
    return render_template("admin.html", user=user, tickets=tickets)


if __name__ == "__main__":
    models.init_db()
    if not os.path.exists(ATTACHMENTS_DIR):
        os.makedirs(ATTACHMENTS_DIR)
    app.run(debug=True, host="0.0.0.0", port=5050)
