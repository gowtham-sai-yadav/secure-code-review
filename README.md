# Secure Code Review — Scaler Support Desk

A secure code review of the **Scaler Support Desk** application (a deliberately vulnerable Flask web app),
performed with **Semgrep** (SAST) followed by **manual verification** of every finding.

📄 **Deliverable:** [`Secure_Code_Review_Report_SupportDesk.pdf`](Secure_Code_Review_Report_SupportDesk.pdf)

## Summary

| Metric | Value |
|---|---|
| **Static Analysis Tool Used** | Semgrep v1.168.0 (`--config auto`) |
| **Raw Semgrep findings** | 22 |
| **Total Findings Reported** | **15** |
| **True Positives (genuine vulnerabilities)** | **12** |
| **False Positives** | **3** |

> Semgrep produced 22 raw findings. After de-duplicating overlapping rules and manually verifying each one
> in context, the report documents **15 distinct findings**. Manual review additionally surfaced **5**
> high-impact bugs that Semgrep missed (IDOR, broken access control, path-traversal read, arbitrary file
> upload, stored XSS via `|safe`) — classes of flaw SAST tools typically cannot detect.

## True Positives (12)

| # | Vulnerability | File | Line(s) | CWE |
|---|---|---|---|---|
| 1 | SQL Injection (ticket search) | `models.py` | 117–118 | CWE-89 |
| 2 | Remote Code Execution via `eval()` | `app.py` | 162–164 | CWE-95 |
| 3 | OS Command Injection (ping) | `app.py` | 190–191 | CWE-78 |
| 4 | Stored XSS via `|safe` | `templates/ticket.html` | 35 | CWE-79 |
| 5 | Path Traversal — file read (download) | `app.py` | 120, 123 | CWE-22 |
| 6 | Unrestricted / Arbitrary File Upload | `app.py` | 150–152 | CWE-434 |
| 7 | Broken Access Control (admin reports) | `app.py` | 207–213 | CWE-862 |
| 8 | IDOR — view any ticket | `app.py` | 98–101 | CWE-639 |
| 9 | Weak Password Hashing (unsalted MD5) | `utils.py` | 7, 11 | CWE-916 |
| 10 | Hardcoded Flask `SECRET_KEY` | `app.py` | 20 | CWE-798 |
| 11 | Flask `debug=True` + bind `0.0.0.0` | `app.py` | 220 | CWE-489 |
| 12 | Missing CSRF protection | `templates/ticket.html` | 14, 25, 39 | CWE-352 |

## False Positives (3)

| # | Flagged As | File | Line(s) | Why it's a False Positive |
|---|---|---|---|---|
| 13 | SQL Injection | `models.py` | 135–136 | `status` is whitelisted via `STATUS_COLUMNS` — raw input never reaches the query |
| 14 | Command Injection | `app.py` | 200–203 | `host` is validated by `is_valid_ip()` (literal IP only) before `os.popen` |
| 15 | Path Traversal | `app.py` | 131–134 | `resolve_within()` canonicalizes the path and enforces directory containment |

## Repository Layout

```
.
├── Secure_Code_Review_Report_SupportDesk.pdf   # ← main deliverable
├── report.html                                 # report source (rendered to PDF)
├── semgrep_results.txt / semgrep_results.json  # raw SAST output
├── shots/                                       # screenshots (SAST output + highlighted code)
├── supportdesk-app/                             # the reviewed source code
├── gen_shots.py / gen_report.py                 # tooling used to build screenshots & report
└── Secure Code Review Assignment ... .pdf       # original assignment brief
```

## Reproduce the Scan

```bash
python3 -m venv semgrep-venv
source semgrep-venv/bin/activate
pip install semgrep
cd supportdesk-app
semgrep scan --config auto .
```

---
*Reviewer: Gowtham Sai Yadav · Roll No. 23BCS10168*
