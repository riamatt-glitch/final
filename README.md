# Risk-Based Vulnerability Assessment and Management System (RBVMS)

BSc (Hons) Network Security and Computer Forensics — final-year project artefact, Riana Matengu (2231147).

RBVMS ranks vulnerabilities by **organisational risk**, not just CVSS severity. It imports real CVE records
from the **National Vulnerability Database (NVD) API 2.0**, matches them to an asset inventory, and calculates a
**Smart Priority Score (0–100)** for each vulnerability on each asset. Security administrators use a web dashboard
to prioritise, assign and track remediation.

Technology stack (Section 1.11): Python 3.12 · Django 5 · MySQL 8.0 (SQLite fallback) · Bootstrap 5 · Chart.js · NVD REST API 2.0 · pytest-django.

---

## Quick start (Windows)

The tools are already installed on this machine (Python 3.12, Git, MySQL 8.0, VS Code) and the virtual
environment `venv\` contains every package. To start the system:

```bash
venv\Scripts\python.exe manage.py runserver
```

Then open http://127.0.0.1:8000 and sign in as **j.ncube** (Administrator) or **t.moyo** (Security Analyst).
The demo password is set by `DEMO_PASSWORD` in `.env`. The default value is in `.env.example`.

### Set up from scratch (another computer)

```bash
python -m venv venv
venv\Scripts\pip install -r requirements.txt
copy .env.example .env
venv\Scripts\python manage.py migrate
venv\Scripts\python manage.py seed_demo
venv\Scripts\python manage.py createsuperuser
venv\Scripts\python manage.py runserver
```

### Database: MySQL 8.0

On this computer the system already uses **MySQL 8.0.45**. It runs as the Windows service `MySQL80` on
`127.0.0.1:3306` and starts automatically with Windows. The `rbvms` database and user already exist. Both
passwords were randomly generated and are stored only in `.env`, which Git ignores:

- `DB_PASSWORD` is the app's `rbvms` account.
- `MYSQL_ROOT_PASSWORD` is the MySQL administrator account. Use it for MySQL Workbench.

To set up MySQL on another computer:

1. Install MySQL 8.0. Edit the password in `setup_mysql.sql`, then run that file as root in MySQL Workbench.
2. In `.env`, set `DB_ENGINE=mysql` and `DB_PASSWORD=<the password you chose>`.
3. Run `venv\Scripts\python manage.py migrate` and `venv\Scripts\python manage.py seed_demo`.

To run without MySQL, set `DB_ENGINE=sqlite` in `.env`.

---

## Features → requirements (Section 2.4)

| Requirement | Where |
|---|---|
| FR1 Secure login before any data access | Django auth; every view is `login_required`; `admin_required` for admin-only actions |
| FR2 Import CVEs from the NVD (on demand or scheduled) | *Vulnerabilities → Import from NVD*; `manage.py import_nvd` (schedule with Task Scheduler) |
| FR3 Asset inventory with criticality | *Assets* (criticality, exposure, software keywords) |
| FR4 Match CVEs to affected assets | `services.match_vulnerability`: asset software keywords vs. the CVE's CPE list |
| FR5 Smart Priority Score | `vulnmgmt/scoring.py`; breakdown on each finding page; *Reports → How the score works* |
| FR6 Risk level classification | Critical ≥ 80 · High ≥ 60 · Medium ≥ 40 · Low |
| FR7 Dashboard ordered by score | *Dashboard*, *Prioritised findings* |
| FR8 Assign and track remediation to closure | Remediation tasks + lifecycle state chart (Open → Acknowledged → In Remediation → Resolved → Closed, or → Risk Accepted → Closed) |
| FR9 Audit log of all changes | `AuditLog` written by model signals (create/update/delete with field diffs), logins, scoring, imports, exports |
| FR10 Reports | *Reports* (risk × status, per-asset risk, workload, completion rate), CSV export, print |
| NFR1 5,000 records in < 5 s | Indexed, paginated list (up to 5,000 per page); `test_dashboard_list_5000_records_under_5_seconds` |
| NFR2 No plaintext passwords | Django PBKDF2-SHA256 salted hashing; `test_passwords_are_hashed` |
| NFR3 Repeatable score | Pure deterministic function; `test_score_is_repeatable` |

Evaluation (Section 2.2): *Reports → Smart vs CVSS-only ranking* ranks the same findings both ways. It shows
which findings moved up or down once organisational context was added.

## Smart Priority Score

Each factor is scaled to 0–1 and multiplied by its weight. The weights sum to 100.

| Factor | Weight | Value |
|---|---|---|
| CVSS base score | 30 | score ÷ 10 |
| Asset criticality | 25 | Low .25 · Medium .5 · High .75 · Critical 1 |
| Exploit available | 10 | 1/0 (NVD "Exploit" reference tag) |
| Actively exploited (CISA KEV) | 10 | 1/0 |
| Exposure | 10 | Internal .3 · DMZ .7 · Internet 1 |
| Affected systems | 5 | active assets with this CVE ÷ 5 (max 1) |
| Patch unavailable | 5 | 1 if no patch/advisory exists |
| Remediation pending | 5 | Open/Acknowledged 1 · In Remediation .5 · closed states 0 |

`calculateScore()` follows the pre- and post-conditions in Section 3.7. It saves the score and risk level, creates an
**Open** remediation task for Medium, High and Critical findings (due in 30, 14 or 7 days), and writes an audit entry.
Changing an asset's criticality or exposure, or a CVE's data, automatically rescores every affected finding.

## Project layout

```
rbvms/                 Django project settings and URLs
vulnmgmt/
  models.py            User, Asset, Vulnerability, AssetVulnerability, RemediationTask, AuditLog (class diagram)
  scoring.py           Smart Priority Score engine
  nvd.py               NVD API 2.0 client (rate-limit aware) and CVE parser
  services.py          Import + asset matching
  signals.py           Audit logging and automatic rescoring
  views.py / urls.py   Web interface
  templates/, static/  Bootstrap 5 + Chart.js UI
  management/commands/ import_nvd, seed_demo, rescore, generate_load_data
  tests/               pytest-django test suite
```

## Management commands

```bash
venv\Scripts\python manage.py import_nvd --cve CVE-2021-44228
venv\Scripts\python manage.py import_nvd --keyword "apache http server" --max 50
venv\Scripts\python manage.py import_nvd --days 7          # recent CVEs, for a scheduled daily task
venv\Scripts\python manage.py import_nvd --kev --max 200    # CISA Known Exploited Vulnerabilities
venv\Scripts\python manage.py seed_demo [--live] [--reset] # fabricated demo organisation
venv\Scripts\python manage.py rescore
venv\Scripts\python manage.py generate_load_data --count 5000   # NFR1 load test (--clear to remove)
```

## Tests

```bash
venv\Scripts\python -m pytest
```

## Ethics (Section 1.8)

All assets, users and organisational data are fabricated. Vulnerability data comes from public NVD records,
or from the built-in sample of public CVEs used by the offline demo. NVD access follows its rate limits:
6 seconds between requests without an API key, 0.6 seconds with one.
