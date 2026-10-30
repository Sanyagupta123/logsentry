# LogSentry

LogSentry is a local Flask dashboard for parsing Apache/Nginx combined access logs, summarizing traffic, and flagging explainable security indicators. It is an educational MVP, not a SIEM. A finding is a lead for investigation, not proof of an attack.

## Features

- Combined log parsing with timestamp, IP, method, path, status, size, referrer, and user agent validation.
- Pandas summaries for status, traffic, top IPs and endpoints, errors, and hourly activity.
- Four sliding-window rules: five 401/403 responses per IP in 60 seconds (high); more than 100 requests per IP in 60 seconds (medium); sensitive path access (medium); ten 5xx responses per endpoint in 60 seconds (medium).
- Flask JSON API, SQLite analysis history, responsive dark dashboard, and synthetic sample data.
- 5 MB and 100,000-line upload limits. Raw log content is not stored.

## Windows setup

```powershell
cd "E:\GIT HUB\logsentry"
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Open <http://127.0.0.1:5000>. Select `sample_logs/demo_access.log` in the dashboard. The included sample is synthetic and uses documentation-only IP ranges.

## API

- `GET /api/health` — local service health.
- `POST /api/analyze` — multipart form field `file`, `.log` or `.txt` UTF-8 file.
- `GET /api/history` — latest 50 summaries.
- `GET /api/analysis/<id>` — stored analysis and summary.
- `GET /api/analysis/<id>/findings` — stored findings.

Set `LOGSENTRY_DB` to choose the SQLite database path. Upload size and line count are fixed at 5 MB and 100,000 lines.

## Structure

`app.py` wires Flask routes; `logsentry/parser.py`, `analyzer.py`, `detection.py`, and `database.py` hold the parsing, summaries, rules, and persistence. `templates/` and `static/` provide the dashboard. `tests/` contains pytest coverage; `sample_logs/` contains synthetic data.

## Test

```powershell
python -m pytest -q
```

## Security, privacy, and limitations

Production logs can contain IP addresses, authentication tokens, session identifiers, and personal data. Only analyze logs you are authorized to use; do not upload private logs to external services. The browser loads Chart.js from jsDelivr. This MVP does not block IPs, retain raw log files, authenticate users, or cover every log format. Detection rules use configurable Python thresholds through `detect(rows, thresholds=...)`; the HTTP interface currently uses defaults. Login detection counts 401/403 responses regardless of endpoint because access logs do not reliably identify login routes. Sensitive-path detection is a request indicator, including expected scanner traffic.

## Architecture

Upload validation → parser and IP/time validation → Pandas analytics and sliding-window rules → SQLite summary/finding rows → JSON API and safe `textContent` dashboard rendering.

## Screenshots

Add a screenshot after running the local dashboard.

## License

MIT License. Include a `LICENSE` file with the standard MIT text before publishing this repository under that license.

## Publishing

Create an empty GitHub repository, then run:

```powershell
git init
git add .
git commit -m "Build LogSentry log analysis MVP"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/logsentry.git
git push -u origin main
```
