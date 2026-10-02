# Recon X - OSINT Intelligence Tool

A web-based OSINT (Open Source Intelligence) dashboard built with Flask. Give it a domain, an email, a URL and an IP address, and it pulls together publicly available intelligence into one view, with an optional PDF report.

## Features

- **WHOIS lookup** - registration and ownership data for a domain
- **crt.sh subdomain enumeration** - subdomains from public certificate transparency logs
- **Wayback Machine history** - historical URLs captured for a domain
- **IP geolocation** - location and network details for an IP (via ipinfo.io)
- **Shodan host lookup** - open ports and service banners Shodan has indexed for an IP
- **Email format validation**
- **Website title extraction**
- **PDF report generation** - export the full result set as a report (ReportLab)
- **Multi-user accounts with an admin panel** - activate/deactivate or remove users
- **Rate limiting, hashed passwords, session management** (Flask-Limiter, Werkzeug, Flask-Login)

> Use this tool only on domains, IPs and systems you own or have permission to test.

## Tech stack

Python 3 · Flask · Flask-SQLAlchemy (SQLite) · Flask-Login · Flask-Limiter · Shodan API · ipinfo API · python-whois · crt.sh · Wayback Machine CDX API · ReportLab · PyJWT

## Setup

```bash
git clone https://github.com/Cybersec-001/ReconX.git
cd ReconX
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Create your `.env` (see `.env.example`):

```bash
cp .env.example .env
python generate_secret_key.py   # writes a fresh SECRET_KEY into .env
```

Then fill in the optional values in `.env`:

| Variable | Required | Purpose |
| --- | --- | --- |
| `SECRET_KEY` | Yes | Flask session/JWT signing. App refuses to start without it. |
| `ADMIN_USERNAME` + `ADMIN_PASSWORD` | No | When both are set, an admin account is created on first run. |
| `SHODAN_API_KEY` | No | Enables Shodan host lookups. |
| `IPINFO_ACCESS_TOKEN` | No | Enables IP geolocation. |
| `VIRUSTOTAL_API_KEY`, `HIBP_API_KEY`, `CENSYS_API_ID`, `CENSYS_API_SECRET` | No | Reserved for additional lookups. |
| `FLASK_DEBUG` | No | `true` enables Flask debug mode for local development. Never enable in production. |

## Run

```bash
python app.py
```

Open http://127.0.0.1:5000, register an account, and run a scan.

For production, serve with gunicorn (included in requirements):

```bash
gunicorn app:app
```

## Project structure

```
app.py                  Flask application and routes
config.py               Env-based config (no hardcoded fallbacks)
generate_secret_key.py  Writes a fresh SECRET_KEY into .env
templates/              Jinja templates (login, register, scan, results, admin)
static/                 Stylesheet
```

## Security notes

- No default credentials: `SECRET_KEY` is mandatory and the admin account exists only if you set one via env vars.
- Passwords are stored as Werkzeug hashes; the SQLite database and `.env` are git-ignored.
- Login, registration and PDF export are rate-limited.
- Debug mode is off unless `FLASK_DEBUG=true` is set explicitly.

## API endpoints / pages

- `/` - main scanning page (login required)
- `/login`, `/register` - account pages
- `/admin` - admin panel (admin users only)
- `/download_pdf` - PDF report of the latest scan

## Contributing

Pull requests are welcome.

## Hosted portfolio demo

The public landing page and `/demo` use clearly labeled sample data. The signed-in `/workspace` keeps real WHOIS, certificate transparency and archive lookups. Shodan and IP geolocation need optional API keys; missing keys never produce fake live results.

Deploy as a **free Render web service**, Python runtime:

- Build: `pip install -r requirements.txt`
- Start: `gunicorn app:app --workers 1 --threads 4 --timeout 120 --bind 0.0.0.0:$PORT`
- Set a generated `SECRET_KEY`. Do not set demo admin credentials.
- Health check: `/health`

Free Render has an ephemeral filesystem. SQLite accounts disappear on a restart or redeploy, and the in-memory report cache/rate limits reset too. This is a portfolio demo, not a durable production account system. Do not use sensitive data. For persistent hosting, configure `DATABASE_URL` and its database driver plus shared rate-limit storage before offering real accounts.

Security changes include CSRF-protected POST forms, POST-only admin mutations, bounded input/report sizes, private-address checks for title requests, redirect blocking and password length validation. These are hardening steps, not a security certification. Rate limits are per process, public-source results depend on upstream availability, and free hosting can have cold starts.
