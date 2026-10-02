from flask import Flask, render_template, request, send_file, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps
from datetime import datetime, timedelta

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Preformatted
from reportlab.lib.styles import getSampleStyleSheet
from xml.sax.saxutils import escape
import io

import requests
import whois
import ipinfo
import shodan
import os
from dotenv import load_dotenv
import re
import json
import time
import secrets
import socket
import ipaddress
from urllib.parse import urlparse
from flask import abort
from bs4 import BeautifulSoup
import urllib3
urllib3.disable_warnings()

# Load API Keys and Config
load_dotenv()
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
IPINFO_ACCESS_TOKEN = os.getenv("IPINFO_ACCESS_TOKEN")

# SECRET_KEY is required - no insecure fallback.
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError(
        "SECRET_KEY is not set. Generate one with `python generate_secret_key.py` "
        "or copy .env.example to .env and fill it in."
    )

# Admin user is created on first run only when BOTH are set.
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

# Optional API keys (features degrade gracefully when unset)
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
HIBP_API_KEY = os.getenv('HIBP_API_KEY')
CENSYS_API_ID = os.getenv('CENSYS_API_ID')
CENSYS_API_SECRET = os.getenv('CENSYS_API_SECRET')

# Initialize Flask App
app = Flask(__name__, static_folder="static")
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///users.db').replace('postgres://', 'postgresql://', 1)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=os.getenv('RENDER') == 'true', MAX_CONTENT_LENGTH=16384)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

# Initialize extensions
db = SQLAlchemy(app)

@app.context_processor
def csrf_context():
    def csrf_token():
        if '_csrf' not in session:
            session['_csrf'] = secrets.token_urlsafe(32)
        return session['_csrf']
    return {'csrf_token': csrf_token}

@app.before_request
def protect_forms():
    if request.method == 'POST':
        supplied = request.form.get('csrf_token', '')
        expected = session.get('_csrf', '')
        if not expected or not secrets.compare_digest(supplied, expected):
            abort(400, 'Form expired. Reload and try again.')

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# User Model
class User(UserMixin, db.Model):
    __tablename__ = 'users'  # Explicitly set table name
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    api_key = db.Column(db.String(120), unique=True, nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    # Flask-Login passes the value returned by User.get_id() (the primary key as a string)
    try:
        return User.query.get(int(user_id))
    except (ValueError, TypeError):
        return None

# Create tables if they do not exist (never drop existing data)
with app.app_context():
    db.create_all()

    # Create admin user on first run, only when credentials are provided via env
    if ADMIN_USERNAME and ADMIN_PASSWORD:
        if not User.query.filter_by(username=ADMIN_USERNAME).first():
            admin = User(
                username=ADMIN_USERNAME,
                is_admin=True,
                created_at=datetime.utcnow()
            )
            admin.set_password(ADMIN_PASSWORD)
            db.session.add(admin)
            db.session.commit()
    else:
        app.logger.warning(
            "ADMIN_USERNAME/ADMIN_PASSWORD not set - no admin user created. "
            "You can still register a normal account; set both variables to enable the admin panel."
        )

# Token Required Decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token')
        if not token:
            token = request.headers.get('X-API-Token')

        if not token:
            return {'message': 'Token is missing'}, 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(data['user_id'])
            if current_user is None:
                return {'message': 'Token is invalid'}, 401
        except Exception:
            return {'message': 'Token is invalid'}, 401

        return f(current_user, *args, **kwargs)
    return decorated

# Initialize APIs (optional - routes report a clear error when a key is missing)
shodan_api = shodan.Shodan(SHODAN_API_KEY) if SHODAN_API_KEY else None
ipinfo_handler = ipinfo.getHandler(IPINFO_ACCESS_TOKEN) if IPINFO_ACCESS_TOKEN else None

# WHOIS Lookup
def get_whois_data(domain):
    try:
        w = whois.whois(domain)
        # Format the output nicely
        result = []
        for key, value in w.items():
            if value:
                if isinstance(value, (list, tuple)):
                    value = ', '.join(str(v) for v in value if v)
                result.append(f"{key}: {value}")
        return '\n'.join(result)
    except Exception as e:
        return f"Error: {str(e)}"

# Email Validation
def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if re.match(pattern, email):
        return "Valid email format. This does not verify mailbox existence or ownership."
    else:
        return "Invalid email format."

# Website Title Extraction
def public_target(url):
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('Use a public HTTP or HTTPS URL without credentials.')
    if parsed.port not in (None, 80, 443):
        raise ValueError('Only standard web ports are supported.')
    addresses = socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == 'https' else 80))
    if not addresses or any(not ipaddress.ip_address(item[4][0]).is_global for item in addresses):
        raise ValueError('Private, local and reserved addresses are not allowed.')
    return url

def get_website_title(url):
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        public_target(url)
        # Redirects are not followed; every outbound target must be checked.
        with requests.get(url, timeout=5, allow_redirects=False, stream=True) as response:
            response.raise_for_status()
            if response.is_redirect:
                return 'Website redirects. Enter its final public URL.'
            content = next(response.iter_content(65536), b'').decode('utf-8', errors='replace')
        title = BeautifulSoup(content, 'html.parser').title
        return title.get_text(strip=True)[:300] if title else 'No title found'
    except Exception:
        return 'Website title unavailable. Use a public HTTP/HTTPS URL; private addresses are blocked.'

# IP Geolocation
def get_ip_geolocation(ip):
    if ipinfo_handler is None:
        return "IP geolocation unavailable: IPINFO_ACCESS_TOKEN is not set."
    try:
        details = ipinfo_handler.getDetails(ip)
        return details.all
    except ipinfo.exceptions.RequestQuotaExceededError:
        return "Error: API quota exceeded."
    except Exception as e:
        return f"Error: {str(e)}"

# Shodan API Scan
def get_shodan_scan(ip):
    if shodan_api is None:
        return "Shodan lookup unavailable: SHODAN_API_KEY is not set."
    try:
        host = shodan_api.host(ip)
        return host
    except shodan.APIError as e:
        return f"Error: {str(e)}"

def get_censys_data(domain):
    """Get domain information from Censys"""
    try:
        headers = {
            'Accept': 'application/json',
        }
        auth = (CENSYS_API_ID, CENSYS_API_SECRET)
        response = requests.get(
            f'https://search.censys.io/api/v2/hosts/search?q={domain}',
            headers=headers,
            auth=auth,
            timeout=10
        )
        if response.status_code == 200:
            return response.json()
        return "No Censys data available"
    except Exception as e:
        return f"Censys Error: {str(e)}"

def get_hibp_breaches(email):
    """Check if email has been involved in any breaches using HIBP"""
    try:
        headers = {
            'hibp-api-key': HIBP_API_KEY,
            'User-Agent': 'Recon-X-Tool'
        }
        response = requests.get(
            f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}',
            headers=headers,
            timeout=10
        )
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return "No breaches found"
        return "Unable to check breaches"
    except Exception as e:
        return f"HIBP Error: {str(e)}"

def get_crt_subdomains(domain):
    """Get SSL certificate subdomains from crt.sh"""
    try:
        response = requests.get(f'https://crt.sh/?q=%.{domain}&output=json', timeout=10)
        if response.status_code == 200:
            data = response.json()
            subdomains = list(set([item['name_value'] for item in data]))
            return sorted(set(name.strip() for value in subdomains for name in value.splitlines()))[:100]
        return "No subdomain data available"
    except Exception as e:
        return "Certificate source unavailable or timed out. Try again later."

def get_virustotal_data(domain):
    """Get domain information from VirusTotal"""
    try:
        headers = {
            'x-apikey': VIRUSTOTAL_API_KEY
        }
        response = requests.get(
            f'https://www.virustotal.com/api/v3/domains/{domain}',
            headers=headers,
            timeout=10
        )
        if response.status_code == 200:
            return response.json()
        return "No VirusTotal data available"
    except Exception as e:
        return f"VirusTotal Error: {str(e)}"

def get_wayback_urls(domain):
    """Get historical URLs from Wayback Machine"""
    try:
        response = requests.get(
            f'https://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&collapse=urlkey&limit=100',
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            if len(data) > 1:  # Skip header row
                urls = list(set([item[2] for item in data[1:]]))
                return urls[:100]  # Limit to 100 URLs
            return "No historical URLs found"
        return "No Wayback Machine data available"
    except Exception as e:
        return "Archive source unavailable or timed out. Try again later."

# Routes
@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/health')
@limiter.exempt
def health():
    return {'status': 'ok'}

@app.route('/demo')
def demo():
    return render_template('result.html', demo_mode=True,
        whois_data='Sample domain: example.com\nReserved for documentation and examples.\nIllustrative result, not a live WHOIS query.',
        email_validation='hello@example.com: valid email format (sample). This does not verify mailbox ownership.',
        website_title='Example Domain (sample)',
        ip_geolocation='Optional API key required for live geolocation.',
        shodan_scan='Optional Shodan key required. ReconX reads indexed intelligence; it does not run port scans.',
        subdomains=['www.example.com (illustrative)'],
        wayback_urls=['https://example.com/ (illustrative)'])

@app.route("/workspace", methods=["GET", "POST"])
@login_required
@limiter.limit("100 per hour")
def index():
    if request.method == "POST":
        if not current_user.is_active:
            flash("Your account has been deactivated")
            return redirect(url_for('login'))

        domain = request.form.get("domain", "").strip()
        email = request.form.get("email", "").strip()
        url = request.form.get("url", "").strip()
        ip = request.form.get("ip", "").strip()

        if not all([domain, email, url, ip]):
            return render_template("index.html", error="All fields are required")

        if not re.fullmatch(r'(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}', domain):
            return render_template('index.html', error='Enter a domain name only, such as example.com.'), 400
        try:
            if not ipaddress.ip_address(ip).is_global:
                raise ValueError()
        except ValueError:
            return render_template('index.html', error='Enter a public IP address.'), 400
        if len(email) > 254 or len(url) > 2048:
            return render_template('index.html', error='Input is too long.'), 400

        try:
            # Get all scan results
            whois_data = get_whois_data(domain)
            email_validation = validate_email(email)
            website_title = get_website_title(url)
            ip_geolocation = get_ip_geolocation(ip)
            shodan_scan = get_shodan_scan(ip)
            subdomains = get_crt_subdomains(domain)
            wayback_urls = get_wayback_urls(domain)

            # Store all results in session
            store_results_in_session(
                whois_data, email_validation, website_title,
                ip_geolocation, shodan_scan, subdomains, wayback_urls
            )

            return render_template("result.html",
                               whois_data=whois_data,
                               email_validation=email_validation,
                               website_title=website_title,
                               ip_geolocation=ip_geolocation,
                               shodan_scan=shodan_scan,
                               subdomains=subdomains,
                               wayback_urls=wayback_urls)
        except Exception as e:
            return render_template("index.html", error=f"Error: {str(e)}")

    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("3 per minute")
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password")

        if not re.fullmatch(r'[a-zA-Z0-9_-]{3,40}', username) or not 10 <= len(password) <= 128:
            flash('Use a 3-40 character username (letters, numbers, _ or -) and a 10-128 character password.')
            return render_template('register.html'), 400
        if User.query.filter_by(username=username).first():
            flash("Username already exists")
            return render_template("register.html")

        if password != confirm_password:
            flash("Passwords do not match")
            return render_template("register.html")

        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash("Registration successful! Please login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            if not user.is_active:
                flash("Your account has been deactivated")
                return render_template("login.html")

            login_user(user)
            user.last_login = datetime.utcnow()
            db.session.commit()

            token = jwt.encode({
                'user_id': user.id,
                'exp': datetime.utcnow() + timedelta(days=1)
            }, app.config['SECRET_KEY'])
            session['token'] = token

            if user.is_admin:
                return redirect(url_for('admin'))
            return redirect(url_for('index'))

        flash('Invalid username or password')
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.pop('token', None)
    return redirect(url_for('login'))

@app.route("/admin")
@login_required
def admin():
    if not current_user.is_admin:
        flash("Access denied")
        return redirect(url_for("index"))

    users = User.query.all()
    return render_template("admin.html", users=users)

@app.route("/admin/user/<int:user_id>/toggle", methods=["POST"])
@login_required
def toggle_user(user_id):
    if not current_user.is_admin:
        flash("Access denied")
        return redirect(url_for("index"))

    user = User.query.get_or_404(user_id)
    if ADMIN_USERNAME and user.username == ADMIN_USERNAME:
        flash("Cannot modify admin user")
        return redirect(url_for("admin"))

    user.is_active = not user.is_active
    db.session.commit()
    flash(f"User {user.username} {'activated' if user.is_active else 'deactivated'}")
    return redirect(url_for("admin"))

@app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash("Access denied")
        return redirect(url_for("index"))

    user = User.query.get_or_404(user_id)
    if ADMIN_USERNAME and user.username == ADMIN_USERNAME:
        flash("Cannot delete admin user")
        return redirect(url_for("admin"))

    db.session.delete(user)
    db.session.commit()
    flash(f"User {user.username} deleted")
    return redirect(url_for("admin"))

@app.route("/download_pdf", methods=["GET"])
@login_required
@limiter.limit("5 per minute")
def download_pdf():
    try:
        # Get all data from session
        report = session.get('report_id')
        payload = scan_reports.get(report, (None, {}))
        if not payload[0] or payload[0] != current_user.id:
            flash('No report available. Run a new scan.')
            return redirect(url_for('index'))
        data = payload[1]
        whois_data = data.get('whois_data')
        email_validation = data.get('email_validation')
        website_title = data.get('website_title')
        ip_geolocation = data.get('ip_geolocation')
        shodan_scan = data.get('shodan_scan')
        subdomains = data.get('subdomains')
        wayback_urls = data.get('wayback_urls')

        if not all([whois_data, email_validation, website_title, ip_geolocation, shodan_scan]):
            flash("No scan data available. Please perform a scan first.")
            return redirect(url_for('index'))

        buffer = io.BytesIO()
        document = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=50,
            leftMargin=50, topMargin=50, bottomMargin=50)
        styles = getSampleStyleSheet()
        story = [Paragraph('ReconX Intelligence Report', styles['Title']),
            Paragraph('Generated: ' + datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC'), styles['Normal']),
            Paragraph('Researcher: ' + escape(current_user.username), styles['Normal']),
            Spacer(1, 20)]
        for title, value in [('WHOIS Information', whois_data), ('Email format', email_validation),
                ('Website title', website_title), ('IP geolocation', ip_geolocation),
                ('Shodan indexed intelligence', shodan_scan), ('Certificate subdomains', subdomains),
                ('Historical URLs', wayback_urls)]:
            story.append(Paragraph(title, styles['Heading2']))
            text = json.dumps(value, indent=2, default=str) if isinstance(value, (dict, list)) else str(value)
            for line in text.splitlines() or ['No data returned.']:
                story.append(Paragraph(escape(line), styles['BodyText']))
            story.append(Spacer(1, 14))
        story.append(Paragraph('Only investigate systems you own or have permission to assess. '
            'External-source results can be incomplete; email format does not verify mailbox ownership.', styles['Normal']))
        document.build(story)
        buffer.seek(0)

        return send_file(
            buffer,
            download_name='recon_x_report.pdf',
            as_attachment=True,
            mimetype='application/pdf'
        )

    except Exception as e:
        flash(f"Error generating PDF: {str(e)}")
        return redirect(url_for('index'))

# Bounded temporary report cache. Gunicorn uses one worker on the demo host.
scan_reports = {}
def store_results_in_session(whois_data, email_validation, website_title, ip_geolocation, shodan_scan, subdomains, wayback_urls):
    scan_reports.pop(session.get('report_id'), None)
    while len(scan_reports) >= 50:
        scan_reports.pop(next(iter(scan_reports)))
    report_id = secrets.token_urlsafe(24)
    scan_reports[report_id] = (current_user.id, dict(whois_data=whois_data,
        email_validation=email_validation, website_title=website_title,
        ip_geolocation=ip_geolocation, shodan_scan=shodan_scan,
        subdomains=subdomains, wayback_urls=wayback_urls))
    session['report_id'] = report_id

if __name__ == "__main__":
    # Debug stays OFF unless FLASK_DEBUG is explicitly enabled (never enable it in production)
    debug_mode = os.getenv("FLASK_DEBUG", "false").strip().lower() in ("1", "true", "yes")
    app.run(debug=debug_mode)
