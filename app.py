import os
import json
import csv
import threading
from datetime import datetime, timedelta
from functools import wraps
from io import BytesIO, StringIO

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, jsonify, send_file
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from flask_mail import Mail, Message
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ----------------------------------------------------------------------
# App Configuration
# ----------------------------------------------------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = 'change-this-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///environment.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/images/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ----------------------------------------------------------------------
# Flask-Mail Configuration
# Override these via environment variables in production, or update them
# through the Admin → Email Settings page at runtime.
# ----------------------------------------------------------------------
app.config['MAIL_SERVER']   = os.environ.get('MAIL_SERVER',   'smtp.gmail.com')
app.config['MAIL_PORT']     = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS']  = os.environ.get('MAIL_USE_TLS',  'true').lower() == 'true'
app.config['MAIL_USE_SSL']  = os.environ.get('MAIL_USE_SSL',  'false').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', '')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', '')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'ecoWatch Alerts <noreply@ecowatch.mw>')

db = SQLAlchemy(app)
mail = Mail(app)
CORS(app, supports_credentials=True)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ----------------------------------------------------------------------
# District & Department Configuration
# ----------------------------------------------------------------------
MALAWI_DISTRICTS = [
    'Balaka', 'Blantyre', 'Chikwawa', 'Chiradzulu', 'Chitipa',
    'Dedza', 'Dowa', 'Karonga', 'Kasungu', 'Likoma', 'Lilongwe',
    'Machinga', 'Mangochi', 'Mchinji', 'Mulanje', 'Mwanza',
    'Mzimba', 'Neno', 'Nkhata Bay', 'Nkhotakota', 'Nsanje',
    'Ntcheu', 'Ntchisi', 'Phalombe', 'Rumphi', 'Salima',
    'Thyolo', 'Zomba'
]

DEPARTMENTS = [
    'Sanitation',
    'Forestry',
    'Environmental Protection',
    'Wildlife & National Parks',
    'Mines & Minerals',
    'General Administration'
]

# Maps incident category -> department that receives the notification
CATEGORY_DEPARTMENT_MAP = {
    'dumping':        'Sanitation',
    'pollution':      'Environmental Protection',
    'charcoal':       'Forestry',
    'deforestation':  'Forestry',
    'poaching':       'Wildlife & National Parks',
    'mining':         'Mines & Minerals',
    'wildfire':       'Forestry',
    'other':          'General Administration',
}

# Incident categories presented to the reporter
INCIDENT_CATEGORIES = [
    ('deforestation', '🌳 Deforestation / Illegal Logging'),
    ('pollution',     '🏭 Pollution'),
    ('poaching',      '🐘 Poaching / Wildlife Crime'),
    ('mining',        '⛏️ Illegal Mining'),
    ('charcoal',      '🔥 Charcoal Burning'),
    ('dumping',       '🗑️ Illegal Waste Dumping'),
    ('wildfire',      '🔥 Wildfire'),
    ('other',         '❓ Other Environmental Incident'),
]

# ----------------------------------------------------------------------
# Models
# ----------------------------------------------------------------------
class User(UserMixin, db.Model):
    id               = db.Column(db.Integer, primary_key=True)
    username         = db.Column(db.String(100), unique=True, nullable=False)
    email            = db.Column(db.String(120), unique=True, nullable=False)
    password_hash    = db.Column(db.String(200), nullable=False)
    role             = db.Column(db.String(20), default='citizen')  # citizen | admin | super_admin
    district         = db.Column(db.String(100), nullable=True)
    department       = db.Column(db.String(100), nullable=True)
    account_status   = db.Column(db.String(20), default='active')  # active | pending_approval | rejected
    id_document_path = db.Column(db.String(500), nullable=True)
    rejection_reason = db.Column(db.Text, nullable=True)
    approved_by      = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at       = db.Column(db.DateTime, default=datetime.utcnow)
    incidents        = db.relationship('Incident', backref='reporter', lazy=True)
    notifications    = db.relationship('Notification', backref='user', lazy=True)

    @property
    def is_active(self):
        return self.account_status == 'active'

    @property
    def display_role(self):
        if self.role == 'super_admin':
            return 'Super Admin'
        if self.role == 'admin' and self.district and self.department:
            return f"{self.department} – {self.district}"
        return self.role.replace('_', ' ').title()

    @property
    def is_admin_or_super(self):
        return self.role in ('admin', 'super_admin')


class Incident(db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    title         = db.Column(db.String(200), nullable=False)   # stores the category label
    description   = db.Column(db.Text, nullable=False)
    category      = db.Column(db.String(100))
    latitude      = db.Column(db.Float)
    longitude     = db.Column(db.Float)
    location_name = db.Column(db.String(200))
    district      = db.Column(db.String(100))                   # district derived from location
    department    = db.Column(db.String(100))                   # responsible department
    status        = db.Column(db.String(20), default='pending')
    image_path    = db.Column(db.String(500))
    user_id       = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    verified_by   = db.Column(db.Integer, nullable=True)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at    = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_emergency  = db.Column(db.Boolean, default=False)


class Notification(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    incident_id = db.Column(db.Integer, db.ForeignKey('incident.id'), nullable=False)
    message     = db.Column(db.String(500), nullable=False)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    is_read     = db.Column(db.Boolean, default=False)
    incident    = db.relationship('Incident', backref='notifications')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ----------------------------------------------------------------------
# Simplified NLP Classifier (built-in)
# ----------------------------------------------------------------------
class IncidentClassifier:
    def __init__(self):
        self.categories = {
            'deforestation': {
                'en': ['tree', 'forest', 'cut', 'logging', 'timber', 'wood', 'clearing', 'felling'],
                'ny': ['mtengo', 'nkhalango', 'kutema', 'kudula', 'matabwa', 'chipika']
            },
            'pollution': {
                'en': ['waste', 'dump', 'chemical', 'toxic', 'smoke', 'air', 'water', 'contaminate'],
                'ny': ['zinyalala', 'kutaya', 'utsi', 'madzi', 'mtsinje', 'kuwononga']
            },
            'poaching': {
                'en': ['animal', 'hunt', 'kill', 'wildlife', 'elephant', 'trap', 'poach'],
                'ny': ['nyama', 'zamtchire', 'kupha', 'alenje', 'njovu', 'nyanga']
            },
            'mining': {
                'en': ['mine', 'dig', 'extract', 'mineral', 'pit', 'quarry', 'gold'],
                'ny': ['mgodi', 'kukumba', 'mchenga', 'golide']
            },
            'charcoal': {
                'en': ['charcoal', 'burn', 'kiln', 'firewood'],
                'ny': ['makala', 'kuotcha', 'nkhuni', 'kuyaka']
            },
            'dumping': {
                'en': ['dump', 'garbage', 'trash', 'litter', 'refuse'],
                'ny': ['kutaya', 'zinyalala', 'malo otayira']
            },
            'wildfire': {
                'en': ['fire', 'wildfire', 'forest fire', 'burning', 'blaze', 'flames', 'bushfire', 'inferno'],
                'ny': ['moto', 'kuyaka', 'nkhalango kuyaka', 'kutentha']
            }
        }
        self.chichewa_indicators = ['ndi', 'ku', 'pa', 'mwina', 'ali', 'amene', 'ndinu', 'kuti', 'chifukwa']
        self.emergency_categories = {'wildfire', 'poaching'}

    def detect_language(self, text):
        text_lower = text.lower()
        for word in self.chichewa_indicators:
            if f' {word} ' in f' {text_lower} ':
                return 'ny'
        return 'en'

    def classify_with_confidence(self, text):
        lang = self.detect_language(text)
        text_lower = text.lower()
        scores = {}
        for cat, keywords in self.categories.items():
            kw_list = keywords.get(lang, keywords['en'])
            matches = [kw for kw in kw_list if kw in text_lower]
            if matches:
                confidence = min(100, len(matches) * 20)
                scores[cat] = {'confidence': confidence, 'matches': matches}
        if scores:
            best = max(scores, key=lambda c: scores[c]['confidence'])
            return {
                'category': best,
                'confidence': scores[best]['confidence'],
                'matches': scores[best]['matches'],
                'language': lang
            }
        return {'category': 'other', 'confidence': 0, 'matches': [], 'language': lang}

    def is_emergency(self, category):
        return category in self.emergency_categories

classifier = IncidentClassifier()

# ----------------------------------------------------------------------
# Helper Functions
# ----------------------------------------------------------------------
def allowed_file(filename):
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''; return ext in {'png', 'jpg', 'jpeg', 'gif', 'pdf'}

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role not in ('admin', 'super_admin'):
            flash('Access denied.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated

def super_admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'super_admin':
            flash('Super admin access required.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated

def get_responsible_department(category):
    return CATEGORY_DEPARTMENT_MAP.get(category, 'General Administration')

def _send_emergency_emails(app_ctx, recipients, incident_id, incident_title,
                            incident_category, incident_district, incident_department,
                            reporter_username, lat, lng, location_name):
    """Send emergency email alerts in a background thread."""
    with app_ctx:
        if not app.config.get('MAIL_USERNAME'):
            app.logger.warning("Email alerts skipped — MAIL_USERNAME not configured.")
            return

        subject = f"🚨 EMERGENCY ALERT: {incident_category.upper()} in {incident_district or 'Unknown District'}"

        map_url = (
            f"https://www.openstreetmap.org/?mlat={lat}&mlon={lng}#map=15/{lat}/{lng}"
            if lat and lng else None
        )

        html_body = render_template(
            'email/emergency_alert.html',
            incident_id=incident_id,
            incident_title=incident_title,
            incident_category=incident_category,
            incident_district=incident_district or 'Unknown District',
            incident_department=incident_department,
            reporter_username=reporter_username,
            location_name=location_name or 'Not specified',
            map_url=map_url,
            reported_at=datetime.utcnow().strftime('%d %B %Y at %H:%M UTC'),
        )

        text_body = (
            f"EMERGENCY ENVIRONMENTAL ALERT — ecoWatch\n"
            f"{'='*50}\n\n"
            f"Category   : {incident_category.upper()}\n"
            f"District   : {incident_district or 'Unknown'}\n"
            f"Department : {incident_department}\n"
            f"Location   : {location_name or 'See coordinates below'}\n"
            f"Reported by: {reporter_username}\n"
            f"Time       : {datetime.utcnow().strftime('%d %B %Y %H:%M UTC')}\n"
            + (f"Map        : {map_url}\n" if map_url else "")
            + f"\nPlease log in to ecoWatch to review and respond to this incident immediately.\n"
        )

        for email_addr in recipients:
            try:
                msg = Message(
                    subject=subject,
                    recipients=[email_addr],
                    body=text_body,
                    html=html_body,
                )
                mail.send(msg)
                app.logger.info(f"Emergency email sent to {email_addr} for incident #{incident_id}")
            except Exception as e:
                app.logger.error(f"Failed to send emergency email to {email_addr}: {e}")


def create_incident_notifications(incident):
    """
    1. Create in-app notifications for all relevant admin users.
    2. If it is an emergency, also send email alerts in a background thread.

    Routing priority (same for both in-app and email):
      1. Admins whose district AND department both match
      2. Admins in the same district (any department)
      3. Admins in the same department (any district)
      4. All admins (fallback)
    """
    dept = incident.department
    dist = incident.district

    targets = User.query.filter_by(role='admin', district=dist, department=dept).all()
    if not targets:
        targets = User.query.filter_by(role='admin', district=dist).all()
    if not targets:
        targets = User.query.filter_by(role='admin', department=dept).all()
    if not targets:
        targets = User.query.filter_by(role='admin').all()

    emoji   = '🚨' if incident.is_emergency else '📋'
    urgency = 'EMERGENCY ALERT' if incident.is_emergency else 'New Incident'

    for admin in targets:
        msg_text = (
            f"{emoji} {urgency}: [{incident.category.upper()}] "
            f"reported in {dist or 'Unknown District'} – "
            f"Assigned to {dept}. \"{incident.title}\""
        )
        db.session.add(Notification(
            user_id=admin.id,
            incident_id=incident.id,
            message=msg_text,
        ))
    db.session.commit()

    # Send email alerts for emergencies only
    if incident.is_emergency:
        recipient_emails = [u.email for u in targets if u.email]
        reporter = User.query.get(incident.user_id)
        reporter_name = reporter.username if reporter else 'Unknown'

        # Run in background so the HTTP response is not held up by SMTP
        thread = threading.Thread(
            target=_send_emergency_emails,
            args=(
                app.app_context(),
                recipient_emails,
                incident.id,
                incident.title,
                incident.category,
                incident.district,
                incident.department,
                reporter_name,
                incident.latitude,
                incident.longitude,
                incident.location_name,
            ),
            daemon=True,
        )
        thread.start()

# ----------------------------------------------------------------------
# Authentication Routes
# ----------------------------------------------------------------------
@app.route('/')
def index():
    incidents = Incident.query.order_by(Incident.created_at.desc()).limit(3).all()
    return render_template('index.html', incidents=incidents)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard' if current_user.role == 'citizen' else 'admin_dashboard'))
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form.get('email')).first()
        if user and check_password_hash(user.password_hash, request.form.get('password')):
            login_user(user, remember=request.form.get('remember'))
            return redirect(url_for('admin_dashboard' if user.role in ('admin','super_admin') else 'dashboard'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        role = request.form.get('role', 'citizen')
        district   = request.form.get('district', '').strip()   if role == 'admin' else None
        department = request.form.get('department', '').strip() if role == 'admin' else None

        errors = []
        if request.form.get('password') != request.form.get('confirm_password'):
            errors.append('Passwords do not match')
        elif len(request.form.get('password', '')) < 6:
            errors.append('Password must be at least 6 characters')
        if User.query.filter_by(email=request.form.get('email','')).first():
            errors.append('Email is already registered')
        if User.query.filter_by(username=request.form.get('username','')).first():
            errors.append('Username is already taken')
        if role == 'admin':
            if not district:
                errors.append('District is required for admin accounts')
            if not department:
                errors.append('Department is required for admin accounts')
            if 'id_document' not in request.files or not request.files['id_document'].filename:
                errors.append('A government-issued ID document is required for admin registration')

        if errors:
            for e in errors:
                flash(e, 'danger')
        else:
            # Save ID document for admin applicants
            id_doc_path = None
            if role == 'admin':
                id_file = request.files['id_document']
                if not allowed_file(id_file.filename):
                    flash('ID document must be an image (PNG, JPG, JPEG) or PDF.', 'danger')
                    return render_template('register.html', districts=MALAWI_DISTRICTS, departments=DEPARTMENTS)
                id_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'id_documents')
                os.makedirs(id_dir, exist_ok=True)
                id_filename = secure_filename(f"id_{request.form['username']}_{datetime.now().timestamp()}_{id_file.filename}")
                id_file.save(os.path.join(id_dir, id_filename))
                id_doc_path = f"images/uploads/id_documents/{id_filename}"

            user = User(
                username=request.form['username'],
                email=request.form['email'],
                password_hash=generate_password_hash(request.form['password']),
                role=role,
                district=district or None,
                department=department or None,
                account_status='pending_approval' if role == 'admin' else 'active',
                id_document_path=id_doc_path,
            )
            db.session.add(user)
            db.session.commit()

            if role == 'admin':
                # Notify all super admins of a new pending application
                super_admins = User.query.filter_by(role='super_admin', account_status='active').all()
                for sa in super_admins:
                    db.session.add(Notification(
                        user_id=sa.id,
                        incident_id=1,  # placeholder; reviewed in admin panel
                        message=f"📋 New admin registration pending approval: {user.username} ({department}, {district})"
                    ))
                db.session.commit()
                flash('Your admin application has been submitted and is awaiting approval by the system administrator. You will be able to log in once approved.', 'info')
            else:
                flash('Account created successfully. Please log in.', 'success')
            return redirect(url_for('login'))

    return render_template('register.html',
                           districts=MALAWI_DISTRICTS,
                           departments=DEPARTMENTS)


# ----------------------------------------------------------------------
# Super Admin — Pending Admin Approvals
# ----------------------------------------------------------------------
@app.route('/superadmin/pending-admins')
@login_required
@super_admin_required
def pending_admins():
    pending = User.query.filter_by(role='admin', account_status='pending_approval').order_by(User.created_at.desc()).all()
    rejected = User.query.filter_by(role='admin', account_status='rejected').order_by(User.created_at.desc()).limit(20).all()
    return render_template('pending_admins.html', pending=pending, rejected=rejected)


@app.route('/superadmin/approve-admin/<int:user_id>', methods=['POST'])
@login_required
@super_admin_required
def approve_admin(user_id):
    user = User.query.get_or_404(user_id)
    if user.role != 'admin' or user.account_status != 'pending_approval':
        flash('Invalid action.', 'danger')
        return redirect(url_for('pending_admins'))
    user.account_status = 'active'
    user.approved_by = current_user.id
    user.rejection_reason = None
    db.session.commit()
    flash(f'Admin account for {user.username} ({user.department}, {user.district}) has been approved.', 'success')
    return redirect(url_for('pending_admins'))


@app.route('/superadmin/reject-admin/<int:user_id>', methods=['POST'])
@login_required
@super_admin_required
def reject_admin(user_id):
    user = User.query.get_or_404(user_id)
    if user.role != 'admin':
        flash('Invalid action.', 'danger')
        return redirect(url_for('pending_admins'))
    reason = request.form.get('reason', '').strip()
    user.account_status = 'rejected'
    user.rejection_reason = reason or 'No reason provided.'
    db.session.commit()
    flash(f'Admin application for {user.username} has been rejected.', 'warning')
    return redirect(url_for('pending_admins'))


@app.route('/superadmin/revoke-admin/<int:user_id>', methods=['POST'])
@login_required
@super_admin_required
def revoke_admin(user_id):
    user = User.query.get_or_404(user_id)
    if user.role not in ('admin',) or user.id == current_user.id:
        flash('Cannot revoke this account.', 'danger')
        return redirect(url_for('view_users'))
    user.account_status = 'rejected'
    user.rejection_reason = request.form.get('reason', 'Access revoked by super admin.')
    db.session.commit()
    flash(f'Access for {user.username} has been revoked.', 'warning')
    return redirect(url_for('view_users'))


@app.route('/superadmin/id-document/<int:user_id>')
@login_required
@super_admin_required
def view_id_document(user_id):
    user = User.query.get_or_404(user_id)
    if not user.id_document_path:
        flash('No ID document on file.', 'warning')
        return redirect(url_for('pending_admins'))
    return redirect(url_for('static', filename=user.id_document_path))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# ----------------------------------------------------------------------
# Public Incident Tracker
# ----------------------------------------------------------------------
@app.route('/public-incidents')
def public_incidents():
    incidents = Incident.query.order_by(Incident.created_at.desc()).all()
    return render_template('public_incidents.html', incidents=incidents)

# ----------------------------------------------------------------------
# User Dashboard
# ----------------------------------------------------------------------
@app.route('/dashboard')
@login_required
def dashboard():
    incidents = Incident.query.filter_by(user_id=current_user.id).order_by(Incident.created_at.desc()).all()
    stats = {
        'total':    len(incidents),
        'pending':  sum(1 for i in incidents if i.status == 'pending'),
        'verified': sum(1 for i in incidents if i.status == 'verified'),
        'resolved': sum(1 for i in incidents if i.status == 'resolved'),
    }
    return render_template('dashboard.html', incidents=incidents, stats=stats)

def reverse_geocode_district(lat, lng):
    """
    Attempt to derive the Malawian district from GPS coordinates using the
    Nominatim reverse-geocoding API (OpenStreetMap). Falls back to None on
    any network or parsing error so the app never breaks.
    """
    import urllib.request, urllib.parse, json as _json
    try:
        params = urllib.parse.urlencode({'lat': lat, 'lon': lng, 'format': 'json', 'zoom': 8})
        url = f"https://nominatim.openstreetmap.org/reverse?{params}"
        req = urllib.request.Request(url, headers={'User-Agent': 'ecoWatch/1.0 (environmental monitoring)'})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = _json.loads(resp.read())
        addr = data.get('address', {})
        # Nominatim returns county, state_district, or state for Malawi districts
        raw = addr.get('county') or addr.get('state_district') or addr.get('state') or ''
        # Strip common suffixes like ' District'
        district_name = raw.replace(' District', '').strip()
        # Match against our known list (case-insensitive)
        for d in MALAWI_DISTRICTS:
            if d.lower() == district_name.lower():
                return d
        return district_name or None
    except Exception:
        return None


@app.route('/api/reverse-geocode')
def api_reverse_geocode():
    """Client-side JS calls this so the district is shown on the form before submission."""
    try:
        lat = float(request.args.get('lat'))
        lng = float(request.args.get('lng'))
        district = reverse_geocode_district(lat, lng)
        return jsonify({'district': district})
    except Exception:
        return jsonify({'district': None})


@app.route('/report', methods=['GET', 'POST'])
@login_required
def report_incident():
    if request.method == 'POST':
        category    = request.form.get('category', '').strip()
        description = request.form.get('description', '').strip()
        lat         = request.form.get('latitude', '').strip()
        lng         = request.form.get('longitude', '').strip()
        loc_name    = request.form.get('location_name', '').strip()

        # --- Validation ---
        if not category:
            flash('Please select an incident category.', 'danger')
            return redirect(url_for('report_incident'))
        if not description:
            flash('Description is required.', 'danger')
            return redirect(url_for('report_incident'))
        if not lat or not lng:
            flash('Please pin the incident location on the map.', 'danger')
            return redirect(url_for('report_incident'))

        # Image is mandatory
        if 'image' not in request.files or not request.files['image'].filename:
            flash('A photo of the incident is required.', 'danger')
            return redirect(url_for('report_incident'))

        file = request.files['image']
        if not allowed_file(file.filename):
            flash('Invalid image type. Allowed: PNG, JPG, JPEG, GIF.', 'danger')
            return redirect(url_for('report_incident'))

        filename = secure_filename(f"{datetime.now().timestamp()}_{file.filename}")
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        image_path = f"images/uploads/{filename}"

        # Derive district from GPS — no manual dropdown needed
        district = reverse_geocode_district(float(lat), float(lng))

        cat_label    = dict(INCIDENT_CATEGORIES).get(category, category.title())
        department   = get_responsible_department(category)
        is_emergency = classifier.is_emergency(category)

        incident = Incident(
            title=cat_label,
            description=description,
            category=category,
            latitude=float(lat),
            longitude=float(lng),
            location_name=loc_name,
            district=district,
            department=department,
            image_path=image_path,
            user_id=current_user.id,
            is_emergency=is_emergency,
        )
        db.session.add(incident)
        db.session.commit()

        create_incident_notifications(incident)

        if is_emergency:
            flash('🚨 EMERGENCY INCIDENT REPORTED! Relevant authorities have been notified.', 'danger')
        else:
            flash(f'Incident reported and routed to {department} ({district or "district TBD"}).', 'success')

        return redirect(url_for('dashboard'))

    return render_template('report_incident.html',
                           categories=INCIDENT_CATEGORIES,
                           districts=MALAWI_DISTRICTS)

@app.route('/view-incident/<int:incident_id>')
def view_incident(incident_id):
    incident = Incident.query.get_or_404(incident_id)
    return render_template('view_incident.html', incident=incident)

# ----------------------------------------------------------------------
# Admin Routes
# ----------------------------------------------------------------------
@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    # Admins only see incidents relevant to their district/department
    query = Incident.query
    if current_user.district:
        query = query.filter(
            db.or_(Incident.district == current_user.district, Incident.district == None)
        )
    if current_user.department:
        query = query.filter(
            db.or_(Incident.department == current_user.department, Incident.department == None)
        )

    all_inc  = query.all()
    total    = len(all_inc)
    pending  = sum(1 for i in all_inc if i.status == 'pending')
    verified = sum(1 for i in all_inc if i.status == 'verified')
    resolved = sum(1 for i in all_inc if i.status == 'resolved')
    recent   = query.order_by(Incident.created_at.desc()).limit(10).all()

    emergency_count    = sum(1 for i in all_inc if i.is_emergency)
    active_emergencies = sum(1 for i in all_inc if i.is_emergency and i.status != 'resolved')
    emergency_incidents = [i for i in all_inc if i.is_emergency][:5]

    users_count = User.query.count()
    unread_notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()

    return render_template('admin_dashboard.html',
                           total_incidents=total, pending_incidents=pending,
                           verified_incidents=verified, resolved_incidents=resolved,
                           total_users=users_count,
                           recent_incidents=recent,
                           unread_notifications=unread_notifications,
                           emergency_count=emergency_count,
                           active_emergencies=active_emergencies,
                           emergency_incidents=emergency_incidents)

@app.route('/admin/incidents')
@login_required
@admin_required
def view_incidents():
    query = Incident.query
    if current_user.district:
        query = query.filter(
            db.or_(Incident.district == current_user.district, Incident.district == None)
        )
    if current_user.department:
        query = query.filter(
            db.or_(Incident.department == current_user.department, Incident.department == None)
        )
    incidents = query.order_by(Incident.created_at.desc()).all()
    return render_template('view_incidents.html', incidents=incidents)

@app.route('/admin/users')
@login_required
@admin_required
def view_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('view_users.html',
                           users=users,
                           districts=MALAWI_DISTRICTS,
                           departments=DEPARTMENTS)


@app.route('/admin/users/<int:user_id>/edit', methods=['POST'])
@login_required
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)

    # Regular admins can only edit citizens; super_admin can edit anyone except other super_admins
    if current_user.role != 'super_admin':
        if user.role != 'citizen':
            return jsonify({'success': False, 'error': 'You can only edit citizen accounts.'}), 403
    else:
        if user.role == 'super_admin' and user.id != current_user.id:
            return jsonify({'success': False, 'error': 'Cannot edit another super admin.'}), 403

    data = request.get_json()
    if 'username' in data and data['username'].strip():
        existing = User.query.filter_by(username=data['username'].strip()).first()
        if existing and existing.id != user.id:
            return jsonify({'success': False, 'error': 'Username already taken.'})
        user.username = data['username'].strip()

    if 'email' in data and data['email'].strip():
        existing = User.query.filter_by(email=data['email'].strip()).first()
        if existing and existing.id != user.id:
            return jsonify({'success': False, 'error': 'Email already in use.'})
        user.email = data['email'].strip()

    if current_user.role == 'super_admin':
        if 'role' in data and data['role'] in ('citizen', 'admin'):
            user.role = data['role']
        if 'district' in data:
            user.district = data['district'].strip() or None
        if 'department' in data:
            user.department = data['department'].strip() or None
        if 'account_status' in data and data['account_status'] in ('active', 'pending_approval', 'rejected'):
            user.account_status = data['account_status']

    db.session.commit()
    return jsonify({'success': True, 'message': f'User {user.username} updated.'})


@app.route('/admin/users/<int:user_id>/reset-password', methods=['POST'])
@login_required
@admin_required
def reset_user_password(user_id):
    user = User.query.get_or_404(user_id)

    if current_user.role != 'super_admin':
        if user.role != 'citizen':
            return jsonify({'success': False, 'error': 'You can only reset passwords for citizen accounts.'}), 403

    data = request.get_json()
    new_password = data.get('password', '').strip()
    if len(new_password) < 6:
        return jsonify({'success': False, 'error': 'Password must be at least 6 characters.'})

    user.password_hash = generate_password_hash(new_password)
    db.session.commit()
    return jsonify({'success': True, 'message': f'Password for {user.username} has been reset.'})


@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)

    if user.id == current_user.id:
        return jsonify({'success': False, 'error': 'You cannot delete your own account.'}), 400
    if user.role == 'super_admin':
        return jsonify({'success': False, 'error': 'Super admin accounts cannot be deleted.'}), 403
    if current_user.role != 'super_admin' and user.role != 'citizen':
        return jsonify({'success': False, 'error': 'You can only delete citizen accounts.'}), 403

    # Anonymise incidents rather than cascade-delete them (preserve audit trail)
    for inc in user.incidents:
        inc.user_id = current_user.id  # re-assign to acting admin as placeholder
    Notification.query.filter_by(user_id=user.id).delete()

    db.session.delete(user)
    db.session.commit()
    return jsonify({'success': True, 'message': f'User {user.username} deleted.'})


@app.route('/admin/users/<int:user_id>/approve', methods=['POST'])
@login_required
@admin_required
def approve_admin_user(user_id):
    """Approve a pending admin — available to both super_admin and regular admins."""
    user = User.query.get_or_404(user_id)
    if user.role != 'admin' or user.account_status != 'pending_approval':
        return jsonify({'success': False, 'error': 'User is not a pending admin.'})
    user.account_status = 'active'
    user.approved_by    = current_user.id
    user.rejection_reason = None
    db.session.commit()
    return jsonify({'success': True, 'message': f'{user.username} approved.'})


@app.route('/admin/users/<int:user_id>/reject', methods=['POST'])
@login_required
@admin_required
def reject_admin_user(user_id):
    """Reject a pending admin — available to both super_admin and regular admins."""
    user = User.query.get_or_404(user_id)
    if user.role != 'admin':
        return jsonify({'success': False, 'error': 'User is not an admin applicant.'})
    data = request.get_json()
    user.account_status   = 'rejected'
    user.rejection_reason = data.get('reason', 'No reason provided.')
    db.session.commit()
    return jsonify({'success': True, 'message': f'{user.username} rejected.'})


@app.route('/admin/train', methods=['GET', 'POST'])
@login_required
@admin_required
def train_classifier():
    if request.method == 'POST':
        flash('Training example received (not persisted in this simplified version)', 'info')
        return redirect(url_for('train_classifier'))
    return render_template('train_classifier.html', keyword_summary={
        cat: kw['en'] + kw['ny'] for cat, kw in classifier.categories.items()
    })

@app.route('/admin/email-settings', methods=['GET', 'POST'])
@login_required
@admin_required
def email_settings():
    """Allow admins to configure SMTP settings at runtime without restarting."""
    if request.method == 'POST':
        app.config['MAIL_SERVER']   = request.form.get('mail_server', '').strip()
        app.config['MAIL_PORT']     = int(request.form.get('mail_port', 587))
        app.config['MAIL_USE_TLS']  = request.form.get('mail_use_tls') == 'on'
        app.config['MAIL_USE_SSL']  = request.form.get('mail_use_ssl') == 'on'
        app.config['MAIL_USERNAME'] = request.form.get('mail_username', '').strip()
        if request.form.get('mail_password'):          # only update if a new password was entered
            app.config['MAIL_PASSWORD'] = request.form['mail_password']
        app.config['MAIL_DEFAULT_SENDER'] = request.form.get('mail_sender', '').strip()

        # Re-initialise Flask-Mail with the new settings
        mail.init_app(app)
        flash('Email settings updated successfully.', 'success')
        return redirect(url_for('email_settings'))

    return render_template('email_settings.html',
                           mail_server=app.config.get('MAIL_SERVER', ''),
                           mail_port=app.config.get('MAIL_PORT', 587),
                           mail_use_tls=app.config.get('MAIL_USE_TLS', True),
                           mail_use_ssl=app.config.get('MAIL_USE_SSL', False),
                           mail_username=app.config.get('MAIL_USERNAME', ''),
                           mail_sender=app.config.get('MAIL_DEFAULT_SENDER', ''),
                           email_configured=bool(app.config.get('MAIL_USERNAME')))


@app.route('/admin/email-settings/test', methods=['POST'])
@login_required
@admin_required
def test_email():
    """Send a test email to the currently logged-in admin."""
    if not app.config.get('MAIL_USERNAME'):
        return jsonify({'success': False, 'error': 'Email is not configured yet. Please save settings first.'})
    try:
        msg = Message(
            subject="✅ ecoWatch — Test Email",
            recipients=[current_user.email],
            body=(
                "This is a test email from your ecoWatch Environmental Monitoring System.\n\n"
                "If you received this, your email alert configuration is working correctly.\n\n"
                "Emergency incident alerts will be sent to the relevant district/department admins automatically."
            ),
            html=render_template('email/test_email.html', admin_name=current_user.username),
        )
        mail.send(msg)
        return jsonify({'success': True, 'message': f'Test email sent to {current_user.email}'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/admin/notifications')
@login_required
@admin_required
def view_notifications():
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).all()
    return render_template('notifications.html', notifications=notifications)

@app.route('/admin/notifications/mark-read/<int:notification_id>')
@login_required
@admin_required
def mark_notification_read(notification_id):
    notification = Notification.query.get_or_404(notification_id)
    if notification.user_id != current_user.id:
        flash('Access denied', 'danger')
        return redirect(url_for('admin_dashboard'))
    notification.is_read = True
    db.session.commit()
    return redirect(request.referrer or url_for('view_notifications'))

@app.route('/admin/notifications/mark-all-read')
@login_required
@admin_required
def mark_all_notifications_read():
    Notification.query.filter_by(user_id=current_user.id, is_read=False).update({'is_read': True})
    db.session.commit()
    flash('All notifications marked as read', 'success')
    return redirect(request.referrer or url_for('admin_dashboard'))

@app.route('/admin/emergencies')
@login_required
@admin_required
def view_emergencies():
    query = Incident.query.filter_by(is_emergency=True)
    if current_user.district:
        query = query.filter(
            db.or_(Incident.district == current_user.district, Incident.district == None)
        )
    if current_user.department:
        query = query.filter(
            db.or_(Incident.department == current_user.department, Incident.department == None)
        )
    emergencies = query.order_by(Incident.created_at.desc()).all()
    return render_template('emergencies.html', emergencies=emergencies)

# ----------------------------------------------------------------------
# Map and Public Data
# ----------------------------------------------------------------------
@app.route('/map')
def map_view():
    incidents = Incident.query.all()
    incident_list = []
    for inc in incidents:
        if inc.latitude and inc.longitude:
            incident_list.append({
                'id': inc.id, 'title': inc.title,
                'description': inc.description[:100] + '...',
                'category': inc.category or 'Uncategorized',
                'latitude': inc.latitude, 'longitude': inc.longitude,
                'status': inc.status,
                'reporter': inc.reporter.username if inc.reporter else 'Anonymous',
                'created_at': inc.created_at.strftime('%Y-%m-%d'),
                'image_url': url_for('static', filename=inc.image_path) if inc.image_path else None,
                'is_emergency': inc.is_emergency,
                'district': inc.district, 'department': inc.department,
            })
    categories = list({inc.category for inc in incidents if inc.category})
    stats = {
        'total':    len(incident_list),
        'pending':  sum(1 for i in incident_list if i['status'] == 'pending'),
        'verified': sum(1 for i in incident_list if i['status'] == 'verified'),
        'resolved': sum(1 for i in incident_list if i['status'] == 'resolved'),
    }
    return render_template('map_view.html', incidents=incident_list, categories=categories,
                           stats=stats, incidents_json=json.dumps(incident_list))

@app.route('/api/map-data')
def get_map_data():
    query = Incident.query
    category = request.args.get('category')
    status   = request.args.get('status')
    date     = request.args.get('date')
    if category and category != 'all':
        query = query.filter_by(category=category)
    if status and status != 'all':
        query = query.filter_by(status=status)
    if date and date != 'all':
        now = datetime.utcnow()
        if date == 'today':
            query = query.filter(db.func.date(Incident.created_at) == now.date())
        elif date == 'week':
            query = query.filter(Incident.created_at >= now - timedelta(days=7))
        elif date == 'month':
            query = query.filter(Incident.created_at >= now - timedelta(days=30))
    data = []
    for inc in query.all():
        if inc.latitude and inc.longitude:
            data.append({
                'id': inc.id, 'title': inc.title,
                'description': inc.description[:100],
                'category': inc.category, 'latitude': inc.latitude,
                'longitude': inc.longitude, 'status': inc.status,
                'reporter': inc.reporter.username if inc.reporter else 'Anonymous',
                'created_at': inc.created_at.strftime('%Y-%m-%d'),
                'image_url': url_for('static', filename=inc.image_path) if inc.image_path else None,
                'is_emergency': inc.is_emergency,
                'district': inc.district, 'department': inc.department,
            })
    return jsonify({'incidents': data})

# ----------------------------------------------------------------------
# API Endpoints (Admin actions)
# ----------------------------------------------------------------------
@app.route('/api/incident/<int:id>/status', methods=['POST'])
@login_required
@admin_required
def update_status(id):
    incident = Incident.query.get_or_404(id)
    data = request.get_json()
    if data.get('status') in ['pending', 'verified', 'resolved', 'rejected']:
        incident.status = data['status']
        incident.verified_by = current_user.id
        db.session.commit()
        return jsonify({'success': True})
    return jsonify({'error': 'Invalid status'}), 400

@app.route('/api/incident/<int:id>', methods=['DELETE'])
@login_required
@admin_required
def delete_incident(id):
    incident = Incident.query.get_or_404(id)
    if incident.image_path:
        try:
            path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(incident.image_path))
            if os.path.exists(path):
                os.remove(path)
        except:
            pass
    db.session.delete(incident)
    db.session.commit()
    return jsonify({'success': True})

# ----------------------------------------------------------------------
# Analytics
# ----------------------------------------------------------------------
@app.route('/analytics')
@login_required
@admin_required
def analytics_dashboard():
    categories = list({c[0] for c in db.session.query(Incident.category).distinct() if c[0]})
    districts  = list({d[0] for d in db.session.query(Incident.location_name).distinct() if d[0]})
    end   = datetime.now().date()
    start = end - timedelta(days=30)
    return render_template('analytics.html', categories=categories, districts=districts,
                           default_start_date=start.strftime('%Y-%m-%d'),
                           default_end_date=end.strftime('%Y-%m-%d'))

@app.route('/api/analytics')
@login_required
@admin_required
def get_analytics():
    start = request.args.get('start_date')
    end   = request.args.get('end_date')
    query = Incident.query
    if current_user.district:
        query = query.filter(
            db.or_(Incident.district == current_user.district, Incident.district == None)
        )
    if current_user.department:
        query = query.filter(
            db.or_(Incident.department == current_user.department, Incident.department == None)
        )
    if start:
        query = query.filter(Incident.created_at >= datetime.strptime(start, '%Y-%m-%d'))
    if end:
        query = query.filter(Incident.created_at <= datetime.strptime(end, '%Y-%m-%d') + timedelta(days=1))
    incidents = query.all()

    cat_counts = {}
    for inc in incidents:
        cat = inc.category or 'Uncategorized'
        cat_counts[cat] = cat_counts.get(cat, 0) + 1
    category_chart = {'labels': list(cat_counts.keys()), 'values': list(cat_counts.values())}

    monthly = {}
    for inc in incidents:
        month = inc.created_at.strftime('%Y-%m')
        monthly[month] = monthly.get(month, 0) + 1
    sorted_months = sorted(monthly.keys())[-6:]
    monthly_chart = {'labels': sorted_months, 'values': [monthly[m] for m in sorted_months]}

    dist_counts = {}
    for inc in incidents:
        d = inc.district or inc.location_name or 'Unknown'
        dist_counts[d] = dist_counts.get(d, 0) + 1
    top_districts = sorted(dist_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    district_chart = {'labels': [d[0] for d in top_districts], 'values': [d[1] for d in top_districts]}

    response_times = []
    for inc in incidents:
        if inc.status == 'resolved' and inc.updated_at and inc.created_at:
            delta = (inc.updated_at - inc.created_at).total_seconds() / 3600
            response_times.append(delta)
    avg_response = round(sum(response_times) / len(response_times), 1) if response_times else 0

    metrics = {
        'total_incidents':  len(incidents),
        'resolved_incidents': sum(1 for i in incidents if i.status == 'resolved'),
        'pending_incidents':  sum(1 for i in incidents if i.status == 'pending'),
        'avg_response_time':  f"{avg_response}h",
        'active_users': len({i.user_id for i in incidents}),
    }

    table_data = []
    for inc in incidents[:50]:
        table_data.append({
            'id': inc.id, 'title': inc.title,
            'category': inc.category, 'status': inc.status,
            'district': inc.district or inc.location_name,
            'department': inc.department,
            'reporter': inc.reporter.username if inc.reporter else 'Anonymous',
            'created_at': inc.created_at.strftime('%Y-%m-%d %H:%M'),
            'response_time': f"{round((inc.updated_at - inc.created_at).total_seconds()/3600, 1)}h"
                if inc.status == 'resolved' and inc.updated_at else 'N/A'
        })

    return jsonify({
        'metrics': metrics,
        'charts': {
            'category_distribution': category_chart,
            'monthly_trend': monthly_chart,
            'district_distribution': district_chart,
            'response_time': {'average': f"{avg_response}h"}
        },
        'incidents': table_data
    })

# ----------------------------------------------------------------------
# Export
# ----------------------------------------------------------------------
@app.route('/api/analytics/export', methods=['POST'])
@login_required
@admin_required
def export_analytics():
    data  = request.json
    start = data.get('filters', {}).get('start_date')
    end   = data.get('filters', {}).get('end_date')
    query = Incident.query
    if start:
        query = query.filter(Incident.created_at >= datetime.strptime(start, '%Y-%m-%d'))
    if end:
        query = query.filter(Incident.created_at <= datetime.strptime(end, '%Y-%m-%d') + timedelta(days=1))
    incidents = query.all()

    if data.get('format') == 'pdf':
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib import colors

        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        elements = [Paragraph("Environmental Incidents Report", getSampleStyleSheet()['Title']), Spacer(1, 12)]
        summary_data = [
            ['Metric', 'Value'],
            ['Total Incidents', str(len(incidents))],
            ['Resolved', str(sum(1 for i in incidents if i.status == 'resolved'))],
            ['Pending', str(sum(1 for i in incidents if i.status == 'pending'))],
        ]
        t = Table(summary_data)
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.green),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        elements.append(t)
        doc.build(elements)
        buffer.seek(0)
        return send_file(buffer, as_attachment=True,
                         download_name=f'report_{datetime.now().strftime("%Y%m%d")}.pdf',
                         mimetype='application/pdf')
    else:
        si = StringIO()
        cw = csv.writer(si)
        cw.writerow(['ID', 'Title', 'Category', 'Status', 'District', 'Department', 'Reporter', 'Date', 'Response Time'])
        for inc in incidents:
            cw.writerow([
                inc.id, inc.title, inc.category, inc.status,
                inc.district or inc.location_name,
                inc.department,
                inc.reporter.username if inc.reporter else 'Anonymous',
                inc.created_at.strftime('%Y-%m-%d'),
                f"{round((inc.updated_at - inc.created_at).total_seconds()/3600, 1)}h"
                if inc.status == 'resolved' and inc.updated_at else 'N/A'
            ])
        output = si.getvalue().encode()
        return send_file(BytesIO(output), as_attachment=True,
                         download_name=f'report_{datetime.now().strftime("%Y%m%d")}.csv',
                         mimetype='text/csv')

@app.route('/offline')
def offline():
    return render_template('offline.html')

# ----------------------------------------------------------------------
# Mobile API v1  (used by the Flutter app)
# All routes return JSON. Session cookie auth via Flask-Login.
# ----------------------------------------------------------------------

def mobile_login_required(f):
    """Like login_required but returns 401 JSON instead of redirecting."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        return f(*args, **kwargs)
    return decorated


def mobile_admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        if current_user.role not in ('admin', 'super_admin'):
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated


def user_to_dict(u):
    return {
        'id':             u.id,
        'username':       u.username,
        'email':          u.email,
        'role':           u.role,
        'district':       u.district,
        'department':     u.department,
        'account_status': u.account_status,
        'display_role':   u.display_role,
        'created_at':     u.created_at.isoformat(),
    }


def incident_to_dict(inc):
    return {
        'id':            inc.id,
        'title':         inc.title,
        'description':   inc.description,
        'category':      inc.category,
        'latitude':      inc.latitude,
        'longitude':     inc.longitude,
        'location_name': inc.location_name,
        'district':      inc.district,
        'department':    inc.department,
        'status':        inc.status,
        'is_emergency':  inc.is_emergency,
        'image_url':     f"https://ems-project-0rck.onrender.com/static/{inc.image_path}" if inc.image_path else None,
        'reporter':      inc.reporter.username if inc.reporter else 'Unknown',
        'reporter_id':   inc.user_id,
        'created_at':    inc.created_at.isoformat(),
        'updated_at':    inc.updated_at.isoformat() if inc.updated_at else None,
    }


# ── Auth ──────────────────────────────────────────────────────────────

@app.route('/api/v1/login', methods=['POST'])
def api_login():
    data = request.get_json() or {}
    user = User.query.filter_by(email=data.get('email', '')).first()
    if not user or not check_password_hash(user.password_hash, data.get('password', '')):
        return jsonify({'success': False, 'error': 'Invalid email or password'}), 401
    if not user.is_active:
        msg = {
            'pending_approval': 'Your account is pending approval by the administrator.',
            'rejected':         f'Your account has been rejected. Reason: {user.rejection_reason or "Contact admin."}',
        }.get(user.account_status, 'Account inactive.')
        return jsonify({'success': False, 'error': msg}), 403
    login_user(user, remember=True)
    return jsonify({'success': True, 'user': user_to_dict(user)})


@app.route('/api/v1/logout', methods=['POST'])
@mobile_login_required
def api_logout():
    logout_user()
    return jsonify({'success': True})


@app.route('/api/v1/me', methods=['GET'])
@mobile_login_required
def api_me():
    return jsonify({'success': True, 'user': user_to_dict(current_user)})


@app.route('/api/v1/register', methods=['POST'])
def api_register():
    # Handles multipart (admin with ID doc) or JSON (citizen)
    if request.content_type and 'multipart' in request.content_type:
        data = request.form
    else:
        data = request.get_json() or {}

    role       = data.get('role', 'citizen')
    username   = data.get('username', '').strip()
    email      = data.get('email', '').strip()
    password   = data.get('password', '')
    district   = data.get('district', '').strip() if role == 'admin' else None
    department = data.get('department', '').strip() if role == 'admin' else None

    if not username or not email or not password:
        return jsonify({'success': False, 'error': 'Username, email and password are required'}), 400
    if len(password) < 6:
        return jsonify({'success': False, 'error': 'Password must be at least 6 characters'}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'success': False, 'error': 'Email already registered'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'success': False, 'error': 'Username already taken'}), 400
    if role == 'admin':
        if not district:
            return jsonify({'success': False, 'error': 'District is required for admin accounts'}), 400
        if not department:
            return jsonify({'success': False, 'error': 'Department is required for admin accounts'}), 400

    id_doc_path = None
    if role == 'admin' and 'id_document' in request.files:
        id_file = request.files['id_document']
        if id_file and id_file.filename:
            id_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'id_documents')
            os.makedirs(id_dir, exist_ok=True)
            id_filename = secure_filename(f"id_{username}_{datetime.now().timestamp()}_{id_file.filename}")
            id_file.save(os.path.join(id_dir, id_filename))
            id_doc_path = f"images/uploads/id_documents/{id_filename}"

    user = User(
        username=username, email=email,
        password_hash=generate_password_hash(password),
        role=role,
        district=district or None,
        department=department or None,
        account_status='pending_approval' if role == 'admin' else 'active',
        id_document_path=id_doc_path,
    )
    db.session.add(user)
    db.session.commit()

    if role == 'admin':
        for sa in User.query.filter_by(role='super_admin', account_status='active').all():
            db.session.add(Notification(
                user_id=sa.id, incident_id=1,
                message=f"📋 New admin registration: {username} ({department}, {district})"
            ))
        db.session.commit()
        return jsonify({'success': True, 'message': 'Application submitted. Awaiting admin approval.'})

    return jsonify({'success': True, 'message': 'Account created. You can now log in.'})


# ── Incidents ─────────────────────────────────────────────────────────

@app.route('/api/v1/incidents', methods=['GET'])
@mobile_login_required
def api_incidents():
    """Citizens get their own; admins get their scoped incidents."""
    if current_user.role == 'citizen':
        incidents = Incident.query.filter_by(user_id=current_user.id).order_by(Incident.created_at.desc()).all()
    else:
        q = Incident.query
        if current_user.district and current_user.role != 'super_admin':
            q = q.filter(db.or_(Incident.district == current_user.district, Incident.district == None))
        if current_user.department and current_user.role != 'super_admin':
            q = q.filter(db.or_(Incident.department == current_user.department, Incident.department == None))
        incidents = q.order_by(Incident.created_at.desc()).all()
    return jsonify({'success': True, 'incidents': [incident_to_dict(i) for i in incidents]})


@app.route('/api/v1/incidents/<int:incident_id>', methods=['GET'])
@mobile_login_required
def api_incident_detail(incident_id):
    inc = Incident.query.get_or_404(incident_id)
    return jsonify({'success': True, 'incident': incident_to_dict(inc)})


@app.route('/api/v1/incidents', methods=['POST'])
@mobile_login_required
def api_create_incident():
    category    = request.form.get('category', '').strip()
    description = request.form.get('description', '').strip()
    lat         = request.form.get('latitude', '').strip()
    lng         = request.form.get('longitude', '').strip()
    loc_name    = request.form.get('location_name', '').strip()

    if not category:
        return jsonify({'success': False, 'error': 'Category is required'}), 400
    if not description:
        return jsonify({'success': False, 'error': 'Description is required'}), 400
    if not lat or not lng:
        return jsonify({'success': False, 'error': 'Location coordinates are required'}), 400
    if 'image' not in request.files or not request.files['image'].filename:
        return jsonify({'success': False, 'error': 'A photo is required'}), 400

    file = request.files['image']
    filename = secure_filename(f"{datetime.now().timestamp()}_{file.filename}")
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    image_path = f"images/uploads/{filename}"

    district     = reverse_geocode_district(float(lat), float(lng))
    cat_label    = dict(INCIDENT_CATEGORIES).get(category, category.title())
    department   = get_responsible_department(category)
    is_emergency = classifier.is_emergency(category)

    incident = Incident(
        title=cat_label, description=description, category=category,
        latitude=float(lat), longitude=float(lng),
        location_name=loc_name, district=district,
        department=department, image_path=image_path,
        user_id=current_user.id, is_emergency=is_emergency,
    )
    db.session.add(incident)
    db.session.commit()
    create_incident_notifications(incident)

    return jsonify({'success': True, 'incident': incident_to_dict(incident),
                    'message': '🚨 Emergency reported!' if is_emergency else f'Reported to {department}.'})


@app.route('/api/v1/incidents/<int:incident_id>/status', methods=['POST'])
@mobile_admin_required
def api_update_incident_status(incident_id):
    inc  = Incident.query.get_or_404(incident_id)
    data = request.get_json() or {}
    if data.get('status') not in ('pending', 'verified', 'resolved', 'rejected'):
        return jsonify({'success': False, 'error': 'Invalid status'}), 400
    inc.status      = data['status']
    inc.verified_by = current_user.id
    db.session.commit()
    return jsonify({'success': True, 'incident': incident_to_dict(inc)})


# ── Notifications ─────────────────────────────────────────────────────

@app.route('/api/v1/notifications', methods=['GET'])
@mobile_login_required
def api_notifications():
    notifs = Notification.query.filter_by(user_id=current_user.id)\
                               .order_by(Notification.created_at.desc()).limit(50).all()
    data = [{
        'id':          n.id,
        'message':     n.message,
        'is_read':     n.is_read,
        'incident_id': n.incident_id,
        'created_at':  n.created_at.isoformat(),
    } for n in notifs]
    unread = sum(1 for n in notifs if not n.is_read)
    return jsonify({'success': True, 'notifications': data, 'unread_count': unread})


@app.route('/api/v1/notifications/<int:notif_id>/read', methods=['POST'])
@mobile_login_required
def api_mark_notification_read(notif_id):
    n = Notification.query.get_or_404(notif_id)
    if n.user_id != current_user.id:
        return jsonify({'success': False, 'error': 'Forbidden'}), 403
    n.is_read = True
    db.session.commit()
    return jsonify({'success': True})


@app.route('/api/v1/notifications/read-all', methods=['POST'])
@mobile_login_required
def api_mark_all_read():
    Notification.query.filter_by(user_id=current_user.id, is_read=False).update({'is_read': True})
    db.session.commit()
    return jsonify({'success': True})


# ── Dashboard stats ───────────────────────────────────────────────────

@app.route('/api/v1/dashboard/stats', methods=['GET'])
@mobile_login_required
def api_dashboard_stats():
    if current_user.role == 'citizen':
        incidents = Incident.query.filter_by(user_id=current_user.id).all()
        return jsonify({'success': True, 'stats': {
            'total':    len(incidents),
            'pending':  sum(1 for i in incidents if i.status == 'pending'),
            'verified': sum(1 for i in incidents if i.status == 'verified'),
            'resolved': sum(1 for i in incidents if i.status == 'resolved'),
        }})
    # Admin
    q = Incident.query
    if current_user.role != 'super_admin':
        if current_user.district:
            q = q.filter(db.or_(Incident.district == current_user.district, Incident.district == None))
        if current_user.department:
            q = q.filter(db.or_(Incident.department == current_user.department, Incident.department == None))
    incidents = q.all()
    unread = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    pending_admins_count = User.query.filter_by(role='admin', account_status='pending_approval').count()
    return jsonify({'success': True, 'stats': {
        'total':              len(incidents),
        'pending':            sum(1 for i in incidents if i.status == 'pending'),
        'verified':           sum(1 for i in incidents if i.status == 'verified'),
        'resolved':           sum(1 for i in incidents if i.status == 'resolved'),
        'emergencies':        sum(1 for i in incidents if i.is_emergency and i.status != 'resolved'),
        'unread_notifications': unread,
        'pending_admins':     pending_admins_count,
    }})


# ── Map data (public) ─────────────────────────────────────────────────

@app.route('/api/v1/map', methods=['GET'])
def api_map_data():
    incidents = Incident.query.filter(
        Incident.latitude != None, Incident.longitude != None
    ).order_by(Incident.created_at.desc()).all()
    return jsonify({'success': True, 'incidents': [incident_to_dict(i) for i in incidents]})


# ── Categories & districts (reference data) ───────────────────────────

@app.route('/api/v1/reference', methods=['GET'])
def api_reference():
    return jsonify({
        'success':    True,
        'categories': [{'value': v, 'label': l} for v, l in INCIDENT_CATEGORIES],
        'districts':  MALAWI_DISTRICTS,
        'departments': DEPARTMENTS,
        'category_department_map': CATEGORY_DEPARTMENT_MAP,
    })


# ----------------------------------------------------------------------
# Error Handlers
# ----------------------------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    db.session.rollback()
    return render_template('500.html'), 500

# ----------------------------------------------------------------------
# Application Entry Point
# ----------------------------------------------------------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        # Super admin — full system oversight, approves/rejects admin registrations
        if not User.query.filter_by(email='superadmin@env.com').first():
            sa = User(
                username='superadmin', email='superadmin@env.com',
                password_hash=generate_password_hash('superadmin123'),
                role='super_admin', account_status='active',
            )
            db.session.add(sa)
            print("Super admin created: superadmin@env.com / superadmin123")

        if not User.query.filter_by(email='admin@env.com').first():
            admin = User(
                username='admin', email='admin@env.com',
                password_hash=generate_password_hash('admin123'),
                role='admin', district='Lilongwe', department='General Administration',
                account_status='active',
            )
            db.session.add(admin)
            print("Admin created: admin@env.com / admin123")

        if not User.query.filter_by(email='sanitation@env.com').first():
            db.session.add(User(
                username='sanitation_admin', email='sanitation@env.com',
                password_hash=generate_password_hash('admin123'),
                role='admin', district='Blantyre', department='Sanitation',
                account_status='active',
            ))

        if not User.query.filter_by(email='forestry@env.com').first():
            db.session.add(User(
                username='forestry_admin', email='forestry@env.com',
                password_hash=generate_password_hash('admin123'),
                role='admin', district='Lilongwe', department='Forestry',
                account_status='active',
            ))

        if not User.query.filter_by(email='citizen@env.com').first():
            db.session.add(User(
                username='citizen', email='citizen@env.com',
                password_hash=generate_password_hash('citizen123'),
                role='citizen', account_status='active',
            ))

        db.session.commit()
    app.run(debug=True, port=5000)
    # Runs on every startup — gunicorn and local alike
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(email='superadmin@env.com').first():
            db.session.add(User(
                username='superadmin', email='superadmin@env.com',
                password_hash=generate_password_hash('superadmin123'),
                role='super_admin', account_status='active',
            ))
        if not User.query.filter_by(email='admin@env.com').first():
            db.session.add(User(
                username='admin', email='admin@env.com',
                password_hash=generate_password_hash('admin123'),
                role='admin', district='Lilongwe', department='General Administration',
                account_status='active',
            ))
        if not User.query.filter_by(email='citizen@env.com').first():
            db.session.add(User(
                username='citizen', email='citizen@env.com',
                password_hash=generate_password_hash('citizen123'),
                role='citizen', account_status='active',
            ))
        db.session.commit()

    if __name__ == '__main__':
        app.run(debug=True, port=5000)