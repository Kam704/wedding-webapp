import os
import re
import secrets
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import quote_plus
import ipaddress

import bcrypt
import sqlite3
from dotenv import load_dotenv, find_dotenv
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, Response, abort, has_request_context, g, send_from_directory
)
from flask_wtf import CSRFProtect
from markupsafe import Markup, escape

# -----------------------
# Load configuration
# -----------------------
# Wczytuje zmienne środowiskowe z pliku .env (jeśli istnieje)
# Force loading values from .env even if environment variables are already set
load_dotenv(find_dotenv(), override=True)

# dotenv loaded above; no debug prints here

# Konfiguracja pobrana z .env lub wartości domyślne
SECRET_KEY = os.getenv("SECRET_KEY", "zmien_to_natychmiast")
LOGIN_PASSWORD = os.getenv("INVITE_PASSWORD", "haslo")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "adminhaslo")
INVITE_PASSWORD_HASH = os.getenv("INVITE_PASSWORD_HASH")
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH")
DATABASE = os.getenv("DATABASE", "rsvp.db")
SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"
SESSION_LIFETIME_MINUTES = int(os.getenv("SESSION_LIFETIME_MINUTES", "120"))
ADMIN_IP_ALLOWLIST = (os.getenv("ADMIN_IP_ALLOWLIST", "") or "").strip()

# -----------------------
# Flask init
# -----------------------
app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=SESSION_COOKIE_SECURE,
    WTF_CSRF_TIME_LIMIT=60 * 60 * 2,  # 2 hours
)
app.permanent_session_lifetime = timedelta(minutes=SESSION_LIFETIME_MINUTES)
csrf = CSRFProtect(app)

EMAIL_PATTERN = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_DIGIT_PATTERN = re.compile(r"[0-9]")
PHONE_SUBSTRING_PATTERN = re.compile(r"\+?\d[\d\s().-]{3,}\d")


@app.template_filter("linkify_email")
def linkify_email(value: str | None):
    """Convert email-like text fragments into safe mailto links."""
    if not value:
        return ""

    text = str(value)
    parts: list[Markup] = []
    last = 0

    for match in EMAIL_PATTERN.finditer(text):
        start, end = match.span()
        if start > last:
            parts.append(Markup(escape(text[last:start])))
        email = match.group(0)
        safe_email = escape(email)
        link = Markup(f'<a href="mailto:{safe_email}" class="text-decoration-none">{safe_email}</a>')
        parts.append(link)
        last = end

    if last < len(text):
        parts.append(Markup(escape(text[last:])))

    if not parts:
        return escape(text)

    return Markup('').join(parts)


@app.template_filter("tel_link")
def tel_link(value: str | None):
    if not value:
        return ""
    text = str(value).strip()
    if not text:
        return ""
    if not PHONE_DIGIT_PATTERN.search(text):
        return escape(text)

    selected_span: tuple[int, int] | None = None
    selected_text = ""
    for match in PHONE_SUBSTRING_PATTERN.finditer(text):
        candidate = match.group(0)
        digit_count = len(re.sub(r"\D", "", candidate))
        if digit_count >= 5:
            selected_span = match.span()
            selected_text = candidate
            break

    if not selected_span:
        selected_span = (0, len(text))
        selected_text = text

    digits = re.sub(r"[^0-9+]", "", selected_text)
    plain_digits = re.sub(r"\D", "", digits)
    if len(plain_digits) < 5:
        return escape(text)

    href = digits if digits.startswith('+') else plain_digits
    safe_href = escape(href)
    safe_number = escape(selected_text.strip() if selected_text.strip() else selected_text)
    link_markup = Markup(f'<a href="tel:{safe_href}" class="text-decoration-none">{safe_number}</a>')

    start, end = selected_span
    if start == 0 and end == len(text):
        return link_markup

    prefix = escape(text[:start]) if start > 0 else Markup("")
    suffix = escape(text[end:]) if end < len(text) else Markup("")
    return Markup("").join([prefix, link_markup, suffix])


@app.template_filter("copy_format")
def copy_format(value: str | None, **replacements):
    if not value:
        return ""
    text = str(value)
    result: list[Markup] = []
    idx = 0
    length = len(text)

    while idx < length:
        start = text.find('{', idx)
        if start == -1:
            result.append(Markup(escape(text[idx:])))
            break

        if start > idx:
            result.append(Markup(escape(text[idx:start])))

        end = text.find('}', start + 1)
        if end == -1:
            result.append(Markup(escape(text[start:])))
            idx = length
            break

        key = text[start + 1:end].strip()
        if key and key in replacements:
            replacement = replacements.get(key)
            if replacement is None:
                replacement = ""
            result.append(Markup(escape(replacement)))
        else:
            result.append(Markup(escape(text[start:end + 1])))
        idx = end + 1

    if not result:
        return escape(text)

    return Markup('').join(result)


def verify_secret(user_input: str, plain_secret: str, hashed_secret: str | None = None) -> bool:
    """Validate passwords via bcrypt hash (if provided) or constant-time compare."""
    if not user_input:
        return False
    if hashed_secret:
        try:
            return bcrypt.checkpw(user_input.encode("utf-8"), hashed_secret.encode("utf-8"))
        except ValueError:
            # Hash present but malformed; fall back to plain secret comparison
            pass
    return secrets.compare_digest(user_input, plain_secret)

# -----------------------
# Helper: DB init / connection
# -----------------------
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("logged"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not admin_ip_allowed():
            session.pop("admin", None)
            abort(403)
        if not session.get("admin"):
            return redirect(url_for("admin"))
        return f(*args, **kwargs)
    return wrapper

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    # Ensure base table exists (keeps backwards compatibility)
    c.execute("""
        CREATE TABLE IF NOT EXISTS rsvp (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            guest TEXT NOT NULL,
            vegetarian TEXT NOT NULL,
            contact_email TEXT,
            created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)

    # Add new columns for children if they don't exist yet (safe ALTER)
    c.execute("PRAGMA table_info(rsvp);")
    existing = [r[1] for r in c.fetchall()]
    if "children" not in existing:
        c.execute("ALTER TABLE rsvp ADD COLUMN children TEXT DEFAULT 'nie';")
    if "children_count" not in existing:
        c.execute("ALTER TABLE rsvp ADD COLUMN children_count INTEGER DEFAULT 0;")
    if "vegetarian_guest" not in existing:
        c.execute("ALTER TABLE rsvp ADD COLUMN vegetarian_guest TEXT DEFAULT 'nie';")
    if "children_veg_count" not in existing:
        c.execute("ALTER TABLE rsvp ADD COLUMN children_veg_count INTEGER DEFAULT 0;")
    if "first_name" not in existing:
        c.execute("ALTER TABLE rsvp ADD COLUMN first_name TEXT;")
    if "last_name" not in existing:
        c.execute("ALTER TABLE rsvp ADD COLUMN last_name TEXT;")
    if "invitation_id" not in existing:
        c.execute("ALTER TABLE rsvp ADD COLUMN invitation_id INTEGER;")
    if "attending" not in existing:
        c.execute("ALTER TABLE rsvp ADD COLUMN attending TEXT DEFAULT 'tak';")

    # simple settings table for storing small key/value pairs (locations etc.)
    c.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);")

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS invitations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE NOT NULL,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            allow_guest INTEGER DEFAULT 0,
            max_children INTEGER DEFAULT 0,
            notes TEXT
        );
        """
    )

    c.execute("PRAGMA table_info(invitations);")
    invitation_cols = [r[1] for r in c.fetchall()]
    if "guest_name" not in invitation_cols:
        c.execute("ALTER TABLE invitations ADD COLUMN guest_name TEXT;")

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS plan_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            subtitle TEXT,
            description TEXT,
            sort_order INTEGER DEFAULT 0
        );
        """
    )

    conn.commit()
    conn.close()

# Utwórz DB przy starcie jeśli nie istnieje
init_db()


def get_setting(key, default=None):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT value FROM settings WHERE key = ?", (key,))
    row = c.fetchone()
    conn.close()
    return row[0] if row and row[0] is not None else default


def set_setting(key, value):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
    conn.commit()
    conn.close()


INVITE_COPY_DEFAULTS = {
    "hero_eyebrow": "Zapraszamy na świętowanie",
    "hero_title": "Bądź z nami w tym dniu",
    "hero_lead": "Potwierdzenie zajmie minutę, a nam pozwoli dopiąć wszystkie szczegóły. Dziękujemy za wiadomość!",
    "info_pill_one": "Termin ustalisz w panelu",
    "info_pill_two": "Dress code: elegancki luz",
    "info_pill_three": "Masz pytanie? Napisz do nas",
    "info_pill_phone": "Zadzwoń: +48 000 000 000",
    "plan_title": "Plan dnia",
    "form_note": "Po wysłaniu zobaczysz potwierdzenie. Jeśli coś się zmieni, odezwij się do nas w każdej chwili.",
    "invite_page_title": "Zaproszenie — RSVP",
    "site_browser_title": "Wedding App",
    "site_nav_title": "Nasze zaproszenie",
    "site_footer_text": "Zaproszenie ślubne",
    "rsvp_section_eyebrow": "RSVP",
    "rsvp_section_title": "Formularz potwierdzenia",
    "rsvp_presence_label": "Czy będziesz z nami?",
    "rsvp_presence_yes": "Tak, będę",
    "rsvp_presence_no": "Niestety nie",
    "rsvp_guest_divider": "Osoba towarzysząca",
    "rsvp_guest_named_question": "Czy {guest_name} będzie obecny/a?",
    "rsvp_guest_named_yes": "Tak, {guest_name}",
    "rsvp_guest_named_no": "Nie, {guest_name} nie będzie",
    "rsvp_guest_select_label": "Osoba towarzysząca?",
    "rsvp_guest_select_yes": "Tak",
    "rsvp_guest_select_no": "Nie",
    "rsvp_guest_not_allowed": "To zaproszenie nie obejmuje osoby towarzyszącej.",
    "rsvp_guest_veg_label": "Dieta wegetariańska (gość)",
    "rsvp_self_veg_label": "Dieta wegetariańska (Ty)",
    "rsvp_children_divider": "Dzieci",
    "rsvp_children_question": "Czy przyprowadzasz dzieci?",
    "rsvp_children_count_label": "Liczba dzieci (max {max_children})",
    "rsvp_children_veg_label": "Dzieci na diecie wege",
    "rsvp_children_not_allowed": "Dzieci nie są zapisane na to zaproszenie.",
    "rsvp_submit_button": "Wyślij RSVP",
}


def get_invite_copy():
    if has_request_context():
        cached = getattr(g, "_invite_copy", None)
        if cached is not None:
            return cached

    rows = {}
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT key, value FROM settings")
        rows = {row[0]: row[1] for row in c.fetchall()}
    except sqlite3.Error:
        rows = {}
    finally:
        if conn:
            conn.close()

    data = {}
    for key, default in INVITE_COPY_DEFAULTS.items():
        raw = rows.get(key)
        data[key] = raw if raw else default

    if has_request_context():
        setattr(g, "_invite_copy", data)

    return data


def normalize_code(raw_code: str | None) -> str:
    return (raw_code or "").strip().upper()


def get_invitation_by_code(raw_code: str):
    code = normalize_code(raw_code)
    if not code:
        return None
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM invitations WHERE code = ?", (code,))
    row = c.fetchone()
    conn.close()
    return row


def get_invitation(invitation_id: int | None):
    if not invitation_id:
        return None
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM invitations WHERE id = ?", (invitation_id,))
    row = c.fetchone()
    conn.close()
    return row


def list_invitations():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM invitations ORDER BY last_name COLLATE NOCASE")
    rows = c.fetchall()
    conn.close()
    return rows


def list_plan_events():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM plan_events ORDER BY sort_order ASC, id ASC")
    rows = c.fetchall()
    conn.close()
    return rows


def create_plan_event(title, subtitle, description, sort_order):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        "INSERT INTO plan_events (title, subtitle, description, sort_order) VALUES (?, ?, ?, ?)",
        (title, subtitle, description, sort_order)
    )
    conn.commit()
    conn.close()


def update_plan_event(event_id, title, subtitle, description, sort_order):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        """
        UPDATE plan_events
        SET title = ?, subtitle = ?, description = ?, sort_order = ?
        WHERE id = ?
        """,
        (title, subtitle, description, sort_order, event_id)
    )
    conn.commit()
    conn.close()


def delete_plan_event(event_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM plan_events WHERE id = ?", (event_id,))
    conn.commit()
    conn.close()


def _parse_acl_entries(raw: str | None) -> list[str]:
    if not raw:
        return []
    tokens = (raw.replace(',', '\n') if raw else '').splitlines()
    return [entry.strip() for entry in tokens if entry.strip()]


def get_admin_acl_entries() -> list[str]:
    try:
        stored = get_setting('admin_acl', '') or ''
    except sqlite3.Error:
        stored = ''
    source = stored.strip() or ADMIN_IP_ALLOWLIST
    return _parse_acl_entries(source)


def get_client_ip() -> str:
    if not has_request_context():
        return ''
    forwarded = request.headers.get('X-Forwarded-For', '')
    if forwarded:
        candidate = forwarded.split(',')[0].strip()
        if candidate:
            return candidate
    return request.remote_addr or ''


def _ip_matches_pattern(ip: str, pattern: str) -> bool:
    if not pattern:
        return False
    pattern = pattern.strip()
    if not pattern:
        return False
    if pattern == '*':
        return True
    try:
        if '/' in pattern:
            network = ipaddress.ip_network(pattern, strict=False)
            return ipaddress.ip_address(ip) in network
    except ValueError:
        pass
    if '*' in pattern:
        prefix = pattern.split('*', 1)[0]
        return ip.startswith(prefix)
    return ip == pattern


def admin_ip_allowed() -> bool:
    entries = get_admin_acl_entries()
    if not entries:
        return True
    ip = get_client_ip()
    if not ip:
        return False
    return any(_ip_matches_pattern(ip, entry) for entry in entries)


@app.context_processor
def inject_admin_access_flag():
    allowed = True
    if has_request_context():
        try:
            allowed = admin_ip_allowed()
        except Exception:
            allowed = True
    try:
        copy_data = get_invite_copy()
    except Exception:
        copy_data = INVITE_COPY_DEFAULTS.copy()
    return {"admin_access_allowed": allowed, "global_copy": copy_data}


@app.route('/favicon.ico')
def favicon():
    icon_path = os.path.join(app.root_path, 'static', 'images')
    return send_from_directory(icon_path, 'background.png', mimetype='image/png')

# -----------------------
# Routes: wejście / logout
# -----------------------
@app.route("/", methods=["GET", "POST"])
def login():
    """
    Strona wejściowa — prosi o hasło INVITE_PASSWORD (z .env).
    Po poprawnym haśle ustawia session['logged'] = True i przekierowuje do /invite.
    """
    session.pop("invitation_id", None)
    session.pop("invite_full_name", None)

    if request.method == "POST":
        code_input = normalize_code(request.form.get("password", ""))
        invitation = get_invitation_by_code(code_input)
        if invitation:
            session["logged"] = True
            session["invitation_id"] = invitation["id"]
            session["invite_full_name"] = f"{invitation['first_name']} {invitation['last_name']}"
            session.permanent = True
            return redirect(url_for("invite"))
        flash("Niepoprawny kod zaproszenia")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("logged", None)
    session.pop("admin", None)
    session.pop("invitation_id", None)
    session.pop("invite_full_name", None)
    return redirect(url_for("login"))

# -----------------------
# Strona zaproszenia + RSVP
# -----------------------
@app.route("/invite")
@login_required
def invite():
    invitation_id = session.get("invitation_id")
    if not invitation_id:
        flash("Zaloguj się używając swojego kodu zaproszenia.")
        return redirect(url_for("login"))

    invitation = get_invitation(invitation_id)
    if not invitation:
        session.pop("invitation_id", None)
        flash("Nie znaleziono zaproszenia. Skontaktuj się z organizatorami.")
        return redirect(url_for("login"))

    # Provide map links if admin configured locations or direct URLs
    wedding_loc = get_setting('wedding_location', '') or ''
    reception_loc = get_setting('reception_location', '') or ''
    wedding_map_url = get_setting('wedding_map_url', '') or ''
    reception_map_url = get_setting('reception_map_url', '') or ''

    if wedding_map_url:
        wedding_map = wedding_map_url
    else:
        wedding_map = f"https://www.google.com/maps/search/?api=1&query={quote_plus(wedding_loc)}" if wedding_loc else None

    if reception_map_url:
        reception_map = reception_map_url
    else:
        reception_map = f"https://www.google.com/maps/search/?api=1&query={quote_plus(reception_loc)}" if reception_loc else None

    # labels
    wedding_label = get_setting('wedding_label', '') or ''
    reception_label = get_setting('reception_label', '') or ''
    same_location = (get_setting('same_location_flag', 'false') or 'false').lower() == 'true'

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM rsvp WHERE invitation_id = ?", (invitation_id,))
    existing_rsvp = c.fetchone()
    conn.close()

    prefill = {
        "first_name": invitation["first_name"],
        "last_name": invitation["last_name"],
        "guest": "tak" if invitation["allow_guest"] else "nie",
        "vegetarian": "nie",
        "vegetarian_guest": "nie",
        "children": "tak" if invitation["max_children"] > 0 else "nie",
        "children_count": invitation["max_children"],
        "children_veg_count": 0,
        "attendance": "tak",
    }

    if existing_rsvp:
        prefill.update({
            "guest": existing_rsvp["guest"],
            "vegetarian": existing_rsvp["vegetarian"],
            "vegetarian_guest": existing_rsvp["vegetarian_guest"],
            "children": existing_rsvp["children"],
            "children_count": existing_rsvp["children_count"],
            "children_veg_count": existing_rsvp["children_veg_count"],
            "attendance": existing_rsvp["attending"] or "tak",
        })

    if not invitation["allow_guest"]:
        prefill["guest"] = "nie"
    if invitation["max_children"] <= 0:
        prefill["children"] = "nie"
        prefill["children_count"] = 0
        prefill["children_veg_count"] = 0
    else:
        prefill["children_count"] = min(prefill.get("children_count", 0) or 0, invitation["max_children"])
        prefill["children_veg_count"] = min(prefill.get("children_veg_count", 0) or 0, prefill["children_count"])

    invite_copy = get_invite_copy()
    plan_events = list_plan_events()

    return render_template(
        "invite.html",
        wedding_map=wedding_map,
        reception_map=reception_map,
        wedding_loc=wedding_loc,
        reception_loc=reception_loc,
        wedding_map_url=wedding_map_url,
        reception_map_url=reception_map_url,
        wedding_label=wedding_label,
        reception_label=reception_label,
        same_location=same_location,
        invite_copy=invite_copy,
        plan_events=plan_events,
        invitation=invitation,
        existing_rsvp=existing_rsvp,
        prefill=prefill,
    )

@app.route("/rsvp", methods=["POST"])
@login_required
def rsvp():
    invitation_id = session.get("invitation_id")
    if not invitation_id:
        flash("Zaloguj się ponownie.")
        return redirect(url_for("login"))

    invitation = get_invitation(invitation_id)
    if not invitation:
        flash("Nie znaleziono zaproszenia.")
        return redirect(url_for("login"))

    has_named_guest = bool((invitation["guest_name"] or "").strip())

    first_name = invitation["first_name"]
    last_name = invitation["last_name"]
    name = (f"{first_name} {last_name}".strip())

    attendance = request.form.get("attendance") or "tak"
    going = attendance == "tak"

    guest = request.form.get("guest") or "nie"
    vegetarian = request.form.get("vegetarian") or "nie"
    children = request.form.get("children") or "nie"
    try:
        children_count = int(request.form.get("children_count") or 0)
        if children_count < 0:
            children_count = 0
    except ValueError:
        children_count = 0
    # read vegetarian choices for guest and children
    vegetarian_guest = request.form.get("vegetarian_guest") or "nie"
    try:
        children_veg_count = int(request.form.get("children_veg_count") or 0)
        if children_veg_count < 0:
            children_veg_count = 0
    except ValueError:
        children_veg_count = 0

    # server-side clamp: children_veg_count cannot exceed children_count
    if children_veg_count > children_count:
        flash("Liczba dzieci na diecie wegetariańskiej nie może być większa niż liczba dzieci.")
        return redirect(url_for("invite"))

    # Validate consistency between guest and guest vegetarian flag
    if guest != 'tak' and (vegetarian_guest == 'tak'):
        flash("Nie można ustawić diety dla osoby towarzyszącej, jeśli nie została wybrana osoba towarzysząca.")
        return redirect(url_for("invite"))

    # If children flag not set but children_count > 0 => validation error
    if children != 'tak' and children_count > 0:
        flash("Zaznaczono liczbę dzieci, ale pole 'Czy przyprowadzasz dzieci?' jest ustawione na 'Nie'.")
        return redirect(url_for("invite"))

    # If children selected, require at least one
    max_children_allowed = max(int(invitation["max_children"] or 0), 0)
    if children_count > max_children_allowed:
        flash("Nie możesz zadeklarować większej liczby dzieci niż zaproszone.")
        return redirect(url_for("invite"))

    if guest == 'tak' and not invitation["allow_guest"]:
        flash("To zaproszenie nie obejmuje osoby towarzyszącej.")
        return redirect(url_for("invite"))

    if not going:
        vegetarian = 'nie'
        if not has_named_guest:
            guest = 'nie'
            vegetarian_guest = 'nie'
            children = 'nie'
            children_count = 0
            children_veg_count = 0

    if children == 'tak' and children_count <= 0:
        flash("Jeśli zaznaczasz, że przyprowadzasz dzieci, podaj ich liczbę większą niż 0.")
        return redirect(url_for("invite"))

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id FROM rsvp WHERE invitation_id = ?", (invitation_id,))
    existing = c.fetchone()
    if existing:
        c.execute(
            """
            UPDATE rsvp
            SET name=?, first_name=?, last_name=?, guest=?, vegetarian=?, vegetarian_guest=?,
                children=?, children_count=?, children_veg_count=?, attending=?, created=CURRENT_TIMESTAMP
            WHERE invitation_id=?
            """,
            (name, first_name, last_name, guest, vegetarian, vegetarian_guest,
             children, children_count, children_veg_count, 'tak' if going else 'nie', invitation_id)
        )
    else:
        c.execute(
            """
            INSERT INTO rsvp
            (name, first_name, last_name, guest, vegetarian, vegetarian_guest, children, children_count, children_veg_count, attending, invitation_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (name, first_name, last_name, guest, vegetarian, vegetarian_guest,
             children, children_count, children_veg_count, 'tak' if going else 'nie', invitation_id)
        )
    conn.commit()
    conn.close()

    full_name = name
    return render_template("thanks.html", name=full_name)

# -----------------------
# Panel administratora
# -----------------------
@app.route("/admin", methods=["GET", "POST"])
def admin():
    """
    Formularz logowania do panelu admina (ADMIN_PASSWORD z .env).
    """
    # Ensure visiting the admin login clears any previous admin session
    session.pop("admin", None)
    if not admin_ip_allowed():
        return render_template("admin_login.html", blocked_ip=True), 403

    if request.method == "POST":
        admin_pass = request.form.get("password", "")
        if verify_secret(admin_pass, ADMIN_PASSWORD, ADMIN_PASSWORD_HASH):
            session["admin"] = True
            session.permanent = True
            return redirect(url_for("admin_panel"))
        flash("Błędne hasło administratora.")
    return render_template("admin_login.html", blocked_ip=False)

@app.route("/admin/logout")
def admin_logout():
    session.pop("admin", None)
    return redirect(url_for("admin"))

@app.route("/admin/panel")
@admin_required
def admin_panel():
    conn = get_db_connection()
    c = conn.cursor()
    # select expanded columns including new diet fields
    # select id, first_name and last_name to support split-name fields
    c.execute(
        """
        SELECT rsvp.id, rsvp.first_name, rsvp.last_name, rsvp.guest, rsvp.vegetarian,
               rsvp.vegetarian_guest, rsvp.children, rsvp.children_count, rsvp.children_veg_count,
               rsvp.created, rsvp.attending, invitations.code, invitations.guest_name
        FROM rsvp
        LEFT JOIN invitations ON invitations.id = rsvp.invitation_id
        ORDER BY rsvp.created DESC
        """
    )
    raw_rows = c.fetchall()
    rows = []
    total_guests = 0
    total_children = 0
    total_vegetarian = 0
    total_vegetarian_children = 0
    total_adults = 0
    for r in raw_rows:
        # r: id, first_name, last_name, guest, vegetarian_self, vegetarian_guest, children_flag, children_count, children_veg_count, created
        attending_flag = (r["attending"] or 'tak').lower()
        primary_present = 1 if attending_flag == 'tak' else 0
        guest_flag = r["guest"]
        plus_guest = 1 if (guest_flag == 'tak') else 0
        kids = int(r["children_count"] or 0)
        if (r["children"] or 'nie') != 'tak':
            kids = 0
        total = primary_present + plus_guest + kids
        # vegetarian counts
        veg_self = 1 if (r["vegetarian"] == 'tak' and primary_present == 1) else 0
        veg_guest = 1 if (r["vegetarian_guest"] == 'tak' and plus_guest == 1) else 0
        veg_children = int(r["children_veg_count"] or 0)
        # ensure veg_children doesn't exceed kids
        if veg_children > kids:
            veg_children = kids
        veg_total = veg_self + veg_guest + veg_children
        total_guests += total
        total_children += kids
        total_vegetarian += veg_total
        total_vegetarian_children += veg_children
        total_adults += (primary_present + plus_guest)
        rows.append({
            "id": r["id"],
            "first_name": r["first_name"],
            "last_name": r["last_name"],
            "guest": r["guest"],
            "vegetarian": r["vegetarian"],
            "vegetarian_guest": r["vegetarian_guest"],
            "children": r["children"],
            "children_count": kids,
            "children_veg_count": veg_children,
            "created": r["created"],
            "total": total,
            "veg_total": veg_total,
            "attending": attending_flag,
            "invitation_code": r["code"],
            "guest_name": r["guest_name"],
        })
    conn.close()

    summary = {
        "submissions": len(rows),
        "total_guests": total_guests,
        "total_children": total_children,
        "total_vegetarian": total_vegetarian,
        "total_vegetarian_children": total_vegetarian_children,
        "total_adults": total_adults,
        "total_normal": total_guests - total_vegetarian,
    }
    # also fetch editable locations
    wedding_loc = get_setting('wedding_location', '') or ''
    reception_loc = get_setting('reception_location', '') or ''
    wedding_map_url = get_setting('wedding_map_url', '') or ''
    reception_map_url = get_setting('reception_map_url', '') or ''
    wedding_label = get_setting('wedding_label', '') or ''
    reception_label = get_setting('reception_label', '') or ''
    same_location = (get_setting('same_location_flag', 'false') or 'false').lower() == 'true'
    invite_copy = get_invite_copy()
    invitations = list_invitations()
    plan_events = list_plan_events()
    admin_acl_text = get_setting('admin_acl', '') or ''
    current_admin_ip = get_client_ip()

    return render_template(
        "admin_panel.html",
        rows=rows,
        summary=summary,
        wedding_loc=wedding_loc,
        reception_loc=reception_loc,
        wedding_map_url=wedding_map_url,
        reception_map_url=reception_map_url,
        wedding_label=wedding_label,
        reception_label=reception_label,
        same_location=same_location,
        invite_copy=invite_copy,
        invitations=invitations,
        plan_events=plan_events,
        admin_acl_text=admin_acl_text,
        current_admin_ip=current_admin_ip,
    )


@app.route('/admin/set_locations', methods=['POST'])
@admin_required
def set_locations():
    wedding = (request.form.get('wedding_location') or '').strip()
    reception = (request.form.get('reception_location') or '').strip()
    wedding_map_url = (request.form.get('wedding_map_url') or '').strip()
    reception_map_url = (request.form.get('reception_map_url') or '').strip()
    wedding_label = (request.form.get('wedding_label') or '').strip()
    reception_label = (request.form.get('reception_label') or '').strip()
    same_location_flag = 'true' if request.form.get('same_location_flag') == 'on' else 'false'
    set_setting('wedding_location', wedding)
    set_setting('reception_location', reception)
    set_setting('wedding_map_url', wedding_map_url)
    set_setting('reception_map_url', reception_map_url)
    set_setting('wedding_label', wedding_label)
    set_setting('reception_label', reception_label)
    set_setting('same_location_flag', same_location_flag)
    flash('Miejsca zostały zapisane.')
    return redirect(url_for('admin_panel'))


@app.route('/admin/set_invite_copy', methods=['POST'])
@admin_required
def set_invite_copy():
    for key in INVITE_COPY_DEFAULTS.keys():
        value = (request.form.get(key) or '').strip()
        set_setting(key, value)
    flash('Treści zaproszenia zostały zapisane.')
    return redirect(url_for('admin_panel'))


@app.route('/admin/set_acl', methods=['POST'])
@admin_required
def set_admin_acl_route():
    raw = (request.form.get('admin_acl') or '').strip()
    normalized = '\n'.join(_parse_acl_entries(raw))
    set_setting('admin_acl', normalized)
    flash('Lista dozwolonych adresów IP została zaktualizowana.')
    return redirect(url_for('admin_panel'))


def _parse_int(value, default=0):
    try:
        parsed = int(value)
        return parsed
    except (ValueError, TypeError):
        return default


@app.route('/admin/invitations/create', methods=['POST'])
@admin_required
def admin_create_invitation():
    first_name = (request.form.get('first_name') or '').strip()
    last_name = (request.form.get('last_name') or '').strip()
    code = normalize_code(request.form.get('code'))
    allow_guest = 1 if request.form.get('allow_guest') == 'on' else 0
    guest_name = (request.form.get('guest_name') or '').strip()
    max_children = max(_parse_int(request.form.get('max_children'), 0), 0)
    notes = (request.form.get('notes') or '').strip()

    if not allow_guest:
        guest_name = ''

    if not first_name or not last_name or not code:
        flash('Imię, nazwisko i kod są wymagane.', 'error')
        return redirect(url_for('admin_panel'))

    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute(
            "INSERT INTO invitations (code, first_name, last_name, allow_guest, max_children, notes, guest_name) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (code, first_name, last_name, allow_guest, max_children, notes, guest_name)
        )
        conn.commit()
        flash('Zaproszenie zostało dodane.')
    except sqlite3.IntegrityError:
        flash('Kod zaproszenia musi być unikalny.', 'error')
    finally:
        conn.close()
    return redirect(url_for('admin_panel'))


@app.route('/admin/invitations/<int:invitation_id>/update', methods=['POST'])
@admin_required
def admin_update_invitation(invitation_id):
    first_name = (request.form.get('first_name') or '').strip()
    last_name = (request.form.get('last_name') or '').strip()
    code = normalize_code(request.form.get('code'))
    allow_guest = 1 if request.form.get('allow_guest') == 'on' else 0
    guest_name = (request.form.get('guest_name') or '').strip()
    max_children = max(_parse_int(request.form.get('max_children'), 0), 0)
    notes = (request.form.get('notes') or '').strip()

    if not allow_guest:
        guest_name = ''

    if not first_name or not last_name or not code:
        flash('Imię, nazwisko i kod są wymagane.', 'error')
        return redirect(url_for('admin_panel'))

    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute(
            """
            UPDATE invitations
            SET first_name=?, last_name=?, code=?, allow_guest=?, max_children=?, notes=?, guest_name=?
            WHERE id=?
            """,
            (first_name, last_name, code, allow_guest, max_children, notes, guest_name, invitation_id)
        )
        conn.commit()
        flash('Zaproszenie zaktualizowane.')
    except sqlite3.IntegrityError:
        flash('Kod zaproszenia musi być unikalny.', 'error')
    finally:
        conn.close()
    return redirect(url_for('admin_panel'))


@app.route('/admin/invitations/<int:invitation_id>/delete', methods=['POST'])
@admin_required
def admin_delete_invitation(invitation_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM rsvp WHERE invitation_id = ?", (invitation_id,))
    c.execute("DELETE FROM invitations WHERE id = ?", (invitation_id,))
    conn.commit()
    conn.close()
    flash('Zaproszenie zostało usunięte.')
    return redirect(url_for('admin_panel'))

@app.route('/admin/plan-events/create', methods=['POST'])
@admin_required
def admin_create_plan_event_route():
    title = (request.form.get('title') or '').strip()
    subtitle = (request.form.get('subtitle') or '').strip()
    description = (request.form.get('description') or '').strip()
    sort_order = _parse_int(request.form.get('sort_order'), 0)

    if not title:
        flash('Tytuł wydarzenia jest wymagany.', 'error')
        return redirect(url_for('admin_panel'))

    create_plan_event(title, subtitle, description, sort_order)
    flash('Wydarzenie dodane do planu dnia.')
    return redirect(url_for('admin_panel'))

@app.route('/admin/plan-events/<int:event_id>/update', methods=['POST'])
@admin_required
def admin_update_plan_event_route(event_id):
    title = (request.form.get('title') or '').strip()
    subtitle = (request.form.get('subtitle') or '').strip()
    description = (request.form.get('description') or '').strip()
    sort_order = _parse_int(request.form.get('sort_order'), 0)

    if not title:
        flash('Tytuł wydarzenia jest wymagany.', 'error')
        return redirect(url_for('admin_panel'))

    update_plan_event(event_id, title, subtitle, description, sort_order)
    flash('Wydarzenie zaktualizowane.')
    return redirect(url_for('admin_panel'))

@app.route('/admin/plan-events/<int:event_id>/delete', methods=['POST'])
@admin_required
def admin_delete_plan_event_route(event_id):
    delete_plan_event(event_id)
    flash('Wydarzenie usunięte z planu dnia.')
    return redirect(url_for('admin_panel'))
# -----------------------
# Eksport CSV
# -----------------------
@app.route("/admin/export_csv")
@admin_required
def export_csv():

    conn = get_db_connection()
    c = conn.cursor()
    # select with split name fields
    c.execute(
        """
        SELECT rsvp.id, rsvp.first_name, rsvp.last_name, rsvp.guest, rsvp.vegetarian,
               rsvp.vegetarian_guest, rsvp.children, rsvp.children_count, rsvp.children_veg_count,
               rsvp.created, rsvp.attending, invitations.code, invitations.guest_name
        FROM rsvp
        LEFT JOIN invitations ON invitations.id = rsvp.invitation_id
        ORDER BY rsvp.created DESC
        """
    )
    rows = c.fetchall()
    conn.close()

    def generate():
        header = [
            "ID", "Kod_zaproszenia", "Imię", "Nazwisko", "Obecnosc", "Osoba_towarzyszaca",
            "Wegetarianin_osoba", "Wegetarianin_gosc", "Children", "Children_count",
            "Children_veg_count", "Total_people", "Utworzono", "Nazwa_osoby_towarzyszacej"
        ]
        yield ",".join(header) + "\n"
        for row in rows:
            # row: id, first_name, last_name, guest, vegetarian_self, vegetarian_guest, children_flag, children_count, children_veg_count, created
            kids = int(row["children_count"] or 0)
            plus_guest = 1 if (row["guest"] == 'tak') else 0
            total = 0 if (row["attending"] == 'nie') else 1 + plus_guest + kids
            safe_extended = [
                row["id"],
                row["code"] or "",
                row["first_name"] or "",
                row["last_name"] or "",
                row["attending"] or "",
                row["guest"],
                row["vegetarian"],
                row["vegetarian_guest"],
                row["children"],
                row["children_count"],
                row["children_veg_count"],
                total,
                row["created"],
                row["guest_name"] or "",
            ]
            safe = ["" if v is None else str(v) for v in safe_extended]
            quoted = ['"{}"'.format(s.replace('"', '""')) for s in safe]
            yield ",".join(quoted) + "\n"

    return Response(
        generate(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=rsvp_export.csv"}
    )


@app.route("/admin/delete/<int:entry_id>", methods=["POST"])
@admin_required
def admin_delete(entry_id):
    """Delete an RSVP entry by id. Protected by admin_required."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM rsvp WHERE id = ?", (entry_id,))
    conn.commit()
    conn.close()
    flash("Zgłoszenie zostało usunięte.")
    return redirect(url_for("admin_panel"))

# -----------------------
# Health / test route (opcjonalne)
# -----------------------
@app.route("/_health")
def health():
    return "ok", 200


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    return response

# -----------------------
# Start app (development)
# -----------------------
if __name__ == "__main__":
    # W trybie produkcyjnym uruchamiaj przez Gunicorn. Disable Flask debug overlay for diagnosis.
    app.run(host="0.0.0.0", port=10500, debug=False)
