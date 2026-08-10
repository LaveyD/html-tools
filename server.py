"""
软件工具集 - 后端 API
Flask + SQLite: 软件上传/下载（多版本）、需求收集、版本管理、管理员认证
"""
import json
import uuid
import sqlite3
import struct
import io
from datetime import datetime, timedelta
from pathlib import Path
from functools import wraps
import re
import os
from flask import Flask, request, jsonify, send_from_directory, send_file, redirect, make_response
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

try:
    from PIL import Image
    HAS_ICON_EXTRACT = True
except ImportError:
    HAS_ICON_EXTRACT = False

app = Flask(__name__)

@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data: blob:; "
        "style-src 'self' 'unsafe-inline';"
    )
    return response

BASE_DIR = Path(__file__).parent.resolve()
DB_PATH = BASE_DIR / 'software.db'
UPLOAD_DIR = BASE_DIR / 'software_files'
UPLOAD_DIR.mkdir(exist_ok=True)
ICON_DIR = BASE_DIR / 'software_icons'
ICON_DIR.mkdir(exist_ok=True)
# ── Security config (env vars or defaults) ─────────────────
UPLOAD_MAX_SIZE = int(os.environ.get('UPLOAD_MAX_SIZE', 1024 * 1024 * 1024))  # 1GB default
ALLOWED_EXTENSIONS = set(os.environ.get('ALLOWED_EXTENSIONS',
    'exe,msi,zip,rar,7z,tar,gz,bz2,xz,dmg,pkg,deb,rpm,apk,appx').split(','))


# ─── Icon Extraction ───────────────────────────────────────
def extract_exe_icon(exe_path, size=64):
    """Extract icon from .exe/.dll — pure struct parse, find PNG/BMP in .rsrc section."""
    if not HAS_ICON_EXTRACT:
        return None
    try:
        with open(exe_path, 'rb') as f:
            data = f.read(1048576)  # read first 1MB — enough for PE header + .rsrc

        if len(data) < 64 or data[:2] != b'MZ':
            return None

        # PE header
        pe_offset = struct.unpack_from('<I', data, 60)[0]
        if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
            return None
        coff = pe_offset + 4
        num_sections = struct.unpack_from('<H', data, coff + 2)[0]
        opt_hdr_size = struct.unpack_from('<H', data, coff + 16)[0]

        # Find .rsrc section by name
        sec_offset = coff + 20 + opt_hdr_size
        rsrc_ro = rsrc_rs = None
        for i in range(num_sections):
            base = sec_offset + i * 40
            name = data[base:base+8].rstrip(b'\x00').decode('ascii', errors='replace')
            if 'rsrc' in name:
                rsrc_rs = struct.unpack_from('<I', data, base + 16)[0]
                rsrc_ro = struct.unpack_from('<I', data, base + 20)[0]
                break

        if rsrc_ro is None or rsrc_rs == 0:
            return None

        # Search for PNG (89504E47) or BMP (424D) in .rsrc section
        rsrc_end = rsrc_ro + rsrc_rs
        search_data = data[rsrc_ro:rsrc_end]
        search_len = len(search_data)

        # PNG scan
        for i in range(search_len - 8):
            if search_data[i] == 0x89 and search_data[i+1] == 0x50 and search_data[i+2] == 0x4E and search_data[i+3] == 0x47:
                # Walk PNG chunks to find IEND
                p = i + 8
                while p + 8 <= search_len:
                    cl = struct.unpack_from('>I', search_data, p)[0]
                    if cl > 10000000:
                        break
                    p += 12 + cl
                    if search_data[p-8:p-4] == b'IEND':
                        png_data = search_data[i:p]
                        img = Image.open(io.BytesIO(png_data))
                        if img.mode != 'RGBA':
                            img = img.convert('RGBA')
                        img = img.resize((size, size), Image.Resampling.LANCZOS if hasattr(Image, 'Resampling') else Image.Resampling.LANCZOS)
                        buf = io.BytesIO()
                        img.save(buf, format='PNG')
                        return buf.getvalue()

        # BMP scan
        for i in range(search_len - 6):
            if search_data[i] == 0x42 and search_data[i+1] == 0x4D:
                bmp_sz = struct.unpack_from('<I', search_data, i + 2)[0]
                if 54 < bmp_sz < 10000000 and i + bmp_sz <= search_len:
                    bmp_data = search_data[i:i+bmp_sz]
                    img = Image.open(io.BytesIO(bmp_data))
                    if img.mode != 'RGBA':
                        img = img.convert('RGBA')
                    img = img.resize((size, size), Image.Resampling.LANCZOS if hasattr(Image, 'Resampling') else Image.Resampling.LANCZOS)
                    buf = io.BytesIO()
                    img.save(buf, format='PNG')
                    return buf.getvalue()

        return None
    except Exception as e:
        print(f"Icon extract error: {e}")
        return None

# ─── Admin Auth ────────────────────────────────────────────
# Admin password hash (sha256 of the password)
# Default password: admin123 — change this!
ADMIN_TOKENS = {}  # token -> expiry

# ── Captcha (in-memory, no Redis needed) ──────────────────
import random
import string
import io
from datetime import datetime, timedelta

CAPTCHA_STORE = {}  # token -> {answer, expires_at}
CAPTCHA_LENGTH = 5
CAPTCHA_EXPIRY = timedelta(minutes=5)

# ── Rate limiter (in-memory sliding window) ────────────────
LOGIN_FAIL_COUNTS = {}    # ip -> [(timestamp, count)]
ACCOUNT_LOCKOUTS = {}     # ip -> unlock_time

RATE_LIMIT_IP_WINDOW = 60        # seconds
RATE_LIMIT_IP_MAX = 15           # max requests per window per IP
LOGIN_FAIL_WINDOW = 300          # 5 minutes
LOGIN_FAIL_MAX = 5               # max failures before lockout
ACCOUNT_LOCKOUT_DURATION = 300   # 5 minutes lockout


def _cleanup_expired_stores():
    """Clean up expired captcha and rate limit entries."""
    now = datetime.now()
    # Clean captcha
    expired = [k for k, v in CAPTCHA_STORE.items() if now > v['expires_at']]
    for k in expired:
        del CAPTCHA_STORE[k]
    # Clean rate limits (older than 2 windows)
    cutoff = now - timedelta(seconds=RATE_LIMIT_IP_WINDOW * 2)
    for ip in list(LOGIN_FAIL_COUNTS.keys()):
        LOGIN_FAIL_COUNTS[ip] = [t for t in LOGIN_FAIL_COUNTS[ip] if t > cutoff]
        if not LOGIN_FAIL_COUNTS[ip]:
            del LOGIN_FAIL_COUNTS[ip]
    for ip in list(ACCOUNT_LOCKOUTS.keys()):
        if now > ACCOUNT_LOCKOUTS[ip]:
            del ACCOUNT_LOCKOUTS[ip]


def _check_ip_rate_limit(ip):
    """Check if IP has exceeded login rate limit. Returns (allowed, remaining, message|None)."""
    now = datetime.now()
    # Check lockout first
    if ip in ACCOUNT_LOCKOUTS:
        if now > ACCOUNT_LOCKOUTS[ip]:
            del ACCOUNT_LOCKOUTS[ip]
            LOGIN_FAIL_COUNTS.pop(ip, None)
        else:
            unlock_in = int((ACCOUNT_LOCKOUTS[ip] - now).total_seconds())
            return False, 0, f'账户已锁定，{unlock_in}秒后重试'
    # Sliding window check
    if ip not in LOGIN_FAIL_COUNTS:
        return True, RATE_LIMIT_IP_MAX, None
    window_start = now - timedelta(seconds=RATE_LIMIT_IP_WINDOW)
    recent = [t for t in LOGIN_FAIL_COUNTS[ip] if t > window_start]
    LOGIN_FAIL_COUNTS[ip] = recent
    remaining = max(0, RATE_LIMIT_IP_MAX - len(recent))
    if remaining == 0:
        return False, 0, '请求过于频繁，请稍后再试'
    return True, remaining, None


def _record_login_failure(ip):
    """Record a login failure and check if account should be locked."""
    now = datetime.now()
    if ip not in LOGIN_FAIL_COUNTS:
        LOGIN_FAIL_COUNTS[ip] = []
    LOGIN_FAIL_COUNTS[ip].append(now)
    # Check if locked
    window_start = now - timedelta(seconds=LOGIN_FAIL_WINDOW)
    recent = [t for t in LOGIN_FAIL_COUNTS[ip] if t > window_start]
    if len(recent) >= LOGIN_FAIL_MAX:
        ACCOUNT_LOCKOUTS[ip] = now + timedelta(seconds=ACCOUNT_LOCKOUT_DURATION)


def _clear_login_failures(ip):
    """Clear login failure count on successful login."""
    LOGIN_FAIL_COUNTS.pop(ip, None)
    ACCOUNT_LOCKOUTS.pop(ip, None)


def _generate_captcha():
    """Generate captcha. Returns (token, png_bytes)."""
    # Generate answer
    chars = string.ascii_letters + string.digits
    answer = ''.join(random.choices(chars, k=CAPTCHA_LENGTH))
    token = uuid.uuid4().hex
    CAPTCHA_STORE[token] = {
        'answer': answer,
        'expires_at': datetime.now() + CAPTCHA_EXPIRY,
    }
    # Render as PNG using Pillow
    try:
        from PIL import Image, ImageDraw, ImageFont
        img = Image.new('RGBA', (160, 60), (255, 255, 255, 255))
        draw = ImageDraw.Draw(img)
        # Try to use a font, fall back to default
        font = None
        for font_path in ['C:/Windows/Fonts/arialbd.ttf',  # Windows: Arial Bold
                          'C:/Windows/Fonts/arial.ttf',   # Windows: Arial
                          '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf',  # Linux
                          '/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf']:# Linux
            if os.path.exists(font_path):
                font = ImageFont.truetype(font_path, 28)
                break
        if not font:
            font = ImageFont.load_default()
        # Draw characters with random offsets
        char_width = 160 // CAPTCHA_LENGTH
        for i, ch in enumerate(answer):
            ox = i * char_width + random.randint(2, 8)
            oy = random.randint(5, 20)
            color = tuple(random.randint(50, 120) for _ in range(3))
            draw.text((ox, oy), ch, fill=color, font=font)
        # Draw noise lines
        for _ in range(5):
            x1, y1 = random.randint(0, 160), random.randint(0, 60)
            x2, y2 = random.randint(0, 160), random.randint(0, 60)
            draw.line([(x1, y1), (x2, y2)], fill=(200, 200, 200), width=1)
        # Draw noise dots
        for _ in range(40):
            x, y = random.randint(0, 160), random.randint(0, 60)
            draw.point((x, y), fill=(200, 200, 200))
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        return token, buf.getvalue()
    except Exception as e:
        print(f"Captcha generation error: {e}")
        # Fallback: return simple text
        return token, b'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=='


def _verify_captcha(token, user_answer):
    """Verify captcha answer. Returns True/False."""
    _cleanup_expired_stores()
    now = datetime.now()
    if token not in CAPTCHA_STORE:
        return False
    entry = CAPTCHA_STORE[token]
    if now > entry['expires_at']:
        del CAPTCHA_STORE[token]
        return False
    # Time-safe comparison
    import secrets
    valid = secrets.compare_digest(entry['answer'].upper(), user_answer.upper())
    # One-time use: delete immediately
    del CAPTCHA_STORE[token]
    return valid


def init_admin():
    """Load admin config from file"""
    config_path = BASE_DIR / '.admin_config'
    if not config_path.exists():
        # Create default: password = admin123
        pw = 'admin123'
        config_path.write_text(json.dumps({
            'password_hash': generate_password_hash(pw),
            'force_change': True,
        }, indent=2))
    with open(config_path) as f:
        cfg = json.load(f)
    return cfg


ADMIN_CONFIG = init_admin()
ADMIN_PASSWORD_HASH = ADMIN_CONFIG['password_hash']


def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = (
            request.headers.get('X-Admin-Token')
            or request.cookies.get('admin_token')
        )
        if not token or token not in ADMIN_TOKENS:
            return jsonify({'code': 401, 'message': '未授权'}), 401
        # Check expiry
        if datetime.now() > ADMIN_TOKENS[token]:
            ADMIN_TOKENS.pop(token, None)
            return jsonify({'code': 401, 'message': 'Token 已过期'}), 401
        return f(*args, **kwargs)
    return decorated


@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    data = request.get_json(force=True) if request.is_json else {}
    password_field = data.get('password', '')
    captcha_token = data.get('captcha_token', '')
    captcha_answer = data.get('captcha_answer', '')
    nonce = data.get('nonce', '')
    ip = request.remote_addr

    # Rate limit check
    _cleanup_expired_stores()
    allowed, remaining, rate_msg = _check_ip_rate_limit(ip)
    if not allowed:
        return jsonify({'code': 429, 'message': rate_msg}), 429

    # Verify captcha
    if not _verify_captcha(captcha_token, captcha_answer):
        _record_login_failure(ip)
        return jsonify({'code': 400, 'message': '验证码错误'}), 400

    # Verify password (plain text — RSA encryption removed due to CDN dependency in intranet)
    if not check_password_hash(ADMIN_PASSWORD_HASH, password_field):
        _record_login_failure(ip)
        return jsonify({'code': 403, 'message': '密码错误'}), 403

    # Success: clear failures, issue token
    _clear_login_failures(ip)
    token = uuid.uuid4().hex
    ADMIN_TOKENS[token] = datetime.now() + timedelta(hours=24)

    force_change = ADMIN_CONFIG.get('force_change', False)
    resp = make_response(jsonify({'code': 0, 'data': {'token': token, 'force_change': force_change}}))
    resp.set_cookie(
        'admin_token', token,
        httponly=True,
        samesite='Strict',
        max_age=86400
    )
    return resp


@app.route('/api/captcha', methods=['GET'])
def get_captcha():
    """Generate and return captcha as PNG image."""
    ip = request.remote_addr
    _cleanup_expired_stores()
    allowed, _, msg = _check_ip_rate_limit(ip)
    if not allowed:
        return jsonify({'code': 429, 'message': msg}), 429

    token, png_bytes = _generate_captcha()
    from flask import Response
    resp = Response(png_bytes, status=200, mimetype='image/png')
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['X-Captcha-Token'] = token
    return resp


@app.route('/api/admin/logout', methods=['POST'])
def admin_logout():
    token = (
        request.headers.get('X-Admin-Token')
        or request.cookies.get('admin_token')
    )
    if token:
        ADMIN_TOKENS.pop(token, None)
    return jsonify({'code': 0, 'message': '已退出'})


# ─── DB helpers ────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    conn = get_db()
    conn.executescript("""
        -- 软件条目表
        CREATE TABLE IF NOT EXISTS software (
            id TEXT PRIMARY KEY,
            slug TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT,
            tags TEXT DEFAULT '[]',
            status TEXT DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- 版本文件表
        CREATE TABLE IF NOT EXISTS software_versions (
            id TEXT PRIMARY KEY,
            software_id TEXT NOT NULL,
            version TEXT NOT NULL,
            filename TEXT NOT NULL,
            original_name TEXT NOT NULL,
            file_size INTEGER DEFAULT 0,
            download_count INTEGER DEFAULT 0,
            uploader TEXT,
            status TEXT DEFAULT 'active',
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (software_id) REFERENCES software(id) ON DELETE CASCADE,
            UNIQUE(software_id, version, status)
        );

        -- 屏蔽工具表
        CREATE TABLE IF NOT EXISTS blocked_tools (
            id TEXT PRIMARY KEY,
            tool_id TEXT UNIQUE NOT NULL,
            tool_name TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- 需求表
        CREATE TABLE IF NOT EXISTS requests (
            id TEXT PRIMARY KEY,
            type TEXT NOT NULL DEFAULT 'software',
            title TEXT NOT NULL,
            description TEXT,
            submitter TEXT,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_software_category ON software(category);
        CREATE INDEX IF NOT EXISTS idx_software_status ON software(status);
        CREATE INDEX IF NOT EXISTS idx_software_created ON software(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_versions_software ON software_versions(software_id);
        CREATE INDEX IF NOT EXISTS idx_versions_status ON software_versions(status);
        CREATE INDEX IF NOT EXISTS idx_requests_status ON requests(status);

        -- Migrate old data if exists (from single-table schema)
        CREATE TABLE IF NOT EXISTS _migrate_check (id INTEGER);
    """)
    conn.commit()

    # Auto-migrate: if old 'software' table had 'filename' column, it's the v1 schema
    try:
        old_cols = [r['name'] for r in conn.execute(
            "PRAGMA table_info(software)"
        ).fetchall() if r['name'] == 'filename']
        if old_cols:
            # Old schema has 'filename' — migrate to new schema
            migrate_v1_to_v2(conn)
    except Exception:
        pass

    conn.close()


def migrate_v1_to_v2(conn):
    """Migrate from single-table schema to software + versions schema"""
    print("[Migrate] Old schema detected, migrating to v2...")

    # Create new tables
    conn.execute("DROP TABLE IF EXISTS software_new")
    conn.execute("DROP TABLE IF EXISTS software_versions_new")

    conn.executescript("""
        CREATE TABLE software_new (
            id TEXT PRIMARY KEY,
            slug TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT,
            tags TEXT DEFAULT '[]',
            status TEXT DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE software_versions_new (
            id TEXT PRIMARY KEY,
            software_id TEXT NOT NULL,
            version TEXT NOT NULL,
            filename TEXT NOT NULL,
            original_name TEXT NOT NULL,
            file_size INTEGER DEFAULT 0,
            download_count INTEGER DEFAULT 0,
            uploader TEXT,
            status TEXT DEFAULT 'active',
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (software_id) REFERENCES software_new(id) ON DELETE CASCADE
        );
    """)

    # Read old data
    old_rows = conn.execute("SELECT * FROM software").fetchall()
    for row in old_rows:
        sw_id = row['id']
        conn.execute(
            "INSERT INTO software_new (id, slug, name, category, description, tags, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (sw_id, row['slug'], row['name'], row['category'],
             row['description'], row['tags'] or '[]',
             row['created_at'], row['updated_at'])
        )
        ver_id = uuid.uuid4().hex
        conn.execute(
            "INSERT INTO software_versions_new (id, software_id, version, filename, original_name, file_size, download_count, uploader, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (ver_id, sw_id, row['version'] or '1.0', row['filename'],
             row['original_name'], row['file_size'], row['download_count'],
             row['uploader'], row['created_at'])
        )

    # Replace tables
    conn.execute("DROP TABLE software")
    conn.execute("ALTER TABLE software_new RENAME TO software")
    conn.execute("DROP TABLE software_versions")
    conn.execute("ALTER TABLE software_versions_new RENAME TO software_versions")

    # Recreate indexes
    conn.executescript("""
        CREATE INDEX idx_software_category ON software(category);
        CREATE INDEX idx_software_status ON software(status);
        CREATE INDEX idx_software_created ON software(created_at DESC);
        CREATE INDEX idx_versions_software ON software_versions(software_id);
        CREATE INDEX idx_versions_status ON software_versions(status);
    """)

    conn.commit()
    print(f"[Migrate] Done — {len(old_rows)} software entries migrated")


# ─── Helpers ───────────────────────────────────────────────

def make_slug(name):
    """Generate URL-friendly slug from name"""
    slug = ""
    for ch in name:
        if ch.isalnum():
            slug += ch.lower()
        else:
            slug += "-"
    return slug.strip("-") or uuid.uuid4().hex[:8]


def format_size(size_bytes):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} PB"


def software_to_dict(row):
    return {
        'id': row['id'],
        'slug': row['slug'],
        'name': row['name'],
        'category': row['category'],
        'description': row['description'],
        'tags': json.loads(row['tags']) if row['tags'] else [],
        'status': row['status'],
        'created_at': row['created_at'],
        'updated_at': row['updated_at'],
    }


def version_to_dict(row):
    return {
        'id': row['id'],
        'version': row['version'],
        'filename': row['filename'],
        'original_name': row['original_name'],
        'file_size': row['file_size'],
        'file_size_text': format_size(row['file_size']),
        'download_count': row['download_count'],
        'uploader': row['uploader'],
        'status': row['status'],
        'notes': row['notes'],
        'created_at': row['created_at'],
    }


# ─── Software List ─────────────────────────────────────────

@app.route('/api/software/list', methods=['GET'])
def list_software():
    category = request.args.get('category', '').strip()
    q = request.args.get('q', '').strip()

    conn = get_db()
    if category and q:
        rows = conn.execute(
            "SELECT * FROM software WHERE status='active' AND category=? AND (name LIKE ? OR description LIKE ?) ORDER BY updated_at DESC",
            (category, f'%{q}%', f'%{q}%')
        ).fetchall()
    elif category:
        rows = conn.execute(
            "SELECT * FROM software WHERE status='active' AND category=? ORDER BY updated_at DESC",
            (category,)
        ).fetchall()
    elif q:
        rows = conn.execute(
            "SELECT * FROM software WHERE status='active' AND (name LIKE ? OR description LIKE ?) ORDER BY updated_at DESC",
            (f'%{q}%', f'%{q}%')
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM software WHERE status='active' ORDER BY updated_at DESC"
        ).fetchall()

    result = []
    for sw in rows:
        sw_dict = software_to_dict(sw)

        # Get latest active version
        ver = conn.execute(
            "SELECT * FROM software_versions WHERE software_id=? AND status='active' ORDER BY created_at DESC LIMIT 1",
            (sw['id'],)
        ).fetchone()

        # Get total version count
        ver_count = conn.execute(
            "SELECT COUNT(*) FROM software_versions WHERE software_id=?",
            (sw['id'],)
        ).fetchone()[0]

        sw_dict['versions'] = [version_to_dict(ver)] if ver else []
        sw_dict['version_count'] = ver_count
        sw_dict['latest_version'] = ver['version'] if ver else None
        sw_dict['latest_size'] = format_size(ver['file_size']) if ver else ''
        sw_dict['total_downloads'] = conn.execute(
            "SELECT COALESCE(SUM(download_count),0) FROM software_versions WHERE software_id=?",
            (sw['id'],)
        ).fetchone()[0]

        # Add icon URL if icon exists
        icon_path = ICON_DIR / f"{sw['id']}.png"
        sw_dict['icon_url'] = f"/software_icons/{sw['id']}.png" if icon_path.exists() else None

        result.append(sw_dict)

    conn.close()
    return jsonify({'code': 0, 'data': result, 'total': len(result)})


# ─── Software Detail (with all versions) ──────────────────

@app.route('/api/software/<slug>', methods=['GET'])
def get_software(slug):
    conn = get_db()
    sw = conn.execute("SELECT * FROM software WHERE slug=?", (slug,)).fetchone()
    if not sw:
        conn.close()
        return jsonify({'code': 404, 'message': '软件不存在'}), 404

    sw_dict = software_to_dict(sw)

    # All versions (active first, then archived)
    versions = conn.execute(
        "SELECT * FROM software_versions WHERE software_id=? ORDER BY "
        "CASE status WHEN 'active' THEN 0 ELSE 1 END, created_at DESC",
        (sw['id'],)
    ).fetchall()

    sw_dict['versions'] = [version_to_dict(v) for v in versions]
    sw_dict['version_count'] = len(versions)
    sw_dict['total_downloads'] = conn.execute(
        "SELECT COALESCE(SUM(download_count),0) FROM software_versions WHERE software_id=?",
        (sw['id'],)
    ).fetchone()[0]

    conn.close()
    return jsonify({'code': 0, 'data': sw_dict})


# ─── Upload ────────────────────────────────────────────────

@app.route('/api/software/parse-filename', methods=['GET', 'POST'])
def parse_filename():
    """Parse software name, version, arch from filename."""
    fn = request.args.get('filename', '') if request.method == 'GET' else ''
    if not fn:
        data = request.get_json(silent=True) or {}
        fn = data.get('filename', '')
    if not fn:
        return jsonify({'code': 400, 'message': '缺少 filename'}), 400

    # Strip extension
    name_part = fn.rsplit('.', 1)[0] if '.' in fn else fn
    # Replace separators with space
    name_part = re.sub(r'[_\-\s]+', ' ', name_part)
    # Try to extract version
    version = ''
    # Pattern: vX.Y.Z, vY.Z, or digits.digits.digits...
    ver_match = re.search(
        r'(?:v|version|VER)?([\d]+(?:\.[\d]+){1,4})(?:\s*[a-zA-Z]+)?',
        name_part, re.IGNORECASE
    )
    if ver_match:
        version = ver_match.group(1)
    # Try to extract architecture
    arch = ''
    arch_pattern = r'\b(x64|x86|amd64|arm64|aarch64|i386|win32|win64|macos|linux|android)\b'
    for m in re.finditer(arch_pattern, name_part, re.IGNORECASE):
        arch = m.group(1).lower()
        break
    # Clean name: remove version + arch + common filler words (Setup, Installer, etc.)
    clean_name = re.sub(r'(?:v|version|VER)?[\d]+(?:\.[\d]+){1,4}(?:\s*[a-zA-Z]+)?', '', name_part, flags=re.IGNORECASE).strip()
    clean_name = re.sub(arch_pattern, '', clean_name, flags=re.IGNORECASE).strip()
    clean_name = re.sub(r'(setup|installer|install|portable|full|crack|patch|keygen)', '', clean_name, flags=re.IGNORECASE).strip()
    clean_name = re.sub(r'\s+', ' ', clean_name).strip()
    # Capitalize first letter
    if clean_name:
        clean_name = clean_name[0].upper() + clean_name[1:]

    return jsonify({
        'code': 0,
        'data': {
            'filename': fn,
            'name': clean_name or name_part,
            'version': version,
            'arch': arch,
        }
    })


@app.route('/api/software/extract-icon', methods=['POST'])
@require_admin
def extract_icon_api():
    """Extract icon from uploaded .exe file header (1MB max). Returns base64 PNG."""
    file = request.files.get('file')
    if not file or not file.filename:
        return jsonify({'code': 400, 'message': '缺少文件'}), 400

    fn = file.filename.lower()
    if not fn.endswith(('.exe', '.dll', '.msi')):
        return jsonify({'code': 400, 'message': '仅支持 .exe/.dll/.msi'}), 400

    import tempfile
    import base64

    # Save temp file (read first 1MB only — that's enough for resource section)
    with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as tmp:
        data = file.read(1048576)  # 1MB max
        tmp.write(data)
        tmp_path = tmp.name

    try:
        icon_data = extract_exe_icon(tmp_path, size=64)
        if icon_data:
            b64 = base64.b64encode(icon_data).decode('ascii')
            return jsonify({'code': 0, 'icon': b64})
        else:
            return jsonify({'code': 404, 'message': '未找到图标'})
    finally:
        import os
        os.unlink(tmp_path)


@app.route('/api/software/upload', methods=['POST'])
@require_admin
def upload_software():
    name = request.form.get('name', '').strip()
    category = request.form.get('category', '').strip()
    version = request.form.get('version', '').strip() or '1.0'
    description = request.form.get('description', '').strip()
    uploader = request.form.get('uploader', '').strip()
    tags_str = request.form.get('tags', '[]').strip()

    if not name:
        return jsonify({'code': 400, 'message': '软件名称不能为空'}), 400
    if not category:
        return jsonify({'code': 400, 'message': '请选择分类'}), 400

    file = request.files.get('file')
    if not file or not file.filename:
        return jsonify({'code': 400, 'message': '请上传文件'}), 400

    # Extension whitelist
    ext = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else ''
    if ext not in ALLOWED_EXTENSIONS:
        return jsonify({'code': 400, 'message': f'不支持的文件类型: .{ext}'}), 400

    # File size limit (configurable via UPLOAD_MAX_SIZE env var, default 1GB)
    file.seek(0, 2)
    fsize = file.tell()
    file.seek(0)
    if fsize > UPLOAD_MAX_SIZE:
        max_mb = UPLOAD_MAX_SIZE // (1024 * 1024)
        return jsonify({'code': 400, 'message': f'文件过大，最大支持 {max_mb}MB'}), 400

    try:
        tags = json.loads(tags_str)
    except Exception:
        tags = [t.strip() for t in tags_str.split(',') if t.strip()]

    import html as htmlmod
    original_name = secure_filename(file.filename) or 'unknown'
    slug = make_slug(name)
    conn = get_db()

    # Check if software already exists by slug
    existing = conn.execute(
        "SELECT * FROM software WHERE slug=?", (slug,)
    ).fetchone()

    if existing:
        # Update existing software info
        conn.execute(
            "UPDATE software SET name=?, category=?, description=?, tags=?, updated_at=? WHERE id=?",
            (htmlmod.escape(name), category, htmlmod.escape(description), json.dumps(tags, ensure_ascii=False),
             datetime.now().isoformat(), existing['id'])
        )
        sw_id = existing['id']
        is_new_software = False
    else:
        # Create new software
        sw_id = uuid.uuid4().hex
        conn.execute(
            "INSERT INTO software (id, slug, name, category, description, tags) VALUES (?, ?, ?, ?, ?, ?)",
            (sw_id, slug, htmlmod.escape(name), category, htmlmod.escape(description),
             json.dumps(tags, ensure_ascii=False))
        )
        is_new_software = True

    # Save file
    uid = uuid.uuid4().hex
    safe_filename = f"{uid}_{original_name}"
    file_path = UPLOAD_DIR / safe_filename
    file.save(str(file_path))
    file_size = file_path.stat().st_size

    # Extract icon from .exe/.msi
    icon_data = None
    if original_name.lower().endswith(('.exe', '.dll', '.msi')):
        icon_data = extract_exe_icon(str(file_path), size=64)

    # Save icon: auto-extracted or manually uploaded
    icon_path = ICON_DIR / f"{sw_id}.png"
    if icon_data:
        icon_path.write_bytes(icon_data)
    else:
        # Try base64 icon from form
        icon_b64 = request.form.get('icon_data', '')
        if icon_b64:
            try:
                if ',' in icon_b64:
                    icon_b64 = icon_b64.split(',', 1)[1]
                import base64
                raw = base64.b64decode(icon_b64)
                from PIL import Image as PILImage
                img = PILImage.open(io.BytesIO(raw))
                if img.mode != 'RGBA':
                    img = img.convert('RGBA')
                img = img.resize((64, 64), PILImage.Resampling.LANCZOS if hasattr(PILImage, 'Resampling') else PILImage.LANCZOS)
                buf = io.BytesIO()
                img.save(buf, format='PNG')
                icon_path.write_bytes(buf.getvalue())
            except Exception as e:
                print(f"Icon save error: {e}")
        else:
            # Try manual icon file upload (legacy)
            icon_file = request.files.get('icon')
            if icon_file and icon_file.filename:
                from PIL import Image as PILImage
                tmp = io.BytesIO(icon_file.read())
                try:
                    img = PILImage.open(tmp)
                    if img.mode != 'RGBA':
                        img = img.convert('RGBA')
                    img = img.resize((64, 64), PILImage.Resampling.LANCZOS if hasattr(PILImage, 'Resampling') else PILImage.LANCZOS)
                    buf = io.BytesIO()
                    img.save(buf, format='PNG')
                    icon_path.write_bytes(buf.getvalue())
                except:
                    pass

    # Save version
    ver_id = uuid.uuid4().hex
    try:
        conn.execute(
            "INSERT INTO software_versions (id, software_id, version, filename, original_name, file_size, uploader) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (ver_id, sw_id, version, safe_filename, original_name, file_size, uploader)
        )
    except sqlite3.IntegrityError:
        # Same version already active — update the existing version
        old_ver = conn.execute(
            "SELECT * FROM software_versions WHERE software_id=? AND version=? AND status='active'",
            (sw_id, version)
        ).fetchone()

        # Archive the old one
        if old_ver:
            old_file = UPLOAD_DIR / old_ver['filename']
            if old_file.exists():
                old_file.unlink()
            conn.execute(
                "UPDATE software_versions SET status='archived' WHERE id=?",
                (old_ver['id'],)
            )

        conn.execute(
            "INSERT INTO software_versions (id, software_id, version, filename, original_name, file_size, uploader) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (ver_id, sw_id, version, safe_filename, original_name, file_size, uploader)
        )

    conn.commit()
    conn.close()

    return jsonify({
        'code': 0,
        'message': '上传成功' if is_new_software else '新版本上传成功',
        'data': {
            'slug': slug,
            'version': version,
            'size': file_size,
            'size_text': format_size(file_size),
            'is_new_software': is_new_software,
        }
    })


# ─── Download ──────────────────────────────────────────────

@app.route('/api/software/<slug>/download', methods=['GET'])
@app.route('/api/software/<slug>/download/<version_id>', methods=['GET'])
def download_software(slug, version_id=None):
    conn = get_db()
    sw = conn.execute("SELECT * FROM software WHERE slug=?", (slug,)).fetchone()
    if not sw:
        conn.close()
        return jsonify({'code': 404, 'message': '软件不存在'}), 404

    if version_id:
        ver = conn.execute("SELECT * FROM software_versions WHERE id=?", (version_id,)).fetchone()
    else:
        # Default: latest active version
        ver = conn.execute(
            "SELECT * FROM software_versions WHERE software_id=? AND status='active' ORDER BY created_at DESC LIMIT 1",
            (sw['id'],)
        ).fetchone()

    conn.close()

    if not ver:
        return jsonify({'code': 404, 'message': '版本不存在'}), 404

    # Increment download count
    conn = get_db()
    conn.execute(
        "UPDATE software_versions SET download_count = download_count + 1 WHERE id=?",
        (ver['id'],)
    )
    conn.commit()
    conn.close()

    filepath = UPLOAD_DIR / ver['filename']
    if not filepath.exists():
        return jsonify({'code': 404, 'message': '文件已不存在'}), 404

    return send_file(str(filepath), as_attachment=True, download_name=ver['original_name'])


# ─── Version Management ────────────────────────────────────

@app.route('/api/software/<slug>/version/<version_id>', methods=['PATCH'])
@require_admin
def update_version(slug, version_id):
    conn = get_db()
    sw = conn.execute("SELECT * FROM software WHERE slug=?", (slug,)).fetchone()
    if not sw:
        conn.close()
        return jsonify({'code': 404, 'message': '软件不存在'}), 404

    ver = conn.execute(
        "SELECT * FROM software_versions WHERE id=? AND software_id=?",
        (version_id, sw['id'])
    ).fetchone()
    if not ver:
        conn.close()
        return jsonify({'code': 404, 'message': '版本不存在'}), 404

    data = request.get_json(force=True) if request.is_json else {}
    actions = data.get('actions', [])

    for action in actions:
        if action == 'archive':
            conn.execute(
                "UPDATE software_versions SET status='archived' WHERE id=?",
                (version_id,)
            )
        elif action == 'activate':
            conn.execute(
                "UPDATE software_versions SET status='active' WHERE id=?",
                (version_id,)
            )
        elif action == 'delete':
            # Soft delete + remove file
            fpath = UPLOAD_DIR / ver['filename']
            if fpath.exists():
                fpath.unlink()
            conn.execute("DELETE FROM software_versions WHERE id=?", (version_id,))

    conn.commit()
    conn.close()
    return jsonify({'code': 0, 'message': '操作成功'})


@app.route('/api/software/<slug>', methods=['PATCH'])
@require_admin
def update_software(slug):
    conn = get_db()
    sw = conn.execute("SELECT * FROM software WHERE slug=?", (slug,)).fetchone()
    if not sw:
        conn.close()
        return jsonify({'code': 404, 'message': '软件不存在'}), 404

    data = request.get_json(force=True) if request.is_json else {}
    actions = data.get('actions', [])

    for action in actions:
        if action == 'archive':
            conn.execute("UPDATE software SET status='archived' WHERE id=?", (sw['id'],))
        elif action == 'activate':
            conn.execute("UPDATE software SET status='active' WHERE id=?", (sw['id'],))
        elif action == 'delete':
            # Delete all versions and files
            versions = conn.execute(
                "SELECT * FROM software_versions WHERE software_id=?",
                (sw['id'],)
            ).fetchall()
            for v in versions:
                fpath = UPLOAD_DIR / v['filename']
                if fpath.exists():
                    fpath.unlink()
            conn.execute("DELETE FROM software_versions WHERE software_id=?", (sw['id'],))
            conn.execute("DELETE FROM software WHERE id=?", (sw['id'],))

    # Update fields
    if 'name' in data:
        new_slug = make_slug(data['name'])
        conn.execute("UPDATE software SET name=?, slug=? WHERE id=?", (data['name'], new_slug, sw['id']))
    if 'category' in data:
        conn.execute("UPDATE software SET category=? WHERE id=?", (data['category'], sw['id']))
    if 'description' in data:
        conn.execute("UPDATE software SET description=? WHERE id=?", (data['description'], sw['id']))
    if 'tags' in data:
        conn.execute("UPDATE software SET tags=? WHERE id=?", (json.dumps(data['tags'], ensure_ascii=False), sw['id']))
    if 'icon_data' in data:
        # Update icon
        icon_b64 = data['icon_data']
        if icon_b64:
            try:
                if ',' in icon_b64:
                    icon_b64 = icon_b64.split(',', 1)[1]
                import base64
                from PIL import Image as PILImage
                raw = base64.b64decode(icon_b64)
                img = PILImage.open(io.BytesIO(raw))
                if img.mode != 'RGBA':
                    img = img.convert('RGBA')
                img = img.resize((64, 64), PILImage.Resampling.LANCZOS if hasattr(PILImage, 'Resampling') else PILImage.LANCZOS)
                buf = io.BytesIO()
                img.save(buf, format='PNG')
                icon_path = ICON_DIR / f"{sw['id']}.png"
                icon_path.write_bytes(buf.getvalue())
            except Exception as e:
                print(f"Icon update error: {e}")

    conn.execute("UPDATE software SET updated_at=? WHERE id=?", (datetime.now().isoformat(), sw['id']))
    conn.commit()
    conn.close()
    return jsonify({'code': 0, 'message': '操作成功'})


@app.route('/api/admin/software/<slug>', methods=['GET'])
@require_admin
def get_software_detail(slug):
    """Get software detail for editing."""
    conn = get_db()
    sw = conn.execute("SELECT * FROM software WHERE slug=?", (slug,)).fetchone()
    if not sw:
        conn.close()
        return jsonify({'code': 404, 'message': '软件不存在'}), 404
    conn.close()
    sw_dict = software_to_dict(sw)
    sw_dict['tags'] = json.loads(sw['tags']) if sw['tags'] else []
    # Check if icon exists
    icon_path = ICON_DIR / f"{sw['id']}.png"
    sw_dict['icon_url'] = f"/software_icons/{sw['id']}.png" if icon_path.exists() else None
    return jsonify({'code': 0, 'data': sw_dict})


# ─── Search ────────────────────────────────────────────────

@app.route('/api/software/search', methods=['GET'])
def search_software():
    q = request.args.get('q', '').strip().lower()
    category = request.args.get('category', '').strip()
    conn = get_db()

    conditions = ["status='active'"]
    params = []
    if q:
        conditions.append("(name LIKE ? OR description LIKE ? OR tags LIKE ?)")
        params.extend([f'%{q}%', f'%{q}%', f'%{q}%'])
    if category:
        conditions.append("category=?")
        params.append(category)

    where = " AND ".join(conditions)
    rows = conn.execute(f"SELECT * FROM software WHERE {where} ORDER BY updated_at DESC", params).fetchall()

    result = []
    for sw in rows:
        sw_dict = software_to_dict(sw)
        ver = conn.execute(
            "SELECT * FROM software_versions WHERE software_id=? AND status='active' ORDER BY created_at DESC LIMIT 1",
            (sw['id'],)
        ).fetchone()
        sw_dict['latest_version'] = version_to_dict(ver) if ver else None
        sw_dict['version_count'] = conn.execute(
            "SELECT COUNT(*) FROM software_versions WHERE software_id=?",
            (sw['id'],)
        ).fetchone()[0]
        result.append(sw_dict)

    conn.close()

    return jsonify({'code': 0, 'data': result, 'total': len(result)})


# ─── Request APIs ──────────────────────────────────────────

@app.route('/api/request/list', methods=['GET'])
def list_requests():
    conn = get_db()
    rows = conn.execute("SELECT * FROM requests ORDER BY created_at DESC").fetchall()
    conn.close()
    return jsonify({
        'code': 0,
        'data': [{'id': r['id'], 'type': r['type'], 'title': r['title'],
                   'description': r['description'], 'submitter': r['submitter'],
                   'status': r['status'], 'created_at': r['created_at']} for r in rows]
    })


@app.route('/api/request/submit', methods=['POST'])
def submit_request():
    data = request.get_json(force=True) if request.is_json else {}
    if not data.get('title'):
        return jsonify({'code': 400, 'message': '标题不能为空'}), 400

    import html as htmlmod
    uid = uuid.uuid4().hex
    conn = get_db()
    conn.execute(
        "INSERT INTO requests (id, type, title, description, submitter) VALUES (?, ?, ?, ?, ?)",
        (uid, data.get('type', 'software'), htmlmod.escape(data['title']),
         htmlmod.escape(data.get('description', '')), htmlmod.escape(data.get('submitter', '')))
    )
    conn.commit()
    conn.close()

    req_path = BASE_DIR / 'requests.json'
    reqs = []
    if req_path.exists():
        try:
            with open(req_path) as f:
                reqs = json.load(f)
        except Exception:
            reqs = []
    reqs.insert(0, {
        'id': uid, 'type': data.get('type', 'software'), 'title': data['title'],
        'description': data.get('description', ''), 'submitter': data.get('submitter', ''),
        'status': 'pending', 'created_at': datetime.now().isoformat()
    })
    with open(req_path, 'w', encoding='utf-8') as f:
        json.dump(reqs, f, ensure_ascii=False, indent=2)

    return jsonify({'code': 0, 'message': '提交成功', 'data': {'id': uid}})


# ─── Admin APIs ────────────────────────────────────────────

@app.route('/api/admin/stats', methods=['GET'])
@require_admin
def admin_stats():
    conn = get_db()
    sw_total = conn.execute("SELECT COUNT(*) FROM software").fetchone()[0]
    sw_active = conn.execute("SELECT COUNT(*) FROM software WHERE status='active'").fetchone()[0]
    sw_archived = conn.execute("SELECT COUNT(*) FROM software WHERE status='archived'").fetchone()[0]
    ver_total = conn.execute("SELECT COUNT(*) FROM software_versions").fetchone()[0]
    total_downloads = conn.execute("SELECT COALESCE(SUM(download_count),0) FROM software_versions").fetchone()[0]
    total_disk = conn.execute("SELECT COALESCE(SUM(file_size),0) FROM software_versions").fetchone()[0]
    req_total = conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
    req_pending = conn.execute("SELECT COUNT(*) FROM requests WHERE status='pending'").fetchone()[0]
    conn.close()
    return jsonify({
        'code': 0,
        'data': {
            'software_total': sw_total,
            'software_active': sw_active,
            'software_archived': sw_archived,
            'version_total': ver_total,
            'total_downloads': total_downloads,
            'total_disk': format_size(total_disk),
            'request_total': req_total,
            'request_pending': req_pending,
        }
    })


@app.route('/api/admin/software', methods=['GET'])
@require_admin
def admin_software_list():
    """Full software list including archived"""
    status = request.args.get('status', '').strip()
    q = request.args.get('q', '').strip()
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 20))
    offset = (page - 1) * per_page

    conn = get_db()
    conditions = []
    params = []
    if status:
        conditions.append("status=?")
        params.append(status)
    if q:
        conditions.append("(name LIKE ? OR description LIKE ?)")
        params.extend([f'%{q}%', f'%{q}%'])
    where = (" AND ".join(conditions)) if conditions else "1=1"

    total = conn.execute(f"SELECT COUNT(*) FROM software WHERE {where}", params).fetchone()[0]
    rows = conn.execute(
        f"SELECT * FROM software WHERE {where} ORDER BY updated_at DESC LIMIT ? OFFSET ?",
        params + [per_page, offset]
    ).fetchall()

    result = []
    for sw in rows:
        sw_dict = software_to_dict(sw)
        # Latest active version
        ver = conn.execute(
            "SELECT * FROM software_versions WHERE software_id=? AND status='active' ORDER BY created_at DESC LIMIT 1",
            (sw['id'],)
        ).fetchone()
        sw_dict['latest_version'] = version_to_dict(ver) if ver else None
        sw_dict['version_count'] = conn.execute(
            "SELECT COUNT(*) FROM software_versions WHERE software_id=?",
            (sw['id'],)
        ).fetchone()[0]
        sw_dict['total_downloads'] = conn.execute(
            "SELECT COALESCE(SUM(download_count),0) FROM software_versions WHERE software_id=?",
            (sw['id'],)
        ).fetchone()[0]
        result.append(sw_dict)

    conn.close()
    return jsonify({
        'code': 0,
        'data': result,
        'total': total,
        'page': page,
        'per_page': per_page,
    })


@app.route('/api/admin/software/<slug>/versions', methods=['GET'])
@require_admin
def admin_software_versions(slug):
    conn = get_db()
    sw = conn.execute("SELECT * FROM software WHERE slug=?", (slug,)).fetchone()
    if not sw:
        conn.close()
        return jsonify({'code': 404, 'message': '软件不存在'}), 404

    versions = conn.execute(
        "SELECT * FROM software_versions WHERE software_id=? ORDER BY created_at DESC",
        (sw['id'],)
    ).fetchall()
    conn.close()
    return jsonify({
        'code': 0,
        'data': [version_to_dict(v) for v in versions]
    })


@app.route('/api/admin/request', methods=['GET'])
@require_admin
def admin_request_list():
    status = request.args.get('status', '').strip()
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    offset = (page - 1) * per_page

    conn = get_db()
    if status:
        total = conn.execute("SELECT COUNT(*) FROM requests WHERE status=?", (status,)).fetchone()[0]
        rows = conn.execute(
            "SELECT * FROM requests WHERE status=? ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (status, per_page, offset)
        ).fetchall()
    else:
        total = conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
        rows = conn.execute(
            "SELECT * FROM requests ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (per_page, offset)
        ).fetchall()
    conn.close()
    return jsonify({
        'code': 0,
        'data': [{'id': r['id'], 'type': r['type'], 'title': r['title'],
                   'description': r['description'], 'submitter': r['submitter'],
                   'status': r['status'], 'created_at': r['created_at']} for r in rows],
        'total': total,
    })


@app.route('/api/admin/request/<req_id>', methods=['PATCH'])
@require_admin
def admin_request_update(req_id):
    data = request.get_json(force=True) if request.is_json else {}
    conn = get_db()
    row = conn.execute("SELECT * FROM requests WHERE id=?", (req_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({'code': 404, 'message': '需求不存在'}), 404

    if 'status' in data:
        conn.execute("UPDATE requests SET status=? WHERE id=?", (data['status'], req_id))
    if 'description' in data:
        conn.execute("UPDATE requests SET description=? WHERE id=?", (data['description'], req_id))
    conn.commit()
    conn.close()
    return jsonify({'code': 0, 'message': '更新成功'})


# ─── Tools Management (blocked tools) ────────────────────────

@app.route('/api/admin/tools', methods=['GET'])
@require_admin
def admin_tools_list():
    """List all tools from tools.json with blocked status"""
    try:
        with open(BASE_DIR / 'tools.json') as f:
            data = json.load(f)
    except Exception:
        return jsonify({'code': 0, 'data': [], 'total': 0})

    # Get blocked tool IDs from DB
    conn = get_db()
    blocked = {r['tool_id'] for r in conn.execute("SELECT tool_id FROM blocked_tools").fetchall()}
    conn.close()

    tools = []
    for t in data.get('tools', []):
        t['blocked'] = t['id'] in blocked or t.get('visible') == False
        tools.append({
            'id': t['id'],
            'name': t['name'],
            'category': t.get('category', ''),
            'description': t.get('description', ''),
            'blocked': t['blocked'],
            'icon': t.get('icon', ''),
        })

    return jsonify({'code': 0, 'data': tools, 'total': len(tools)})


@app.route('/api/admin/tool/block', methods=['GET', 'POST'])
@require_admin
def admin_block_tool():
    if request.method == 'POST' and request.is_json:
        data = request.get_json(force=True)
    elif request.method == 'GET':
        data = request.args
    else:
        data = {}
    tool_id = data.get('tool_id', '')
    if not tool_id:
        return jsonify({'code': 400, 'message': '缺少 tool_id'}), 400

    conn = get_db()
    existing = conn.execute("SELECT * FROM blocked_tools WHERE tool_id=?", (tool_id,)).fetchone()
    if existing:
        conn.close()
        return jsonify({'code': 0, 'message': '已屏蔽', 'data': {'blocked': True}})

    uid = uuid.uuid4().hex
    # Try to get tool name
    try:
        with open(BASE_DIR / 'tools.json') as f:
            raw = json.load(f)
        tool_name = next((t['name'] for t in raw.get('tools', []) if t['id'] == tool_id), tool_id)
    except Exception:
        tool_name = tool_id

    conn.execute(
        "INSERT INTO blocked_tools (id, tool_id, tool_name) VALUES (?, ?, ?)",
        (uid, tool_id, tool_name)
    )
    conn.commit()
    conn.close()
    return jsonify({'code': 0, 'message': '已屏蔽', 'data': {'blocked': True}})


@app.route('/api/admin/tool/unblock', methods=['GET', 'POST'])
@require_admin
def admin_unblock_tool():
    data = request.get_json(force=True) if request.is_json else {}
    tool_id = data.get('tool_id', '')
    if not tool_id:
        return jsonify({'code': 400, 'message': '缺少 tool_id'}), 400

    conn = get_db()
    conn.execute("DELETE FROM blocked_tools WHERE tool_id=?", (tool_id,))
    conn.commit()
    conn.close()
    return jsonify({'code': 0, 'message': '已取消屏蔽', 'data': {'blocked': False}})

@app.route('/api/tools/blocked', methods=['GET'])
def public_blocked_tools():
    """Public endpoint: return list of blocked tool IDs for the homepage."""
    conn = get_db()
    rows = conn.execute("SELECT tool_id FROM blocked_tools").fetchall()
    conn.close()
    return jsonify({'code': 0, 'data': [r['tool_id'] for r in rows]})


# ─── Click tracking (keep existing) ────────────────────────

CLICKS_DB = BASE_DIR / 'clicks.db'


def get_clicks_db():
    conn = sqlite3.connect(str(CLICKS_DB))
    conn.execute("CREATE TABLE IF NOT EXISTS clicks (id TEXT PRIMARY KEY, count INTEGER DEFAULT 1)")
    conn.commit()
    return conn


@app.route('/api/clicks', methods=['POST'])
def track_click():
    data = request.get_json(force=True, silent=True) or {}
    tool_id = data.get('toolId') or data.get('tool_id', '') or data.get('id', '')
    conn = get_clicks_db()
    conn.execute(
        "INSERT INTO clicks VALUES (?, 1) ON CONFLICT(id) DO UPDATE SET count = count + 1",
        (tool_id,)
    )
    conn.commit()
    row = conn.execute("SELECT count FROM clicks WHERE id=?", (tool_id,)).fetchone()
    conn.close()
    return jsonify({'clicks': row[0] if row else 1})


@app.route('/api/clicks/<tool_id>', methods=['GET'])
def get_clicks(tool_id):
    conn = get_clicks_db()
    row = conn.execute("SELECT count FROM clicks WHERE id=?", (tool_id,)).fetchone()
    conn.close()
    return jsonify({'clicks': row[0] if row else 0})


if __name__ == '__main__':
    init_db()
    print("Starting server on 0.0.0.0:8105")
    app.run(host='0.0.0.0', port=8105, threaded=True)
