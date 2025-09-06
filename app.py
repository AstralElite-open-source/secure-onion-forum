import os
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Optional, Tuple
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

from flask import (
    Flask,
    abort,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from markupsafe import Markup
from markdown_it import MarkdownIt
import bleach
import hashlib
from cryptography.fernet import Fernet

def _get_persistent_secret() -> str:
    """Return a stable secret key.

    Priority:
    1) SECRET_KEY env var if provided and non-empty.
    2) Read from a file located alongside the database file (e.g., /data/secret_key).
    3) Generate a new one, write it to that file, and use it.
    If file operations fail, fall back to an in-memory random key (sessions will reset on restart).
    """
    sk = os.environ.get("SECRET_KEY", "").strip()
    if sk:
        return sk

    db_path_str = os.environ.get("FORUM_DB_PATH", "forum.db")
    try:
        base = Path(db_path_str).parent if Path(db_path_str).parent else Path(".")
        secret_file = base / "secret_key"
        if secret_file.exists():
            try:
                return secret_file.read_text(encoding="utf-8").strip()
            except Exception:
                pass

        # Generate and persist
        new_sk = secrets.token_hex(32)
        try:
            base.mkdir(parents=True, exist_ok=True)
            secret_file.write_text(new_sk, encoding="utf-8")
            try:
                os.chmod(secret_file, 0o600)  # best-effort
            except Exception:
                pass
        except Exception:
            # Could not persist; return volatile key
            return new_sk
        return new_sk
    except Exception:
        return secrets.token_hex(32)


def create_app() -> Flask:
    app = Flask(
        __name__,
        static_folder="static",
        template_folder="templates",
    )

    # Configuration
    app.config.update(
        DATABASE=os.environ.get("FORUM_DB_PATH", "forum.db"),
        SECRET_KEY=_get_persistent_secret(),
        MAX_CONTENT_LENGTH=256 * 1024,  # 256 KB per request
        TEMPLATES_AUTO_RELOAD=True,
    REQUIRE_LOGIN=os.environ.get("REQUIRE_LOGIN", "1") in {"1", "true", "yes"},
    ADMIN_USER=os.environ.get("ADMIN_USER", ""),
    ADMIN_PASS=os.environ.get("ADMIN_PASS", ""),
    USER_ENC_KEY_PATH=None,  # resolved later next to DB
    )

    # Ensure data folder exists if using a nested path
    db_path = Path(app.config["DATABASE"])  # type: ignore[index]
    if db_path.parent and not db_path.parent.exists():
        db_path.parent.mkdir(parents=True, exist_ok=True)

    # Database helpers
    def get_db() -> sqlite3.Connection:
        if "db" not in g:
            conn = sqlite3.connect(app.config["DATABASE"])  # type: ignore[index]
            conn.row_factory = sqlite3.Row
            # Conservative pragmas suited for Tor hidden services (durable, but still performant)
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
            g.db = conn
        return g.db  # type: ignore[return-value]

    def close_db(_: Optional[BaseException] = None) -> None:
        db = g.pop("db", None)
        if db is not None:
            db.close()

    app.teardown_appcontext(close_db)

    def _get_user_enc_key_and_salt() -> Tuple[bytes, bytes]:
        """Get or create a symmetric key and a salt for username hashing.

        - Key is Fernet key stored at /data/user_enc_key (alongside DB)
        - Salt is stored at /data/user_hash_salt (32 random bytes, hex)
        """
        dbp = Path(app.config["DATABASE"])  # type: ignore[index]
        base = dbp.parent if dbp.parent else Path(".")
        key_file = base / "user_enc_key"
        salt_file = base / "user_hash_salt"

        if key_file.exists():
            key = key_file.read_bytes().strip()
        else:
            key = Fernet.generate_key()
            base.mkdir(parents=True, exist_ok=True)
            key_file.write_bytes(key)
            try:
                os.chmod(key_file, 0o600)
            except Exception:
                pass

        if salt_file.exists():
            salt_hex = salt_file.read_text(encoding="utf-8").strip()
            try:
                salt = bytes.fromhex(salt_hex)
            except Exception:
                salt = os.urandom(32)
        else:
            salt = os.urandom(32)
            base.mkdir(parents=True, exist_ok=True)
            salt_file.write_text(salt.hex(), encoding="utf-8")
            try:
                os.chmod(salt_file, 0o600)
            except Exception:
                pass
        return key, salt

    def _username_hash(s: str, salt: bytes) -> str:
        # case-insensitive uniqueness
        data = s.lower().encode("utf-8") + b"|" + salt
        return hashlib.sha256(data).hexdigest()

    # Content encryption helpers (posts/comments/threads)
    def _get_content_enc_key() -> bytes:
        dbp = Path(app.config["DATABASE"])  # type: ignore[index]
        base = dbp.parent if dbp.parent else Path(".")
        key_file = base / "content_enc_key"
        if key_file.exists():
            return key_file.read_bytes().strip()
        key = Fernet.generate_key()
        base.mkdir(parents=True, exist_ok=True)
        key_file.write_bytes(key)
        try:
            os.chmod(key_file, 0o600)
        except Exception:
            pass
        return key

    def _dec_optional(f: Fernet, blob) -> str:
        if not blob:
            return ""
        try:
            return f.decrypt(blob).decode("utf-8")
        except Exception:
            return ""

    def init_db() -> None:
        db = get_db()
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS categories (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                slug    TEXT UNIQUE NOT NULL,
                name    TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS threads (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                title           TEXT NOT NULL,
                posts_count     INTEGER NOT NULL DEFAULT 0,
                created_at      INTEGER NOT NULL,
                last_activity_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS posts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                thread_id   INTEGER NOT NULL,
                author      TEXT,
                content     TEXT NOT NULL,
                created_at  INTEGER NOT NULL,
                FOREIGN KEY(thread_id) REFERENCES threads(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_threads_last_activity ON threads(last_activity_at DESC);
            CREATE INDEX IF NOT EXISTS idx_posts_thread_id ON posts(thread_id);

            CREATE TABLE IF NOT EXISTS comments (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id     INTEGER NOT NULL,
                author      TEXT,
                content     TEXT NOT NULL,
                created_at  INTEGER NOT NULL,
                FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_comments_post_id ON comments(post_id);

            -- Users for optional login enforcement
            CREATE TABLE IF NOT EXISTS users (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                -- plaintext username removed from uniqueness; store enc + deterministic hash instead
                username        TEXT NOT NULL,
                username_enc    BLOB,
                username_hash   TEXT,
                password_hash   TEXT NOT NULL,
                is_admin        INTEGER NOT NULL DEFAULT 0
            );
            -- ensure unique on username_hash if present (fallback to username for legacy rows)
            CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_hash ON users(username_hash);
            """
        )
        # Migrations: add category_id to threads if missing
        cur = db.execute("PRAGMA table_info(threads)")
        cols = {row[1] for row in cur.fetchall()}
        if "category_id" not in cols:
            db.execute("ALTER TABLE threads ADD COLUMN category_id INTEGER")
            db.execute(
                "CREATE INDEX IF NOT EXISTS idx_threads_category ON threads(category_id)"
            )
        db.commit()

        # Migrate users table columns if missing
        cur = db.execute("PRAGMA table_info(users)")
        ucols = {row[1] for row in cur.fetchall()}
        altered = False
        if "username_enc" not in ucols:
            db.execute("ALTER TABLE users ADD COLUMN username_enc BLOB")
            altered = True
        if "username_hash" not in ucols:
            db.execute("ALTER TABLE users ADD COLUMN username_hash TEXT")
            altered = True
        if altered:
            db.commit()

        # Backfill encryption/hash for existing users
        key, salt = _get_user_enc_key_and_salt()
        f = Fernet(key)
        rows = db.execute("SELECT id, username, username_enc, username_hash FROM users").fetchall()
        for r in rows:
            uid = r[0]
            uname = r[1] or ""
            enc = r[2]
            hsh = r[3]
            if not hsh:
                hsh = _username_hash(uname, salt)
                db.execute("UPDATE users SET username_hash=? WHERE id=?", (hsh, uid))
            if not enc:
                enc_bytes = f.encrypt(uname.encode("utf-8"))
                db.execute("UPDATE users SET username_enc=? WHERE id=?", (enc_bytes, uid))
        # Drop legacy username unique index and clear plaintext usernames (keep empty string as not-null)
        try:
            db.execute("DROP INDEX IF EXISTS idx_users_username")
        except Exception:
            pass
        db.execute("UPDATE users SET username='' WHERE username IS NOT NULL")
        db.commit()

        # Bootstrap admin user if provided via env and not present
        admin_user = app.config.get("ADMIN_USER") or ""
        admin_pass = app.config.get("ADMIN_PASS") or ""
        if admin_user and admin_pass:
            # lookup by hash for deterministic match
            key, salt = _get_user_enc_key_and_salt()
            h = _username_hash(admin_user, salt)
            row = db.execute("SELECT id FROM users WHERE username_hash = ?", (h,)).fetchone()
            if not row:
                db.execute(
                    "INSERT INTO users (username, username_enc, username_hash, password_hash, is_admin) VALUES ('', ?, ?, ?, 1)",
                    (
                        Fernet(key).encrypt(admin_user.encode("utf-8")),
                        h,
                        generate_password_hash(admin_pass),
                    ),
                )
                db.commit()

        # Seed default categories
        existing = db.execute("SELECT COUNT(*) FROM categories").fetchone()[0]
        if existing == 0:
            defaults = [
                ("technology", "Technology"),
                ("learning", "Learning"),
                ("politics", "Politics"),
                ("secret", "Secret"),
            ]
            db.executemany(
                "INSERT INTO categories (slug, name) VALUES (?, ?)", defaults
            )
            db.commit()

        # Ensure existing threads have a category (default to first category)
        row = db.execute("SELECT id FROM categories ORDER BY id ASC LIMIT 1").fetchone()
        if row:
            default_cat_id = row[0]
            db.execute(
                "UPDATE threads SET category_id = COALESCE(category_id, ?) WHERE category_id IS NULL",
                (default_cat_id,),
            )
            db.commit()

        # Encryption migrations for content at rest
        # 1) Add columns if missing
        # threads: title_enc
        cur = db.execute("PRAGMA table_info(threads)")
        tcols = {row[1] for row in cur.fetchall()}
        if "title_enc" not in tcols:
            db.execute("ALTER TABLE threads ADD COLUMN title_enc BLOB")
            db.commit()

        # posts: author_enc, content_enc
        cur = db.execute("PRAGMA table_info(posts)")
        pcols = {row[1] for row in cur.fetchall()}
        added = False
        if "author_enc" not in pcols:
            db.execute("ALTER TABLE posts ADD COLUMN author_enc BLOB")
            added = True
        if "content_enc" not in pcols:
            db.execute("ALTER TABLE posts ADD COLUMN content_enc BLOB")
            added = True
        if added:
            db.commit()

        # comments: author_enc, content_enc
        cur = db.execute("PRAGMA table_info(comments)")
        ccols = {row[1] for row in cur.fetchall()}
        added = False
        if "author_enc" not in ccols:
            db.execute("ALTER TABLE comments ADD COLUMN author_enc BLOB")
            added = True
        if "content_enc" not in ccols:
            db.execute("ALTER TABLE comments ADD COLUMN content_enc BLOB")
            added = True
        if added:
            db.commit()

        # 2) Backfill encryption and scrub plaintext
        cf = Fernet(_get_content_enc_key())
        # threads
        rows = db.execute("SELECT id, title, title_enc FROM threads").fetchall()
        for r in rows:
            if not r[2] and (r[1] or "") != "":
                enc = cf.encrypt((r[1] or "").encode("utf-8"))
                db.execute("UPDATE threads SET title_enc=?, title='' WHERE id=?", (enc, r[0]))
        db.commit()
        # posts
        rows = db.execute("SELECT id, author, content, author_enc, content_enc FROM posts").fetchall()
        for r in rows:
            pid = r[0]
            author = r[1] or ""
            content = r[2] or ""
            aenc = r[3]
            cenc = r[4]
            updates = []
            params = []
            if not aenc and author != "":
                updates.append("author_enc=?")
                params.append(cf.encrypt(author.encode("utf-8")))
            if not cenc and content != "":
                updates.append("content_enc=?")
                params.append(cf.encrypt(content.encode("utf-8")))
            if updates:
                set_clause = ", ".join(updates) + ", author='', content=''"
                db.execute(f"UPDATE posts SET {set_clause} WHERE id=?", (*params, pid))
        db.commit()
        # comments
        rows = db.execute("SELECT id, author, content, author_enc, content_enc FROM comments").fetchall()
        for r in rows:
            cid = r[0]
            author = r[1] or ""
            content = r[2] or ""
            aenc = r[3]
            cenc = r[4]
            updates = []
            params = []
            if not aenc and author != "":
                updates.append("author_enc=?")
                params.append(cf.encrypt(author.encode("utf-8")))
            if not cenc and content != "":
                updates.append("content_enc=?")
                params.append(cf.encrypt(content.encode("utf-8")))
            if updates:
                set_clause = ", ".join(updates) + ", author='', content=''"
                db.execute(f"UPDATE comments SET {set_clause} WHERE id=?", (*params, cid))
        db.commit()

    # CSRF protection minimal and session bootstrap
    @app.before_request
    def csrf_and_session_bootstrap() -> None:  # pragma: no cover - trivial
        # Initialize CSRF token
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(16)

        # Enforce CSRF on POSTs
        if request.method == "POST":
            token_form = request.form.get("csrf_token", "")
            token_sess = session.get("csrf_token", "")
            if not token_form or token_form != token_sess:
                abort(400, description="Invalid CSRF token")

    @app.after_request
    def set_security_headers(resp):  # pragma: no cover - trivial
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        # CSP allows only same-origin resources
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'none'",
        )
        return resp

    # (Invite-only removed)

    # Login enforcement (if REQUIRE_LOGIN is true)
    @app.before_request
    def enforce_login():
        if not app.config.get("REQUIRE_LOGIN", False):
            return None
        allowed = {"login", "healthz", "static"}
        if request.endpoint in allowed:
            return None
        if session.get("user_id"):
            return None
        return redirect(url_for("login"))

    # Utilities
    def now_ts() -> int:
        return int(time.time())

    def clamp_text(s: str, max_len: int) -> str:
        return s if len(s) <= max_len else s[: max_len - 1].rstrip() + "…"

    # Routes
    def get_categories_list():
        db = get_db()
        return db.execute(
            "SELECT id, slug, name FROM categories ORDER BY name ASC"
        ).fetchall()

    @app.route("/")
    def index():
        db = get_db()
        categories = get_categories_list()
        cat_slug = request.args.get("cat")
        cat = None
        if cat_slug:
            cat = db.execute(
                "SELECT id, slug, name FROM categories WHERE slug = ?",
                (cat_slug,),
            ).fetchone()
        try:
            page = max(int(request.args.get("page", "1")), 1)
        except ValueError:
            page = 1
        per_page = 20
        offset = (page - 1) * per_page

        cf = Fernet(_get_content_enc_key())
        if cat is None:
            total_threads = db.execute("SELECT COUNT(*) FROM threads").fetchone()[0]
            _rows = db.execute(
                """
                SELECT t.id, t.title, t.title_enc, t.posts_count, t.created_at, t.last_activity_at,
                       c.name AS category_name, c.slug AS category_slug
                FROM threads t
                LEFT JOIN categories c ON c.id = t.category_id
                ORDER BY t.last_activity_at DESC, t.id DESC
                LIMIT ? OFFSET ?
                """,
                (per_page, offset),
            ).fetchall()
        else:
            total_threads = db.execute(
                "SELECT COUNT(*) FROM threads WHERE category_id = ?",
                (cat["id"],),
            ).fetchone()[0]
            _rows = db.execute(
                """
                SELECT t.id, t.title, t.title_enc, t.posts_count, t.created_at, t.last_activity_at,
                       c.name AS category_name, c.slug AS category_slug
                FROM threads t
                LEFT JOIN categories c ON c.id = t.category_id
                WHERE t.category_id = ?
                ORDER BY t.last_activity_at DESC, t.id DESC
                LIMIT ? OFFSET ?
                """,
                (cat["id"], per_page, offset),
            ).fetchall()
        threads = []
        for r in _rows:
            title = _dec_optional(cf, r["title_enc"]) or (r["title"] or "")
            row = dict(r)
            row["title"] = title
            threads.append(row)

        total_pages = max((total_threads + per_page - 1) // per_page, 1)
        # Recent posts (global)
        _rp = db.execute(
            """
            SELECT p.id as post_id, p.created_at, p.author, p.author_enc, p.content, p.content_enc,
                   t.id as thread_id, t.title as thread_title, t.title_enc as thread_title_enc,
                   c.name as category_name, c.slug as category_slug
            FROM posts p
            JOIN threads t ON t.id = p.thread_id
            LEFT JOIN categories c ON c.id = t.category_id
            ORDER BY p.id DESC
            LIMIT 10
            """
        ).fetchall()
        recent_posts = []
        for r in _rp:
            content = _dec_optional(cf, r["content_enc"]) or (r["content"] or "")
            author = _dec_optional(cf, r["author_enc"]) or (r["author"] or "")
            ttitle = _dec_optional(cf, r["thread_title_enc"]) or (r["thread_title"] or "")
            row = dict(r)
            row["content"] = content
            row["author"] = author if author else "anon"
            row["thread_title"] = ttitle
            recent_posts.append(row)
        return render_template(
            "index.html",
            threads=threads,
            categories=categories,
            cat=cat,
            recent_posts=recent_posts,
            page=page,
            total_pages=total_pages,
        )

    # (Invite-only removed)

    # Authentication
    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = ""
        db = get_db()
        users_count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if request.method == "POST":
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password") or ""
            if username and password:
                if users_count == 0:
                    # Bootstrap first admin user
                    key, salt = _get_user_enc_key_and_salt()
                    h = _username_hash(username, salt)
                    enc = Fernet(key).encrypt(username.encode("utf-8"))
                    db.execute(
                        "INSERT INTO users (username, username_enc, username_hash, password_hash, is_admin) VALUES ('', ?, ?, ?, 1)",
                        (enc, h, generate_password_hash(password)),
                    )
                    db.commit()
                    user = db.execute(
                        "SELECT id, password_hash, is_admin FROM users WHERE username_hash=?",
                        (h,),
                    ).fetchone()
                    session["user_id"] = int(user["id"])  # type: ignore[index]
                    session["username"] = username  # use provided username for display
                    session["is_admin"] = bool(user["is_admin"])  # type: ignore[index]
                    return redirect(url_for("index"))
                else:
                    key, salt = _get_user_enc_key_and_salt()
                    h = _username_hash(username, salt)
                    user = db.execute(
                        "SELECT id, password_hash, is_admin FROM users WHERE username_hash=?",
                        (h,),
                    ).fetchone()
                    if user and check_password_hash(user["password_hash"], password):
                        session["user_id"] = int(user["id"])  # type: ignore[index]
                        session["username"] = username  # use provided username for display
                        session["is_admin"] = bool(user["is_admin"])  # type: ignore[index]
                        return redirect(url_for("index"))
            error = "Invalid credentials"
        return render_template("login.html", error=error, first_user=(users_count == 0))

    @app.route("/logout")
    def logout():
        session.pop("user_id", None)
        session.pop("username", None)
        session.pop("is_admin", None)
        return redirect(url_for("login"))

    # Admin-only helpers and routes
    def admin_required(fn):
        @wraps(fn)
        def _wrap(*args, **kwargs):
            if not session.get("user_id"):
                return redirect(url_for("login"))
            if not session.get("is_admin"):
                abort(403)
            return fn(*args, **kwargs)
        return _wrap

    @app.route("/admin/users", methods=["GET", "POST"])
    @admin_required
    def admin_users():
        db = get_db()
        message = ""
        error = ""
        if request.method == "POST":
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password") or ""
            is_admin_flag = 1 if (request.form.get("is_admin") == "1") else 0
            if not username or not password:
                error = "Username and password are required"
            else:
                try:
                    key, salt = _get_user_enc_key_and_salt()
                    h = _username_hash(username, salt)
                    enc = Fernet(key).encrypt(username.encode("utf-8"))
                    db.execute(
                        "INSERT INTO users (username, username_enc, username_hash, password_hash, is_admin) VALUES ('', ?, ?, ?, ?)",
                        (enc, h, generate_password_hash(password), is_admin_flag),
                    )
                    db.commit()
                    message = "User created"
                except sqlite3.IntegrityError:
                    error = "Username already exists"
        # Decrypt usernames for display and sort case-insensitively
        rows = db.execute("SELECT id, username_enc, is_admin FROM users").fetchall()
        key, _salt = _get_user_enc_key_and_salt()
        f = Fernet(key)
        users = []
        for r in rows:
            try:
                name = f.decrypt(r["username_enc"]).decode("utf-8") if r["username_enc"] else ""
            except Exception:
                name = ""
            users.append({"id": r["id"], "username": name, "is_admin": r["is_admin"]})
        users.sort(key=lambda u: u["username"].lower())
        return render_template("admin_users.html", users=users, message=message, error=error)

    @app.route("/thread/<int:thread_id>")
    def thread_view(thread_id: int):
        db = get_db()
        thread = db.execute(
            """
            SELECT t.id, t.title, t.title_enc, t.posts_count, t.created_at, t.last_activity_at,
                   c.name AS category_name, c.slug AS category_slug
            FROM threads t
            LEFT JOIN categories c ON c.id = t.category_id
            WHERE t.id = ?
            """,
            (thread_id,),
        ).fetchone()
        if not thread:
            abort(404)
        cf = Fernet(_get_content_enc_key())
        thread = dict(thread)
        thread["title"] = _dec_optional(cf, thread.get("title_enc")) or (thread.get("title") or "")

        try:
            page = max(int(request.args.get("page", "1")), 1)
        except ValueError:
            page = 1
        per_page = 50
        offset = (page - 1) * per_page

        total_posts = db.execute(
            "SELECT COUNT(*) FROM posts WHERE thread_id = ?",
            (thread_id,),
        ).fetchone()[0]

        posts = db.execute(
            """
            SELECT id, author, author_enc, content, content_enc, created_at
            FROM posts
            WHERE thread_id = ?
            ORDER BY id ASC
            LIMIT ? OFFSET ?
            """,
            (thread_id, per_page, offset),
        ).fetchall()
        # decrypt posts
        _posts = []
        for p in posts:
            d = dict(p)
            d["author"] = _dec_optional(cf, d.get("author_enc")) or (d.get("author") or "anon")
            d["content"] = _dec_optional(cf, d.get("content_enc")) or (d.get("content") or "")
            _posts.append(d)
        posts = _posts

        # Fetch comments for posts on this page in one query
        post_ids = [p["id"] for p in posts]
        comments_map = {}
        if post_ids:
            q_marks = ",".join(["?"] * len(post_ids))
            comments = db.execute(
                f"SELECT id, post_id, author, author_enc, content, content_enc, created_at FROM comments WHERE post_id IN ({q_marks}) ORDER BY id ASC",
                post_ids,
            ).fetchall()
            for c in comments:
                d = dict(c)
                d["author"] = _dec_optional(cf, d.get("author_enc")) or (d.get("author") or "anon")
                d["content"] = _dec_optional(cf, d.get("content_enc")) or (d.get("content") or "")
                comments_map.setdefault(d["post_id"], []).append(d)

        total_pages = max((total_posts + per_page - 1) // per_page, 1)
        return render_template(
            "thread.html",
            thread=thread,
            posts=posts,
            comments_map=comments_map,
            page=page,
            total_pages=total_pages,
        )

    @app.route("/thread", methods=["POST"])
    def create_thread():
        db = get_db()
        title = (request.form.get("title") or "").strip()
        author = (request.form.get("author") or "").strip() or "anon"
        content = (request.form.get("content") or "").strip()
        cat_id_raw = request.form.get("category_id")

        if not title or not content:
            abort(400, description="Title and content are required")

        title = clamp_text(title, 140)
        author = clamp_text(author, 32)
        content = clamp_text(content, 5000)

        # Resolve category; default to first category if not supplied or invalid
        cat_row = None
        if cat_id_raw and cat_id_raw.isdigit():
            cat_row = db.execute(
                "SELECT id FROM categories WHERE id = ?",
                (int(cat_id_raw),),
            ).fetchone()
        if not cat_row:
            cat_row = db.execute(
                "SELECT id FROM categories ORDER BY id ASC LIMIT 1"
            ).fetchone()
        if not cat_row:
            abort(400, description="No categories configured")
        category_id = cat_row[0]

        ts = now_ts()
        cf = Fernet(_get_content_enc_key())
        title_enc = cf.encrypt(title.encode("utf-8")) if title else None
        cur = db.execute(
            "INSERT INTO threads (title, title_enc, posts_count, created_at, last_activity_at, category_id) VALUES ('', ?, 0, ?, ?, ?)",
            (title_enc, ts, ts, category_id),
        )
        thread_id = cur.lastrowid
        author_enc = cf.encrypt(author.encode("utf-8")) if author else None
        content_enc = cf.encrypt(content.encode("utf-8")) if content else None
        db.execute(
            "INSERT INTO posts (thread_id, author, content, author_enc, content_enc, created_at) VALUES (?, '', '', ?, ?, ?)",
            (thread_id, author_enc, content_enc, ts),
        )
        db.execute(
            "UPDATE threads SET posts_count = posts_count + 1, last_activity_at=? WHERE id=?",
            (ts, thread_id),
        )
        db.commit()
        return redirect(url_for("thread_view", thread_id=thread_id))

    @app.route("/thread/<int:thread_id>/reply", methods=["POST"])
    def reply(thread_id: int):
        db = get_db()
        # Ensure thread exists
        exists = db.execute("SELECT 1 FROM threads WHERE id=?", (thread_id,)).fetchone()
        if not exists:
            abort(404)

        author = (request.form.get("author") or "").strip() or "anon"
        content = (request.form.get("content") or "").strip()
        if not content:
            abort(400, description="Content is required")

        author = clamp_text(author, 32)
        content = clamp_text(content, 5000)

        ts = now_ts()
        cf = Fernet(_get_content_enc_key())
        aenc = cf.encrypt(author.encode("utf-8")) if author else None
        cenc = cf.encrypt(content.encode("utf-8")) if content else None
        db.execute(
            "INSERT INTO posts (thread_id, author, content, author_enc, content_enc, created_at) VALUES (?, '', '', ?, ?, ?)",
            (thread_id, aenc, cenc, ts),
        )
        db.execute(
            "UPDATE threads SET posts_count = posts_count + 1, last_activity_at=? WHERE id=?",
            (ts, thread_id),
        )
        db.commit()
        return redirect(url_for("thread_view", thread_id=thread_id))

    @app.route("/post/<int:post_id>/comment", methods=["POST"])
    def comment(post_id: int):
        db = get_db()
        # Resolve post and thread for redirect and validation
        post = db.execute(
            "SELECT id, thread_id FROM posts WHERE id=?",
            (post_id,),
        ).fetchone()
        if not post:
            abort(404)

        author = (request.form.get("author") or "").strip() or "anon"
        content = (request.form.get("content") or "").strip()
        if not content:
            abort(400, description="Content is required")

        author = clamp_text(author, 32)
        content = clamp_text(content, 2000)

        ts = now_ts()
        cf = Fernet(_get_content_enc_key())
        aenc = cf.encrypt(author.encode("utf-8")) if author else None
        cenc = cf.encrypt(content.encode("utf-8")) if content else None
        db.execute(
            "INSERT INTO comments (post_id, author, content, author_enc, content_enc, created_at) VALUES (?, '', '', ?, ?, ?)",
            (post_id, aenc, cenc, ts),
        )
        # Bump thread activity on comment as well
        db.execute(
            "UPDATE threads SET last_activity_at=? WHERE id=?",
            (ts, post["thread_id"]),
        )
        db.commit()
        return redirect(url_for("thread_view", thread_id=post["thread_id"]) + f"#p{post_id}")

    # Health check (useful for quick smoke test)
    @app.route("/healthz")
    def healthz():  # pragma: no cover - trivial
        return {"ok": True}, 200

    # Initialize DB on first run
    with app.app_context():
        init_db()

    # Expose helpers for tests
    app.get_db = get_db  # type: ignore[attr-defined]
    app.init_db = init_db  # type: ignore[attr-defined]

    # Jinja filters
    def datetimeformat(value: int) -> str:
        try:
            ts = int(value)
        except Exception:
            return ""
        # UTC for consistency on Tor
        return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(ts))

    def nl2br(value: str) -> Markup:
        """Render text with line breaks safely.

        Input is expected to be already HTML-escaped in templates (we use `| e | nl2br`).
        We then:
        - Normalize newlines (\r\n/\r -> \n)
        - Convert escaped `<br>` variants (e.g. `&lt;br&gt;`, `&lt;br/&gt;`, `&lt;br /&gt;`) into real <br>
          so users who type literal `<br>` see a break, without allowing other HTML.
        - Convert remaining newlines to `<br>`.
        """
        s = (value or "")
        # Normalize Windows/Mac newlines
        s = s.replace("\r\n", "\n").replace("\r", "\n")
        # Allow only the <br> tag if it was typed literally (escaped by `|e|` earlier)
        s = (
            s.replace("&lt;br&gt;", "<br>")
            .replace("&lt;br/&gt;", "<br>")
            .replace("&lt;br /&gt;", "<br>")
        )
        # Convert newline characters to <br>
        s = s.replace("\n", "<br>")
        return Markup(s)

    # Markdown renderer (commonmark + breaks)
    md = MarkdownIt("commonmark", {
        "breaks": True,  # newlines -> <br>
    })

    # Allowed tags/attributes for sanitization
    _ALLOWED_TAGS = [
        "p", "br", "strong", "em", "code", "pre", "blockquote",
        "ul", "ol", "li", "a", "h1", "h2", "h3", "h4", "h5", "h6",
    ]
    _ALLOWED_ATTRS = {"a": ["href", "title", "rel"]}

    def markdown_to_html(text: str) -> Markup:
        raw = text or ""
        # Render to HTML with Markdown
        html = md.render(raw)
        # Sanitize to prevent XSS
        cleaned = bleach.clean(
            html,
            tags=_ALLOWED_TAGS,
            attributes=_ALLOWED_ATTRS,
            protocols=["http", "https", "mailto"],
            strip=True,
        )
        return Markup(cleaned)

    app.jinja_env.filters["datetimeformat"] = datetimeformat
    app.jinja_env.filters["nl2br"] = nl2br
    app.jinja_env.filters["markdown"] = markdown_to_html

    return app


app = create_app()


if __name__ == "__main__":  # pragma: no cover
    # Bind to localhost by default; Tor will proxy to this if configured as a hidden service
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8080"))
    app.run(host=host, port=port, debug=False)
