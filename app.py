
import os, re, secrets, hashlib
import smtplib
import ssl
from email.message import EmailMessage
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from datetime import datetime, date
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash, abort
from sqlalchemy import func
from werkzeug.utils import secure_filename
from markupsafe import escape
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

APP_VERSION = "3.6"

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
VIDEO_DIR = os.path.join(UPLOAD_DIR, "videos")
THUMB_DIR = os.path.join(UPLOAD_DIR, "thumbnails")
AVATAR_DIR = os.path.join(UPLOAD_DIR, "avatars")

# Create upload directories if they don't exist
for dir_path in [UPLOAD_DIR, VIDEO_DIR, THUMB_DIR, AVATAR_DIR, os.path.join(UPLOAD_DIR, "emojis")]:
    os.makedirs(dir_path, exist_ok=True)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR,'cannaspot.db')}")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 512 * 1024 * 1024  # 512MB

# use the centralized models/db module
from models import (
    db, User, Server, Channel, Membership, Video, Message, Sponsor, Activity,
    Playlist, PlaylistVideo, Subscription, VideoLike, WatchLater, Short,
    Notification, VoiceParticipant, Friendship, DirectMessage, hash_pw, safe_slug, EmailVerification,
    RtcSignal, RtcParticipant, VideoComment, CustomEmoji, Post, Role, RoleMembership, Advertisement,
    MusicBot, MusicQueue
)

# initialize db with the app
db.init_app(app)
def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    return User.query.get(uid)

@app.before_request
def ensure_tables():
    # Lightweight safeguard to ensure new tables (like EmailVerification) exist after code updates
    try:
        db.create_all()
    except Exception:
        pass

# --- Email configuration helpers ---
SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASS = os.environ.get("SMTP_PASS")
SMTP_FROM = os.environ.get("SMTP_FROM", os.environ.get("SMTP_USER", "no-reply@cannaspot.local"))
SMTP_USE_SSL = os.environ.get("SMTP_USE_SSL", "false").lower() in ("1", "true", "yes")
SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "true").lower() in ("1", "true", "yes")

def send_email(subject: str, to: str, text_body: str, html_body: str | None = None) -> bool:
    """Send an email using SMTP settings from environment.

    Returns True on success, False otherwise. If SMTP not configured, logs and returns False.
    """
    if not SMTP_HOST or not to:
        # SMTP not configured; avoid breaking the flow in dev
        print(f"[email] SMTP not configured or no recipient. Skipping send to {to} with subject '{subject}'.")
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = to
    msg.set_content(text_body)
    if html_body:
        msg.add_alternative(html_body, subtype="html")

    try:
        if SMTP_USE_SSL:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context) as server:
                if SMTP_USER and SMTP_PASS:
                    server.login(SMTP_USER, SMTP_PASS)
                server.send_message(msg)
        else:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
                if SMTP_USE_TLS:
                    server.starttls(context=ssl.create_default_context())
                if SMTP_USER and SMTP_PASS:
                    server.login(SMTP_USER, SMTP_PASS)
                server.send_message(msg)
        print(f"[email] Sent to {to}: {subject}")
        return True
    except Exception as e:
        print(f"[email] Failed to send to {to}: {e}")
        return False

def send_welcome_email(user: User):
    """Compose and send the welcome email to a new user."""
    try:
        site_url = request.host_url.rstrip('/')
        text_body = render_template("email/welcome.txt", user=user, site_url=site_url)
        html_body = None
        try:
            html_body = render_template("email/welcome.html", user=user, site_url=site_url)
        except Exception:
            # HTML template optional
            html_body = None
        send_email(
            subject="Welcome to CannaSpot 🌿",
            to=user.email,
            text_body=text_body,
            html_body=html_body,
        )
    except Exception as e:
        # Never block signup on email failure
        print(f"[email] Welcome email error: {e}")

# --- Token / Security helpers ---
def _get_serializer():
    secret = app.config.get("SECRET_KEY") or "dev-secret"
    return URLSafeTimedSerializer(secret_key=secret, salt="cannaspot-email")

def generate_token(user: User, purpose: str) -> str:
    s = _get_serializer()
    return s.dumps({"uid": user.id, "purpose": purpose})

def verify_token(token: str, purpose: str, max_age: int) -> User | None:
    s = _get_serializer()
    try:
        data = s.loads(token, max_age=max_age)
    except SignatureExpired:
        print("[token] expired")
        return None
    except BadSignature:
        print("[token] bad signature")
        return None
    if data.get("purpose") != purpose:
        return None
    return User.query.get(data.get("uid"))

def send_verification_email(user: User):
    token = generate_token(user, "verify")
    link = url_for("verify_email", token=token, _external=True)
    site_url = request.host_url.rstrip('/')
    text_body = render_template("email/verify_email.txt", user=user, verify_link=link, site_url=site_url)
    html_body = None
    try:
        html_body = render_template("email/verify_email.html", user=user, verify_link=link, site_url=site_url)
    except Exception:
        pass
    send_email(
        subject="Verify your CannaSpot email",
        to=user.email,
        text_body=text_body,
        html_body=html_body
    )

def send_password_reset_email(user: User):
    token = generate_token(user, "reset")
    link = url_for("reset_password", token=token, _external=True)
    site_url = request.host_url.rstrip('/')
    text_body = render_template("email/reset_password.txt", user=user, reset_link=link, site_url=site_url)
    html_body = None
    try:
        html_body = render_template("email/reset_password.html", user=user, reset_link=link, site_url=site_url)
    except Exception:
        pass
    send_email(
        subject="Reset your CannaSpot password",
        to=user.email,
        text_body=text_body,
        html_body=html_body
    )

# Template filters
@app.template_filter("date")
def jinja_date(value, fmt: str = "%b %d, %Y"):
    """Format dates safely in templates.

    Accepts datetime/date/ISO string/epoch and returns a formatted string.
    Defaults to like: Nov 10, 2025
    """
    if value is None:
        return ""
    try:
        if isinstance(value, (int, float)):
            dt = datetime.fromtimestamp(value)
        elif isinstance(value, str):
            # Try ISO 8601 first
            try:
                dt = datetime.fromisoformat(value)
            except Exception:
                return value
        elif isinstance(value, datetime):
            dt = value
        elif isinstance(value, date):
            return value.strftime(fmt)
        else:
            return str(value)
        return dt.strftime(fmt)
    except Exception:
        return str(value)

@app.route("/install", methods=["GET","POST"])
def install():
    try:
        has_user = db.session.query(User.id).first()
        if has_user:
            return redirect(url_for("installed"))
    except Exception:
        pass
    if request.method == "POST":
        engine = request.form.get("engine","sqlite")
        secret = request.form.get("secret") or secrets.token_hex(16)
        if engine == "mysql":
            host = request.form.get("db_host","localhost")
            name = request.form.get("db_name")
            user = request.form.get("db_user")
            pw   = request.form.get("db_pass","")
            url = f"mysql+pymysql://{user}:{pw}@{host}/{name}?charset=utf8mb4"
        else:
            url = f"sqlite:///{os.path.join(BASE_DIR,'cannaspot.db')}"
        
        # Build .env file content
        env_content = f"SECRET_KEY={secret}\nDATABASE_URL={url}\n"
        
        # Add site settings
        site_name = request.form.get("site_name", "CannaSpot").strip()
        site_url = request.form.get("site_url", "").strip()
        allow_registration = "true" if request.form.get("allow_registration") else "false"
        require_verification = "true" if request.form.get("require_email_verification") else "false"
        
        env_content += f"\n# Site Settings\n"
        env_content += f"SITE_NAME={site_name}\n"
        if site_url:
            env_content += f"SITE_URL={site_url}\n"
        env_content += f"ALLOW_REGISTRATION={allow_registration}\n"
        env_content += f"REQUIRE_EMAIL_VERIFICATION={require_verification}\n"
        
        # Add SMTP configuration if provided
        smtp_host = request.form.get("smtp_host", "").strip()
        if smtp_host:
            smtp_port = request.form.get("smtp_port", "587").strip()
            smtp_user = request.form.get("smtp_user", "").strip()
            smtp_pass = request.form.get("smtp_pass", "").strip()
            smtp_from = request.form.get("smtp_from", "").strip() or f"CannaSpot <noreply@cannaspot.local>"
            smtp_use_tls = "true" if request.form.get("smtp_use_tls") else "false"
            
            env_content += f"\n# SMTP Email Configuration\n"
            env_content += f"SMTP_HOST={smtp_host}\n"
            env_content += f"SMTP_PORT={smtp_port}\n"
            env_content += f"SMTP_USER={smtp_user}\n"
            env_content += f"SMTP_PASS={smtp_pass}\n"
            env_content += f"SMTP_FROM={smtp_from}\n"
            env_content += f"SMTP_USE_TLS={smtp_use_tls}\n"
            env_content += f"SMTP_USE_SSL=false\n"
            
            # Update environment variables for current session
            os.environ["SMTP_HOST"] = smtp_host
            os.environ["SMTP_PORT"] = smtp_port
            os.environ["SMTP_USER"] = smtp_user
            os.environ["SMTP_PASS"] = smtp_pass
            os.environ["SMTP_FROM"] = smtp_from
            os.environ["SMTP_USE_TLS"] = smtp_use_tls
            os.environ["SMTP_USE_SSL"] = "false"
        
        # Write .env file
        env_path = os.path.join(BASE_DIR, ".env")
        with open(env_path, "w", encoding="utf-8") as f:
            f.write(env_content)
        
        os.environ["SECRET_KEY"] = secret
        os.environ["DATABASE_URL"] = url
        app.config["SECRET_KEY"] = secret
        app.config["SQLALCHEMY_DATABASE_URI"] = url
        db.engine.dispose()
        db.drop_all()
        db.create_all()
        username = request.form["admin_user"].strip()
        display  = request.form.get("admin_display", username)
        email    = request.form["admin_email"].strip()
        pwd      = request.form["admin_pass"]
        admin = User(username=username, display=display, email=email, password_hash=hash_pw(pwd), is_admin=True)
        bot = User(username="GrowBot", display="GrowBot", email="bot@cannaspot.local", password_hash=hash_pw(secrets.token_hex(8)), is_admin=False)
        db.session.add_all([admin, bot])
        db.session.commit()
        
        # Create default server with custom name and channels
        server_name = request.form.get("server_name", "General Community").strip()
        srv = Server(name=server_name, slug=safe_slug(server_name), owner_id=admin.id)
        db.session.add(srv); db.session.commit()
        
        # Create channels from form input
        default_channels_input = request.form.get("default_channels", "general").strip()
        channel_names = [name.strip() for name in default_channels_input.split('\n') if name.strip()]
        if not channel_names:
            channel_names = ["general"]  # Fallback
        
        for channel_name in channel_names:
            ch = Channel(server_id=srv.id, name=channel_name)
            db.session.add(ch)
        db.session.commit()
        
        # Add memberships
        db.session.add_all([Membership(user_id=admin.id, server_id=srv.id), Membership(user_id=bot.id, server_id=srv.id)])
        db.session.add(Sponsor(name="Top420Seeds.com", url="https://top420seeds.com", logo="/static/logo.png", active=True))
        db.session.commit()
        
        # Try to send welcome email to admin if SMTP is configured
        if smtp_host:
            try:
                send_welcome_email(admin)
            except Exception as e:
                print(f"[install] Could not send welcome email: {e}")
        
        return redirect(url_for("login"))
    return render_template("install.html", version=APP_VERSION)

@app.route("/installed")
def installed():
    return render_template("installed.html")

from sqlalchemy import func
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        u = User.query.filter(func.lower(User.username)==request.form["username"].lower()).first()
        import hashlib
        if u and u.password_hash == hashlib.sha256(request.form["password"].encode("utf-8")).hexdigest():
            session["uid"] = u.id
            return redirect(url_for("recent"))
    return render_template("login.html")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        if User.query.filter_by(username=request.form["username"]).first():
            pass
        else:
            u = User(
                username=request.form["username"],
                email=request.form["email"],
                display=request.form.get("display") or request.form["username"],
                password_hash=hash_pw(request.form["password"])
            )
            db.session.add(u); db.session.commit()
            # Fire-and-forget welcome email
            try:
                send_welcome_email(u)
                send_verification_email(u)
            except Exception as _e:
                print(f"[email] Skipping welcome email: {_e}")
            session["uid"] = u.id
            return redirect(url_for("recent"))
    return render_template("register.html")

@app.route("/verify-email/<token>")
def verify_email(token):
    user = verify_token(token, "verify", max_age=60*60*24*3)  # 3 days
    if not user:
        flash("Verification link is invalid or expired", "error")
        return redirect(url_for("recent"))
    existing = EmailVerification.query.filter_by(user_id=user.id).first()
    if not existing:
        existing = EmailVerification(user_id=user.id, verified_at=datetime.utcnow())
        db.session.add(existing)
    else:
        existing.verified_at = existing.verified_at or datetime.utcnow()
    db.session.commit()
    flash("Email verified. Welcome!", "success")
    return redirect(url_for("recent"))

@app.route("/forgot-password", methods=["GET","POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        user = User.query.filter(func.lower(User.email)==email.lower()).first()
        if user:
            try:
                send_password_reset_email(user)
            except Exception as e:
                print(f"[email] reset send failed: {e}")
        flash("If that email is registered, a reset link has been sent.", "info")
        return redirect(url_for("login"))
    return render_template("forgot_password.html")

@app.route("/reset-password/<token>", methods=["GET","POST"])
def reset_password(token):
    user = verify_token(token, "reset", max_age=60*60*2)  # 2 hours
    if not user:
        flash("Reset link invalid or expired", "error")
        return redirect(url_for("forgot_password"))
    if request.method == "POST":
        pw = request.form.get("password","")
        if len(pw) < 6:
            flash("Password must be at least 6 characters", "error")
        else:
            user.password_hash = hash_pw(pw)
            db.session.commit()
            flash("Password updated. You can now log in.", "success")
            return redirect(url_for("login"))
    return render_template("reset_password.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
def recent():
    try:
        # Check if database is initialized
        user_count = User.query.count()
        if user_count == 0:
            # No users, redirect to install
            return redirect(url_for("install"))
        
        # Get GrowBot user ID (YouTube videos uploader)
        bot = User.query.filter_by(username="GrowBot").first()
        bot_id = bot.id if bot else None
        
        # Get uploaded videos (not from GrowBot) - show these first
        uploaded_vids = Video.query.filter(Video.uploader_id != bot_id).order_by(Video.created_at.desc()).limit(12).all() if bot_id else []
        
        # Get YouTube videos (from GrowBot) - show after uploaded
        youtube_vids = Video.query.filter_by(uploader_id=bot_id).order_by(Video.created_at.desc()).limit(12).all() if bot_id else []
        
        # Combine: uploaded first, then YouTube
        vids = uploaded_vids + youtube_vids
        
        # Add like counts to each video
        for v in vids:
            v.like_count = VideoLike.query.filter_by(video_id=v.id).count()
        
        servers = Server.query.order_by(Server.name).all()
        return render_template("recent.html", videos=vids, uploaded=uploaded_vids, youtube=youtube_vids, servers=servers, user=current_user())
    except Exception as e:
        # Database not initialized, redirect to install
        print(f"Error loading home page: {e}")
        return redirect(url_for("install"))

@app.route("/watch/<int:vid>", methods=["GET", "POST"])
def watch(vid):
    v = Video.query.get_or_404(vid)
    u = current_user()
    
    # Increment view count (only on GET, not on comment POST)
    if request.method == "GET":
        v.view_count = (v.view_count or 0) + 1
        db.session.commit()
    
    # Handle comment submission
    if request.method == "POST" and u:
        content = request.form.get("text", "").strip()
        if content:
            comment = VideoComment(video_id=vid, user_id=u.id, content=content)
            db.session.add(comment)
            db.session.commit()
            # Notify uploader
            if v.uploader_id and v.uploader_id != u.id:
                notif = Notification(
                    user_id=v.uploader_id,
                    message=f"{u.username} commented on your video: {v.title[:30]}",
                    link=url_for("watch", vid=vid)
                )
                db.session.add(notif)
                db.session.commit()
        return redirect(url_for("watch", vid=vid))
    
    # Get comments with user info
    comments_data = (db.session.query(VideoComment, User)
                    .join(User, User.id == VideoComment.user_id)
                    .filter(VideoComment.video_id == vid)
                    .order_by(VideoComment.created_at.desc())
                    .all())
    
    comments = [{"author": user.username, "text": comment.content, "created_at": comment.created_at} 
                for comment, user in comments_data]
    
    more = Video.query.order_by(Video.created_at.desc()).limit(10).all()
    return render_template("watch.html", video=v, related=more, comments=comments, user=u)

from werkzeug.utils import secure_filename
@app.route("/upload", methods=["GET","POST"])
def upload():
    u = current_user()
    if not u: return redirect(url_for("login"))
    if request.method == "POST":
        f = request.files.get("video")
        t = request.files.get("thumb")
        title = request.form.get("title","Untitled")
        desc = request.form.get("description","")
        if f:
            fname = secure_filename(f.filename)
            path = os.path.join("uploads","videos", fname)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            f.save(path)
            thumb_rel = None
            if t:
                tname = secure_filename(t.filename)
                tpath = os.path.join("uploads","thumbnails", tname)
                os.makedirs(os.path.dirname(tpath), exist_ok=True)
                t.save(tpath)
                thumb_rel = "/uploads/thumbnails/" + tname
            v = Video(title=title, filename="/uploads/videos/"+fname, thumbnail=thumb_rel, description=desc, uploader_id=u.id)
            db.session.add(v); db.session.commit()
            return redirect(url_for("recent"))
    return render_template("upload.html", user=u)

@app.route("/upload-short", methods=["GET","POST"])
def upload_short():
    u = current_user()
    if not u: 
        return redirect(url_for("login"))
    if request.method == "POST":
        f = request.files.get("video")
        t = request.files.get("thumb")
        title = request.form.get("title","Untitled Short")
        if f:
            fname = secure_filename(f.filename)
            path = os.path.join("uploads","videos", fname)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            f.save(path)
            
            thumb_rel = None
            if t:
                tname = secure_filename(t.filename)
                tpath = os.path.join("uploads","thumbnails", tname)
                os.makedirs(os.path.dirname(tpath), exist_ok=True)
                t.save(tpath)
                thumb_rel = "/uploads/thumbnails/" + tname
            
            short = Short(title=title, filename="/uploads/videos/"+fname, thumbnail=thumb_rel, uploader_id=u.id)
            db.session.add(short)
            db.session.commit()
            flash("Short uploaded successfully!", "success")
            return redirect(url_for("shorts"))
    return render_template("upload_short.html", user=u)

@app.route("/servers")
def servers_view():
    servers = Server.query.order_by(Server.name).all()
    return render_template("servers.html", servers=servers, user=current_user())

@app.route("/server/<slug>", methods=["GET", "POST"])
def server(slug):
    s = Server.query.filter_by(slug=slug).first_or_404()
    ch = Channel.query.filter_by(server_id=s.id).all()
    mem = Membership.query.filter_by(server_id=s.id).count()
    ismem = False
    u = current_user()
    if u:
        ismem = bool(Membership.query.filter_by(user_id=u.id, server_id=s.id).first())
        # Handle join request
        if request.method == "POST" and not ismem:
            db.session.add(Membership(user_id=u.id, server_id=s.id))
            db.session.commit()
            ismem = True
            flash("✅ You joined the server!", "success")
            return redirect(url_for("server", slug=slug))
    return render_template("server.html", server=s, channels=ch, members=mem, is_member=ismem, user=u)

@app.route("/c/<slug>/<int:cid>", methods=["GET","POST"])
def channel(slug, cid):
    s = Server.query.filter_by(slug=slug).first_or_404()
    ch = Channel.query.get_or_404(cid)
    u = current_user()
    channels = Channel.query.filter_by(server_id=s.id).all()
    if request.method == "POST" and u:
        content = request.form.get("content","").strip()[:2000]
        if content:
            db.session.add(Message(server_id=s.id, channel_id=ch.id, user_id=u.id, content=content))
            db.session.commit()
    msgs = (db.session.query(Message, User)
            .join(User, User.id==Message.user_id)
            .filter(Message.channel_id==ch.id)
            .order_by(Message.created_at.asc()).all())
    return render_template("channel.html", server=s, ch=ch, channels=channels, msgs=msgs, user=u)

@app.route("/create-server", methods=["GET","POST"])
def create_server():
    u = current_user()
    if not u: return redirect(url_for("login"))
    if request.method == "POST":
        name = request.form["name"]
        slug = safe_slug(name)
        icon_file = request.files.get("server_icon")
        icon_path = None
        
        if icon_file and icon_file.filename:
            fname = secure_filename(icon_file.filename)
            icon_path = os.path.join("uploads", "avatars", f"server_{secrets.token_hex(4)}_{fname}")
            os.makedirs(os.path.dirname(icon_path), exist_ok=True)
            icon_file.save(icon_path)
            icon_path = "/" + icon_path.replace("\\", "/")
        
        s = Server(name=name, slug=slug, owner_id=u.id, server_icon=icon_path)
        db.session.add(s); db.session.commit()
        # Create default text channel
        db.session.add(Channel(server_id=s.id, name="general", is_voice=False))
        # Create default voice channel
        db.session.add(Channel(server_id=s.id, name="Voice Chat", is_voice=True))
        db.session.commit()
        db.session.add(Membership(user_id=u.id, server_id=s.id)); db.session.commit()
        return redirect(url_for("server", slug=slug))
    return render_template("create_server.html", user=u)

# SERVER SETUP BOT TEMPLATES
SETUP_TEMPLATES = {
    "grow_community": {
        "name": "🌱 Grow Community",
        "roles": [
            {"name": "Admin", "color": "#E74C3C", "position": 3, "is_admin": True, "can_manage_channels": True, "can_manage_roles": True, "can_kick_members": True, "can_ban_members": True, "can_manage_messages": True, "can_mention_everyone": True},
            {"name": "Moderator", "color": "#3498DB", "position": 2, "can_manage_messages": True, "can_kick_members": True},
            {"name": "Veteran Grower", "color": "#2ECC71", "position": 1, "can_mention_everyone": True},
            {"name": "Member", "color": "#95A5A6", "position": 0, "can_send_messages": True}
        ],
        "channels": [
            {"category": "INFO", "channels": [
                {"name": "welcome", "is_voice": False},
                {"name": "rules", "is_voice": False},
                {"name": "announcements", "is_voice": False}
            ]},
            {"category": "GROW CHAT", "channels": [
                {"name": "general-chat", "is_voice": False},
                {"name": "grow-help", "is_voice": False},
                {"name": "strain-discussion", "is_voice": False},
                {"name": "harvest-showcase", "is_voice": False}
            ]},
            {"category": "VOICE CHANNELS", "channels": [
                {"name": "General Voice", "is_voice": True},
                {"name": "Grow Talk", "is_voice": True}
            ]}
        ]
    },
    "gaming": {
        "name": "🎮 Gaming Server",
        "roles": [
            {"name": "Admin", "color": "#E74C3C", "position": 3, "is_admin": True, "can_manage_channels": True, "can_manage_roles": True, "can_kick_members": True, "can_ban_members": True, "can_manage_messages": True},
            {"name": "Moderator", "color": "#3498DB", "position": 2, "can_manage_messages": True, "can_kick_members": True},
            {"name": "VIP", "color": "#F1C40F", "position": 1, "can_mention_everyone": True},
            {"name": "Gamer", "color": "#9B59B6", "position": 0, "can_send_messages": True}
        ],
        "channels": [
            {"category": "GENERAL", "channels": [
                {"name": "welcome", "is_voice": False},
                {"name": "announcements", "is_voice": False},
                {"name": "general", "is_voice": False}
            ]},
            {"category": "GAMING", "channels": [
                {"name": "looking-for-group", "is_voice": False},
                {"name": "game-chat", "is_voice": False},
                {"name": "clips-highlights", "is_voice": False}
            ]},
            {"category": "VOICE", "channels": [
                {"name": "General Voice", "is_voice": True},
                {"name": "Gaming Room 1", "is_voice": True},
                {"name": "Gaming Room 2", "is_voice": True}
            ]}
        ]
    },
    "general": {
        "name": "💬 General Community",
        "roles": [
            {"name": "Admin", "color": "#E74C3C", "position": 2, "is_admin": True, "can_manage_channels": True, "can_manage_roles": True, "can_kick_members": True, "can_ban_members": True, "can_manage_messages": True},
            {"name": "Moderator", "color": "#3498DB", "position": 1, "can_manage_messages": True},
            {"name": "Member", "color": "#95A5A6", "position": 0, "can_send_messages": True}
        ],
        "channels": [
            {"category": "TEXT CHANNELS", "channels": [
                {"name": "general", "is_voice": False},
                {"name": "random", "is_voice": False},
                {"name": "memes", "is_voice": False}
            ]},
            {"category": "VOICE CHANNELS", "channels": [
                {"name": "General Voice", "is_voice": True},
                {"name": "Chill Room", "is_voice": True}
            ]}
        ]
    }
}

@app.route("/server/<slug>/setup-bot", methods=["GET", "POST"])
def setup_bot(slug):
    u = current_user()
    if not u: return redirect(url_for("login"))
    
    s = Server.query.filter_by(slug=slug).first_or_404()
    if s.owner_id != u.id:
        flash("❌ Only server owner can run Admin Bot", "error")
        return redirect(url_for("server", slug=slug))
    
    if request.method == "POST":
        template_key = request.form.get("template", "general")
        template = SETUP_TEMPLATES.get(template_key, SETUP_TEMPLATES["general"])
        
        # Clear existing channels and roles (except owner)
        Channel.query.filter_by(server_id=s.id).delete()
        Role.query.filter_by(server_id=s.id).delete()
        db.session.commit()
        
        # Create roles
        created_roles = {}
        for role_data in template["roles"]:
            role = Role(
                server_id=s.id,
                name=role_data["name"],
                color=role_data["color"],
                position=role_data["position"],
                is_admin=role_data.get("is_admin", False),
                can_manage_channels=role_data.get("can_manage_channels", False),
                can_manage_roles=role_data.get("can_manage_roles", False),
                can_kick_members=role_data.get("can_kick_members", False),
                can_ban_members=role_data.get("can_ban_members", False),
                can_send_messages=role_data.get("can_send_messages", True),
                can_manage_messages=role_data.get("can_manage_messages", False),
                can_mention_everyone=role_data.get("can_mention_everyone", False)
            )
            db.session.add(role)
            db.session.flush()
            created_roles[role_data["name"]] = role
        
        # Assign owner to Admin role
        if "Admin" in created_roles:
            db.session.add(RoleMembership(user_id=u.id, role_id=created_roles["Admin"].id))
        
        # Create channels with categories
        position = 0
        for cat_group in template["channels"]:
            category = cat_group["category"]
            for ch_data in cat_group["channels"]:
                channel = Channel(
                    server_id=s.id,
                    name=ch_data["name"],
                    is_voice=ch_data["is_voice"],
                    category=category,
                    position=position
                )
                db.session.add(channel)
                position += 1
        
        db.session.commit()
        
        flash(f"✅ Server setup complete! Created {len(template['roles'])} roles and {sum(len(c['channels']) for c in template['channels'])} channels", "success")
        return redirect(url_for("server", slug=slug))
    
    return render_template("setup_bot.html", user=u, server=s, templates=SETUP_TEMPLATES)

@app.route("/profile", methods=["GET","POST"])
def my_profile():
    u = current_user()
    if not u: return redirect(url_for("login"))
    if request.method == "POST":
        u.display = request.form.get("display") or u.display
        u.profile_html = request.form.get("profile_html")[:5000]
        db.session.commit()
        flash("✅ Profile updated successfully!", "success")
        return redirect(url_for("my_profile"))
    return render_template("profile.html", user=u)

@app.route("/change-password", methods=["POST"])
def change_password():
    u = current_user()
    if not u: return redirect(url_for("login"))
    
    current_pw = request.form.get("current_password", "")
    new_pw = request.form.get("new_password", "")
    confirm_pw = request.form.get("confirm_password", "")
    
    # Verify current password
    if u.password_hash != hash_pw(current_pw):
        flash("❌ Current password is incorrect", "error")
        return redirect(url_for("my_profile"))
    
    # Validate new password
    if len(new_pw) < 6:
        flash("❌ New password must be at least 6 characters", "error")
        return redirect(url_for("my_profile"))
    
    if new_pw != confirm_pw:
        flash("❌ New passwords don't match", "error")
        return redirect(url_for("my_profile"))
    
    # Update password
    u.password_hash = hash_pw(new_pw)
    db.session.commit()
    flash("✅ Password changed successfully!", "success")
    return redirect(url_for("my_profile"))

@app.route("/theGspot", methods=["GET","POST"])
def admin_panel():
    u = current_user()
    if not (u and u.is_admin): abort(403)
    if request.method == "POST":
        action = request.form.get("action")
        
        # User management
        if action == "make_admin":
            uid = int(request.form.get("user_id"))
            x = User.query.get(uid); 
            if x: 
                x.is_admin = True; db.session.commit()
                flash(f"✅ {x.username} is now an admin", "success")
        
        elif action == "remove_admin":
            uid = int(request.form.get("user_id"))
            x = User.query.get(uid)
            if x and x.id != u.id:  # Can't demote yourself
                x.is_admin = False; db.session.commit()
                flash(f"✅ Removed admin from {x.username}", "success")
        
        elif action == "delete_user":
            uid = int(request.form.get("user_id"))
            x = User.query.get(uid)
            if x and x.id != u.id:  # Can't delete yourself
                # Delete user's content
                Video.query.filter_by(uploader_id=uid).delete()
                Message.query.filter_by(user_id=uid).delete()
                DirectMessage.query.filter(
                    (DirectMessage.sender_id == uid) | (DirectMessage.recipient_id == uid)
                ).delete()
                Friendship.query.filter(
                    (Friendship.user_id == uid) | (Friendship.friend_id == uid)
                ).delete()
                Notification.query.filter_by(user_id=uid).delete()
                Membership.query.filter_by(user_id=uid).delete()
                db.session.delete(x)
                db.session.commit()
                flash(f"🗑️ Deleted user {x.username} and all their content", "warning")
        
        # Video management
        elif action == "delete_video":
            vid = int(request.form.get("video_id"))
            v = Video.query.get(vid)
            if v:
                # Delete related records
                VideoLike.query.filter_by(video_id=vid).delete()
                WatchLater.query.filter_by(video_id=vid).delete()
                PlaylistVideo.query.filter_by(video_id=vid).delete()
                # Try to delete actual file
                if v.filename and os.path.exists(v.filename.lstrip('/')):
                    try:
                        os.remove(v.filename.lstrip('/'))
                    except:
                        pass
                db.session.delete(v)
                db.session.commit()
                flash(f"🗑️ Deleted video: {v.title}", "warning")
        
        # Server management
        elif action == "delete_server":
            sid = int(request.form.get("server_id"))
            s = Server.query.get(sid)
            if s:
                # Delete channels and messages
                for ch in Channel.query.filter_by(server_id=sid).all():
                    Message.query.filter_by(channel_id=ch.id).delete()
                    VoiceParticipant.query.filter_by(channel_id=ch.id).delete()
                Channel.query.filter_by(server_id=sid).delete()
                Membership.query.filter_by(server_id=sid).delete()
                db.session.delete(s)
                db.session.commit()
                flash(f"🗑️ Deleted server: {s.name}", "warning")
        
        # Sponsor management
        elif action == "add_sponsor":
            name = request.form.get("name"); url = request.form.get("url")
            db.session.add(Sponsor(name=name, url=url, logo="/static/logo.png", active=True))
            db.session.commit()
            flash(f"✅ Added sponsor: {name}", "success")
        
        elif action == "toggle_sponsor":
            sid = int(request.form.get("sponsor_id"))
            s = Sponsor.query.get(sid)
            if s:
                s.active = not s.active
                db.session.commit()
                flash(f"✅ Sponsor {s.name} is now {'active' if s.active else 'inactive'}", "success")
        
        elif action == "delete_sponsor":
            sid = int(request.form.get("sponsor_id"))
            s = Sponsor.query.get(sid)
            if s:
                db.session.delete(s)
                db.session.commit()
                flash(f"🗑️ Deleted sponsor: {s.name}", "warning")
        
        # Emoji management
        elif action == "add_emoji":
            category = request.form.get("emoji_category", "custom").strip()
            emoji_char = request.form.get("emoji_char", "").strip()
            label = request.form.get("emoji_label", "").strip()
            
            # Handle image upload
            image_path = None
            if 'emoji_image' in request.files:
                file = request.files['emoji_image']
                if file and file.filename:
                    fname = secure_filename(file.filename)
                    # Create emojis directory if it doesn't exist
                    emoji_dir = os.path.join(UPLOAD_DIR, 'emojis')
                    os.makedirs(emoji_dir, exist_ok=True)
                    # Save with unique name
                    unique_fname = f"{secrets.token_hex(8)}_{fname}"
                    image_path = os.path.join('emojis', unique_fname)
                    file.save(os.path.join(UPLOAD_DIR, image_path))
            
            # Need either emoji_char or image
            if emoji_char or image_path:
                # Check for duplicates
                if emoji_char:
                    existing = CustomEmoji.query.filter_by(emoji_char=emoji_char, category=category).first()
                else:
                    existing = None
                
                if not existing:
                    db.session.add(CustomEmoji(
                        category=category, 
                        emoji_char=emoji_char or None,
                        image_path=image_path,
                        label=label
                    ))
                    db.session.commit()
                    flash(f"✅ Added emoji to {category}", "success")
                else:
                    flash(f"⚠️ Emoji {emoji_char} already exists in {category}", "warning")
            else:
                flash("⚠️ Please provide either an emoji character or upload an image", "warning")
        
        elif action == "delete_emoji":
            eid = int(request.form.get("emoji_id"))
            e = CustomEmoji.query.get(eid)
            if e:
                db.session.delete(e)
                db.session.commit()
                flash(f"🗑️ Deleted emoji: {e.emoji_char}", "warning")
        
        elif action == "toggle_emoji":
            eid = int(request.form.get("emoji_id"))
            e = CustomEmoji.query.get(eid)
            if e:
                e.is_active = not e.is_active
                db.session.commit()
                flash(f"✅ Emoji {e.emoji_char} is now {'active' if e.is_active else 'inactive'}", "success")
        
        # Message moderation
        elif action == "delete_message":
            mid = int(request.form.get("message_id"))
            m = Message.query.get(mid)
            if m:
                db.session.delete(m)
                db.session.commit()
                flash("🗑️ Message deleted", "warning")
        
        elif action == "transfer_server":
            sid = int(request.form.get("server_id"))
            new_owner_id = int(request.form.get("new_owner_id"))
            s = Server.query.get(sid)
            if s:
                s.owner_id = new_owner_id
                db.session.commit()
                flash(f"✅ Server ownership transferred to user #{new_owner_id}", "success")
        
        return redirect(url_for("admin_panel"))
    
    # Get data for display
    stats = {
        "users": User.query.count(),
        "videos": Video.query.count(),
        "messages": Message.query.count(),
        "servers": Server.query.count(),
        "channels": Channel.query.count(),
        "sponsors": Sponsor.query.count(),
        "admins": User.query.filter_by(is_admin=True).count(),
        "custom_emojis": CustomEmoji.query.filter_by(is_active=True).count(),
        "ads": Advertisement.query.count(),
        "active_ads": Advertisement.query.filter_by(is_active=True).count(),
    }
    
    users = User.query.order_by(User.created_at.desc()).limit(50).all()
    videos = Video.query.order_by(Video.created_at.desc()).limit(50).all()
    servers = Server.query.order_by(Server.created_at.desc()).all()
    sponsors = Sponsor.query.all()
    custom_emojis = CustomEmoji.query.order_by(CustomEmoji.category, CustomEmoji.sort_order).all()
    advertisements = Advertisement.query.order_by(Advertisement.created_at.desc()).all()
    recent_messages = (db.session.query(Message, User, Server, Channel)
                      .join(User, User.id == Message.user_id)
                      .join(Server, Server.id == Message.server_id)
                      .join(Channel, Channel.id == Message.channel_id)
                      .order_by(Message.created_at.desc())
                      .limit(100).all())
    
    return render_template("admin.html", user=u, sponsors=sponsors, stats=stats, 
                         users=users, videos=videos, servers=servers, 
                         recent_messages=recent_messages, custom_emojis=custom_emojis,
                         advertisements=advertisements)

@app.route("/admin/ad/create", methods=["POST"])
def admin_create_ad():
    u = current_user()
    if not u or not u.is_admin:
        return redirect(url_for("login"))
    
    title = request.form.get("title", "").strip()
    content = request.form.get("content", "").strip()
    link = request.form.get("link", "").strip()
    placement = request.form.get("placement", "sidebar")
    
    # Handle image upload
    image_path = None
    ad_image = request.files.get("image")
    if ad_image and ad_image.filename:
        fname = secure_filename(ad_image.filename)
        image_path = os.path.join("uploads", "ads", f"ad_{secrets.token_hex(4)}_{fname}")
        os.makedirs(os.path.dirname(image_path), exist_ok=True)
        ad_image.save(image_path)
        image_path = "/" + image_path.replace("\\", "/")
    
    ad = Advertisement(
        title=title,
        content=content,
        image=image_path,
        link=link,
        placement=placement,
        is_active=True
    )
    db.session.add(ad)
    db.session.commit()
    flash("✅ Advertisement created!", "success")
    return redirect(url_for("admin_panel"))

@app.route("/admin/ad/<int:ad_id>/toggle", methods=["POST"])
def admin_toggle_ad(ad_id):
    u = current_user()
    if not u or not u.is_admin:
        return {"error": "Unauthorized"}, 403
    
    ad = Advertisement.query.get_or_404(ad_id)
    ad.is_active = not ad.is_active
    db.session.commit()
    return {"success": True, "is_active": ad.is_active}

@app.route("/admin/ad/<int:ad_id>/delete", methods=["POST"])
def admin_delete_ad(ad_id):
    u = current_user()
    if not u or not u.is_admin:
        return redirect(url_for("login"))
    
    ad = Advertisement.query.get_or_404(ad_id)
    db.session.delete(ad)
    db.session.commit()
    flash("🗑️ Advertisement deleted", "warning")
    return redirect(url_for("admin_panel"))

@app.route("/api/ad/<int:ad_id>/view", methods=["POST"])
def ad_view(ad_id):
    ad = Advertisement.query.get(ad_id)
    if ad:
        ad.view_count += 1
        db.session.commit()
    return {"success": True}

@app.route("/api/ad/<int:ad_id>/click", methods=["POST"])
def ad_click(ad_id):
    ad = Advertisement.query.get(ad_id)
    if ad:
        ad.click_count += 1
        db.session.commit()
    return {"success": True}

@app.route("/uploads/<path:filename>")
def uploads(filename):
    return send_from_directory("uploads", filename)

@app.context_processor
def inject_globals():
    sponsors = Sponsor.query.filter_by(active=True).all()
    servers = Server.query.order_by(Server.created_at.desc()).all()
    # Get active ads for different placements
    sidebar_ads = Advertisement.query.filter_by(is_active=True, placement='sidebar').limit(3).all()
    feed_ads = Advertisement.query.filter_by(is_active=True, placement='feed').limit(2).all()
    return dict(app_version="3.6", sponsors=sponsors, servers=servers, sidebar_ads=sidebar_ads, feed_ads=feed_ads)

# ===================== WebRTC (Polling-based signaling for LiteSpeed) =====================
from datetime import timedelta

@app.route("/video/<room>")
def video_room(room):
    u = current_user()
    if not u:
        return redirect(url_for("login"))
    # Light guard on room name
    room = re.sub(r"[^a-zA-Z0-9_-]", "-", room)[:64]
    return render_template("video_chat.html", room=room, user=u)

@app.route("/api/rtc/join/<room>", methods=["POST"])
def rtc_join(room):
    u = current_user()
    if not u:
        return {"error": "Not logged in"}, 401
    room = re.sub(r"[^a-zA-Z0-9_-]", "-", room)[:64]
    # Upsert participant
    part = RtcParticipant.query.filter_by(room=room, user_id=u.id).first()
    if not part:
        part = RtcParticipant(room=room, user_id=u.id)
        db.session.add(part)
    part.last_seen = datetime.utcnow()
    db.session.commit()
    # Return current participants (excluding self)
    others = RtcParticipant.query.filter(RtcParticipant.room==room, RtcParticipant.user_id!=u.id).all()
    return {"success": True, "participants": [p.user_id for p in others]}

@app.route("/api/rtc/leave/<room>", methods=["POST"])
def rtc_leave(room):
    u = current_user()
    if not u:
        return {"error": "Not logged in"}, 401
    room = re.sub(r"[^a-zA-Z0-9_-]", "-", room)[:64]
    RtcParticipant.query.filter_by(room=room, user_id=u.id).delete()
    # Optionally notify peers
    sig = RtcSignal(room=room, sender_id=u.id, target_id=None, kind="leave", payload="{}")
    db.session.add(sig)
    db.session.commit()
    return {"success": True}

@app.route("/api/rtc/signal/<room>", methods=["POST"])
def rtc_signal(room):
    u = current_user()
    if not u:
        return {"error": "Not logged in"}, 401
    room = re.sub(r"[^a-zA-Z0-9_-]", "-", room)[:64]
    data = request.get_json(force=True, silent=True) or {}
    target_id = data.get("target_id")
    kind = (data.get("kind") or "").strip()
    payload = data.get("payload")
    if kind not in ("offer","answer","candidate","hello","bye"):
        return {"error": "Invalid kind"}, 400
    if not payload:
        return {"error": "Missing payload"}, 400
    sig = RtcSignal(room=room, sender_id=u.id, target_id=target_id, kind=kind, payload=payload)
    db.session.add(sig)
    # Touch presence
    part = RtcParticipant.query.filter_by(room=room, user_id=u.id).first()
    if part:
        part.last_seen = datetime.utcnow()
    # Cleanup old signals (> 2 hours)
    cutoff = datetime.utcnow() - timedelta(hours=2)
    try:
        RtcSignal.query.filter(RtcSignal.created_at < cutoff).delete()
    except Exception:
        pass
    db.session.commit()
    return {"success": True, "id": sig.id}

@app.route("/api/rtc/poll/<room>")
def rtc_poll(room):
    u = current_user()
    if not u:
        return {"error": "Not logged in"}, 401
    room = re.sub(r"[^a-zA-Z0-9_-]", "-", room)[:64]
    since = int(request.args.get("since", "0"))
    # Update presence
    part = RtcParticipant.query.filter_by(room=room, user_id=u.id).first()
    if part:
        part.last_seen = datetime.utcnow()
        db.session.commit()
    # Fetch signals addressed to me or broadcast (target_id is null), after 'since'
    signals = (RtcSignal.query
               .filter(RtcSignal.room==room,
                       RtcSignal.id > since,
                       ((RtcSignal.target_id == u.id) | (RtcSignal.target_id.is_(None))),
                       (RtcSignal.sender_id != u.id))
               .order_by(RtcSignal.id.asc())
               .all())
    out = [{
        "id": s.id,
        "room": s.room,
        "sender_id": s.sender_id,
        "target_id": s.target_id,
        "kind": s.kind,
        "payload": s.payload,
        "created_at": s.created_at.isoformat()
    } for s in signals]
    # Remove stale participants not seen for >5 minutes
    cutoff = datetime.utcnow() - timedelta(minutes=5)
    try:
        RtcParticipant.query.filter(RtcParticipant.last_seen < cutoff).delete()
        db.session.commit()
    except Exception:
        pass
    return {"success": True, "signals": out, "latest": (out[-1]["id"] if out else since)}

@app.route("/shorts")
def shorts():
    shorts = Short.query.order_by(Short.created_at.desc()).limit(24).all()
    return render_template("shorts.html", shorts=shorts, user=current_user())

@app.route("/slots")
def slots():
    return render_template("slots.html", user=current_user())

@app.route("/subscriptions")
def subscriptions():
    u = current_user()
    if not u:
        return redirect(url_for("login"))
    subs = (db.session.query(User)
            .join(Subscription, Subscription.subscribed_to_id == User.id)
            .filter(Subscription.subscriber_id == u.id)
            .all())
    videos = (db.session.query(Video)
             .join(Subscription, Subscription.subscribed_to_id == Video.uploader_id)
             .filter(Subscription.subscriber_id == u.id)
             .order_by(Video.created_at.desc())
             .limit(24)
             .all())
    return render_template("subscriptions.html", subs=subs, videos=videos, user=u)

@app.route("/music")
def music():
    # This could be filtered to only show music-related videos in the future
    videos = Video.query.order_by(Video.created_at.desc()).limit(24).all()
    return render_template("music.html", videos=videos, user=current_user())

@app.route("/playlists")
def playlists():
    u = current_user()
    if not u:
        return redirect(url_for("login"))
    playlists = Playlist.query.filter_by(user_id=u.id).all()
    return render_template("playlists.html", playlists=playlists, user=u)

@app.route("/my-videos")
def my_videos():
    u = current_user()
    if not u:
        return redirect(url_for("login"))
    videos = Video.query.filter_by(uploader_id=u.id).order_by(Video.created_at.desc()).all()
    return render_template("my_videos.html", videos=videos, user=u)

@app.route("/watch-later")
def watch_later():
    u = current_user()
    if not u:
        return redirect(url_for("login"))
    videos = (db.session.query(Video)
             .join(WatchLater, WatchLater.video_id == Video.id)
             .filter(WatchLater.user_id == u.id)
             .order_by(WatchLater.added_at.desc())
             .all())
    return render_template("watch_later.html", videos=videos, user=u)

@app.route("/liked")
def liked():
    u = current_user()
    if not u:
        return redirect(url_for("login"))
    videos = (db.session.query(Video)
             .join(VideoLike, VideoLike.video_id == Video.id)
             .filter(VideoLike.user_id == u.id)
             .order_by(VideoLike.created_at.desc())
             .all())
    return render_template("liked.html", videos=videos, user=u)

@app.route("/downloads")
def downloads():
    u = current_user()
    if not u:
        return redirect(url_for("login"))
    videos = Video.query.order_by(Video.created_at.desc()).limit(24).all()
    return render_template("downloads.html", videos=videos, user=u)

@app.route("/search")
def search():
    query = request.args.get("q", "").strip()
    if not query:
        return redirect(url_for("recent"))
    
    # Search videos by title or description
    videos = Video.query.filter(
        (Video.title.ilike(f"%{query}%")) | 
        (Video.description.ilike(f"%{query}%"))
    ).order_by(Video.created_at.desc()).limit(50).all()
    
    # Search users by username or display name
    users = User.query.filter(
        (User.username.ilike(f"%{query}%")) | 
        (User.display.ilike(f"%{query}%"))
    ).limit(20).all()
    
    # Search servers by name
    servers = Server.query.filter(
        Server.name.ilike(f"%{query}%")
    ).limit(20).all()
    
    return render_template("search.html", query=query, videos=videos, users=users, servers=servers, user=current_user())

@app.route("/go-live")
def go_live():
    u = current_user()
    if not u:
        return redirect(url_for("login"))
    return render_template("go_live.html", user=u)

# --- Posts helpers and routes ---
import re as _re

def _render_post_html(text: str) -> str:
    safe = escape(text or "")
    url_re = _re.compile(r"(https?://[\w\-._~:/?#\[\]@!$&'()*+,;=%]+)")
    safe = url_re.sub(r'<a href="\1" target="_blank" rel="nofollow noopener">\1</a>', str(safe))
    return safe.replace("\n", "<br>")

@app.route("/create-post", methods=["GET","POST"])
def create_post():
    u = current_user()
    if not u:
        return redirect(url_for("login"))
    if request.method == "POST":
        title = (request.form.get("title") or "").strip()[:200]
        content = (request.form.get("content") or "").strip()
        if not title or not content:
            flash("Title and content are required", "error")
            return redirect(url_for("create_post"))
        p = Post(user_id=u.id, title=title, content_raw=content, content_html=_render_post_html(content))
        db.session.add(p); db.session.commit()
        flash("Post published", "success")
        return redirect(url_for("post_view", pid=p.id))
    return render_template("create_post.html", user=u)

@app.route("/posts")
def posts():
    u = current_user()
    rows = (db.session.query(Post, User)
            .join(User, User.id == Post.user_id)
            .order_by(Post.created_at.desc())
            .all())
    return render_template("posts.html", posts=rows, user=u)

@app.route("/post/<int:pid>")
def post_view(pid):
    u = current_user()
    p = db.session.get(Post, pid)
    if not p:
        abort(404)
    author = User.query.get(p.user_id)
    can_edit = bool(u and (u.id == p.user_id or u.is_admin))
    return render_template("post_view.html", post=p, author=author, can_edit=can_edit, user=u)

@app.route("/post/<int:pid>/edit", methods=["GET","POST"])
def post_edit(pid):
    u = current_user()
    if not u:
        return redirect(url_for("login"))
    p = db.session.get(Post, pid)
    if not p:
        abort(404)
    if not (u.id == p.user_id or u.is_admin):
        abort(403)
    if request.method == "POST":
        title = (request.form.get("title") or "").strip()[:200]
        content = (request.form.get("content") or "").strip()
        if not title or not content:
            flash("Title and content are required", "error")
            return redirect(url_for("post_edit", pid=pid))
        p.title = title
        p.content_raw = content
        p.content_html = _render_post_html(content)
        p.updated_at = datetime.utcnow()
        db.session.commit()
        flash("Post updated", "success")
        return redirect(url_for("post_view", pid=pid))
    return render_template("edit_post.html", post=p, user=u)

@app.route("/post/<int:pid>/delete", methods=["POST"])
def post_delete(pid):
    u = current_user()
    if not u:
        return redirect(url_for("login"))
    p = db.session.get(Post, pid)
    if not p:
        abort(404)
    if not (u.id == p.user_id or u.is_admin):
        abort(403)
    db.session.delete(p)
    db.session.commit()
    flash("Post deleted", "success")
    return redirect(url_for("posts"))

@app.route("/notifications")
def notifications():
    u = current_user()
    if not u:
        return redirect(url_for("login"))
    notifs = Notification.query.filter_by(user_id=u.id).order_by(Notification.created_at.desc()).all()
    return render_template("notifications.html", notifications=notifs, user=u)

@app.route("/voice/<slug>/<int:cid>")
def voice_channel(slug, cid):
    s = Server.query.filter_by(slug=slug).first_or_404()
    ch = Channel.query.get_or_404(cid)
    if not ch.is_voice:
        return redirect(url_for("channel", slug=slug, cid=cid))
    u = current_user()
    participants = (db.session.query(User, VoiceParticipant)
                   .join(VoiceParticipant, VoiceParticipant.user_id == User.id)
                   .filter(VoiceParticipant.channel_id == cid)
                   .all())
    return render_template("voice.html", server=s, ch=ch, participants=participants, user=u)

# API routes for actions

@app.route("/playlist/create", methods=["GET", "POST"])
def create_playlist():
    u = current_user()
    if not u:
        return redirect(url_for("login"))
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        if not name:
            flash("Playlist name is required", "error")
            return redirect(url_for("create_playlist"))
        playlist = Playlist(name=name, user_id=u.id)
        db.session.add(playlist)
        db.session.commit()
        flash("Playlist created successfully", "success")
        return redirect(url_for("playlist_detail", pid=playlist.id))
    return render_template("create_playlist.html", user=u)

@app.route("/playlist/<int:pid>")
def playlist_detail(pid):
    u = current_user()
    if not u:
        return redirect(url_for("login"))
    playlist = Playlist.query.get_or_404(pid)
    if playlist.user_id != u.id:
        abort(403)
    # Get videos in playlist order
    videos = (db.session.query(Video)
             .join(PlaylistVideo, PlaylistVideo.video_id == Video.id)
             .filter(PlaylistVideo.playlist_id == pid)
             .order_by(PlaylistVideo.position)
             .all())
    return render_template("playlist_detail.html", playlist=playlist, videos=videos, user=u)

@app.route("/playlist/<int:pid>/edit", methods=["GET", "POST"])
def edit_playlist(pid):
    u = current_user()
    if not u:
        return redirect(url_for("login"))
    playlist = Playlist.query.get_or_404(pid)
    if playlist.user_id != u.id:
        abort(403)
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        if not name:
            flash("Playlist name is required", "error")
            return redirect(url_for("edit_playlist", pid=pid))
        playlist.name = name
        db.session.commit()
        flash("Playlist updated successfully", "success")
        return redirect(url_for("playlist_detail", pid=pid))
    return render_template("edit_playlist.html", playlist=playlist, user=u)

@app.route("/playlist/<int:pid>/delete", methods=["POST"])
def delete_playlist(pid):
    u = current_user()
    if not u:
        return redirect(url_for("login"))
    playlist = Playlist.query.get_or_404(pid)
    if playlist.user_id != u.id:
        abort(403)
    # Delete playlist videos first
    PlaylistVideo.query.filter_by(playlist_id=pid).delete()
    db.session.delete(playlist)
    db.session.commit()
    flash("Playlist deleted successfully", "success")
    return redirect(url_for("playlists"))

@app.route("/api/playlists")
def api_playlists():
    u = current_user()
    if not u:
        return {"error": "Not logged in"}, 401
    playlists = Playlist.query.filter_by(user_id=u.id).all()
    return {"success": True, "playlists": [{"id": p.id, "name": p.name} for p in playlists]}

@app.route("/api/playlist/<int:pid>/add/<int:vid>", methods=["POST"])
def api_add_to_playlist(pid, vid):
    u = current_user()
    if not u:
        return {"error": "Not logged in"}, 401
    playlist = Playlist.query.get_or_404(pid)
    if playlist.user_id != u.id:
        return {"error": "Unauthorized"}, 403
    # Check if already in playlist
    existing = PlaylistVideo.query.filter_by(playlist_id=pid, video_id=vid).first()
    if existing:
        return {"success": True, "message": "Already in playlist"}
    # Get max position
    max_pos = db.session.query(func.max(PlaylistVideo.position)).filter_by(playlist_id=pid).scalar() or 0
    pv = PlaylistVideo(playlist_id=pid, video_id=vid, position=max_pos + 1)
    db.session.add(pv)
    db.session.commit()
    return {"success": True}

@app.route("/api/playlist/<int:pid>/remove/<int:vid>", methods=["POST"])
def api_remove_from_playlist(pid, vid):
    u = current_user()
    if not u:
        return {"error": "Not logged in"}, 401
    playlist = Playlist.query.get_or_404(pid)
    if playlist.user_id != u.id:
        return {"error": "Unauthorized"}, 403
    pv = PlaylistVideo.query.filter_by(playlist_id=pid, video_id=vid).first()
    if pv:
        db.session.delete(pv)
        db.session.commit()
    return {"success": True}

@app.route("/api/like/<int:vid>", methods=["POST"])
def like_video(vid):
    u = current_user()
    if not u:
        return {"error": "Not logged in"}, 401
    if not VideoLike.query.filter_by(user_id=u.id, video_id=vid).first():
        db.session.add(VideoLike(user_id=u.id, video_id=vid))
        # Notify uploader
        video = Video.query.get(vid)
        if video and video.uploader_id and video.uploader_id != u.id:
            notif = Notification(user_id=video.uploader_id, message=f"{u.username} liked your video!")
            db.session.add(notif)
        db.session.commit()
    return {"success": True}

@app.route("/api/watch-later/<int:vid>", methods=["POST"])
def add_watch_later(vid):
    u = current_user()
    if not u:
        return {"error": "Not logged in"}, 401
    if not WatchLater.query.filter_by(user_id=u.id, video_id=vid).first():
        db.session.add(WatchLater(user_id=u.id, video_id=vid))
        db.session.commit()
    return {"success": True}

@app.route("/api/subscribe/<int:uid>", methods=["POST"])
def subscribe(uid):
    u = current_user()
    if not u:
        return {"error": "Not logged in"}, 401
    if u.id != uid and not Subscription.query.filter_by(subscriber_id=u.id, subscribed_to_id=uid).first():
        db.session.add(Subscription(subscriber_id=u.id, subscribed_to_id=uid))
        # Create notification for the subscribed user
        target = User.query.get(uid)
        if target:
            notif = Notification(user_id=uid, message=f"{u.username} subscribed to you!")
            db.session.add(notif)
        db.session.commit()
    return {"success": True}

@app.route("/api/notification/<int:nid>/read", methods=["POST"])
def mark_notification_read(nid):
    u = current_user()
    if not u:
        return {"error": "Not logged in"}, 401
    notif = Notification.query.get(nid)
    if notif and notif.user_id == u.id:
        notif.is_read = True
        db.session.commit()
        return {"success": True}
    return {"error": "Not found"}, 404

@app.route("/api/notifications/unread")
def unread_notifications():
    u = current_user()
    if not u:
        return {"count": 0}
    count = Notification.query.filter_by(user_id=u.id, is_read=False).count()
    return {"count": count}

@app.route("/api/voice/join/<int:cid>", methods=["POST"])
def join_voice(cid):
    u = current_user()
    if not u:
        return {"error": "Not logged in"}, 401
    # Remove any existing participation
    VoiceParticipant.query.filter_by(user_id=u.id).delete()
    # Add to this channel
    db.session.add(VoiceParticipant(user_id=u.id, channel_id=cid))
    db.session.commit()
    return {"success": True}

@app.route("/api/voice/leave/<int:cid>", methods=["POST"])
def leave_voice(cid):
    u = current_user()
    if not u:
        return {"error": "Not logged in"}, 401
    VoiceParticipant.query.filter_by(user_id=u.id, channel_id=cid).delete()
    db.session.commit()
    return {"success": True}

@app.route("/api/voice/mute/<int:cid>", methods=["POST"])
def mute_voice(cid):
    u = current_user()
    if not u:
        return {"error": "Not logged in"}, 401
    part = VoiceParticipant.query.filter_by(user_id=u.id, channel_id=cid).first()
    if part:
        part.is_muted = request.json.get("muted", False)
        db.session.commit()
    return {"success": True}

@app.route("/api/channel/create", methods=["POST"])
def create_channel():
    u = current_user()
    if not u:
        return {"error": "Not logged in"}, 401
    
    data = request.json
    server_slug = data.get("server_slug")
    name = data.get("name", "").strip()
    is_voice = data.get("is_voice", False)
    
    if not server_slug or not name:
        return {"error": "Missing server_slug or name"}, 400
    
    # Find server
    server = Server.query.filter_by(slug=server_slug).first()
    if not server:
        return {"error": "Server not found"}, 404
    
    # Check if user is a member
    member = Membership.query.filter_by(user_id=u.id, server_id=server.id).first()
    if not member:
        return {"error": "You must be a member to create channels"}, 403
    
    # Create channel
    channel = Channel(
        server_id=server.id,
        name=name,
        is_voice=is_voice
    )
    db.session.add(channel)
    db.session.commit()
    
    return {"success": True, "channel_id": channel.id}

@app.route("/api/voice/counts/<slug>")
def voice_counts(slug):
    server = Server.query.filter_by(slug=slug).first()
    if not server:
        return {"error": "Server not found"}, 404
    
    # Get all voice channels for this server
    channels = Channel.query.filter_by(server_id=server.id, is_voice=True).all()
    counts = {}
    for ch in channels:
        count = VoiceParticipant.query.filter_by(channel_id=ch.id).count()
        counts[ch.id] = count
    
    return counts

# ============ Music Bot ============
@app.route("/api/music/bot/invite/<int:cid>", methods=["POST"])
def music_bot_invite(cid):
    """Invite music bot to a voice channel"""
    user = current_user()
    if not user:
        return {"error": "Not logged in"}, 401
    
    channel = Channel.query.get(cid)
    if not channel or not channel.is_voice:
        return {"error": "Voice channel not found"}, 404
    
    # Check if bot already exists
    bot = MusicBot.query.filter_by(channel_id=cid).first()
    if bot:
        bot.is_active = True
        bot.last_activity = datetime.utcnow()
    else:
        bot = MusicBot(channel_id=cid, is_active=True)
        db.session.add(bot)
    
    db.session.commit()
    return {"success": True, "bot_id": bot.id}

@app.route("/api/music/bot/kick/<int:cid>", methods=["POST"])
def music_bot_kick(cid):
    """Remove music bot from a voice channel"""
    user = current_user()
    if not user:
        return {"error": "Not logged in"}, 401
    
    bot = MusicBot.query.filter_by(channel_id=cid).first()
    if not bot:
        return {"error": "Bot not found"}, 404
    
    # Clear queue
    MusicQueue.query.filter_by(channel_id=cid).delete()
    
    # Deactivate bot
    bot.is_active = False
    bot.is_playing = False
    bot.is_paused = False
    bot.current_song = None
    bot.current_song_title = None
    
    db.session.commit()
    return {"success": True}

@app.route("/api/music/bot/play/<int:cid>", methods=["POST"])
def music_bot_play(cid):
    """Add a song to queue and play"""
    user = current_user()
    if not user:
        return {"error": "Not logged in"}, 401
    
    bot = MusicBot.query.filter_by(channel_id=cid).first()
    if not bot or not bot.is_active:
        return {"error": "Bot not active in this channel"}, 404
    
    data = request.get_json() or {}
    song_url = data.get("url", "")
    song_title = data.get("title", "")
    
    if not song_url:
        return {"error": "No URL provided"}, 400
    
    # Extract video ID from YouTube URL
    import re
    youtube_match = re.search(r'(?:youtube\.com/watch\?v=|youtu\.be/)([a-zA-Z0-9_-]+)', song_url)
    if youtube_match:
        video_id = youtube_match.group(1)
        if not song_title:
            song_title = f"YouTube Video {video_id}"
    else:
        if not song_title:
            song_title = "Unknown Song"
    
    # Get next position in queue
    last_pos = db.session.query(db.func.max(MusicQueue.position)).filter_by(
        channel_id=cid, is_played=False
    ).scalar() or 0
    
    # Add to queue
    queue_item = MusicQueue(
        channel_id=cid,
        added_by=user.id,
        song_url=song_url,
        song_title=song_title,
        position=last_pos + 1
    )
    db.session.add(queue_item)
    
    # If nothing playing, start playing this song
    if not bot.is_playing or not bot.current_song:
        bot.current_song = song_url
        bot.current_song_title = song_title
        bot.is_playing = True
        bot.is_paused = False
        queue_item.is_played = True
    
    bot.last_activity = datetime.utcnow()
    db.session.commit()
    
    return {"success": True, "position": queue_item.position, "title": song_title}

@app.route("/api/music/bot/skip/<int:cid>", methods=["POST"])
def music_bot_skip(cid):
    """Skip current song"""
    user = current_user()
    if not user:
        return {"error": "Not logged in"}, 401
    
    bot = MusicBot.query.filter_by(channel_id=cid).first()
    if not bot or not bot.is_active:
        return {"error": "Bot not active"}, 404
    
    # Mark current song as played
    if bot.current_song:
        current = MusicQueue.query.filter_by(
            channel_id=cid, song_url=bot.current_song, is_played=False
        ).first()
        if current:
            current.is_played = True
    
    # Get next song in queue
    next_song = MusicQueue.query.filter_by(
        channel_id=cid, is_played=False
    ).order_by(MusicQueue.position).first()
    
    if next_song:
        bot.current_song = next_song.song_url
        bot.current_song_title = next_song.song_title
        bot.is_playing = True
        bot.is_paused = False
        next_song.is_played = True
    else:
        bot.current_song = None
        bot.current_song_title = None
        bot.is_playing = False
    
    bot.last_activity = datetime.utcnow()
    db.session.commit()
    
    return {"success": True, "next_song": bot.current_song_title}

@app.route("/api/music/bot/pause/<int:cid>", methods=["POST"])
def music_bot_pause(cid):
    """Pause/resume playback"""
    user = current_user()
    if not user:
        return {"error": "Not logged in"}, 401
    
    bot = MusicBot.query.filter_by(channel_id=cid).first()
    if not bot or not bot.is_active:
        return {"error": "Bot not active"}, 404
    
    bot.is_paused = not bot.is_paused
    bot.last_activity = datetime.utcnow()
    db.session.commit()
    
    return {"success": True, "paused": bot.is_paused}

@app.route("/api/music/bot/stop/<int:cid>", methods=["POST"])
def music_bot_stop(cid):
    """Stop playback and clear queue"""
    user = current_user()
    if not user:
        return {"error": "Not logged in"}, 401
    
    bot = MusicBot.query.filter_by(channel_id=cid).first()
    if not bot or not bot.is_active:
        return {"error": "Bot not active"}, 404
    
    bot.is_playing = False
    bot.is_paused = False
    bot.current_song = None
    bot.current_song_title = None
    bot.last_activity = datetime.utcnow()
    
    # Clear queue
    MusicQueue.query.filter_by(channel_id=cid, is_played=False).delete()
    
    db.session.commit()
    return {"success": True}

@app.route("/api/music/bot/loop/<int:cid>", methods=["POST"])
def music_bot_loop(cid):
    """Toggle loop mode: off -> one -> all -> off"""
    user = current_user()
    if not user:
        return {"error": "Not logged in"}, 401
    
    bot = MusicBot.query.filter_by(channel_id=cid).first()
    if not bot or not bot.is_active:
        return {"error": "Bot not active"}, 404
    
    # Cycle through loop modes
    if bot.loop_mode == "off":
        bot.loop_mode = "one"
    elif bot.loop_mode == "one":
        bot.loop_mode = "all"
    else:
        bot.loop_mode = "off"
    
    bot.last_activity = datetime.utcnow()
    db.session.commit()
    
    return {"success": True, "loop_mode": bot.loop_mode}

@app.route("/api/music/bot/shuffle/<int:cid>", methods=["POST"])
def music_bot_shuffle(cid):
    """Toggle shuffle mode and reorder queue"""
    user = current_user()
    if not user:
        return {"error": "Not logged in"}, 401
    
    bot = MusicBot.query.filter_by(channel_id=cid).first()
    if not bot or not bot.is_active:
        return {"error": "Bot not active"}, 404
    
    bot.is_shuffled = not bot.is_shuffled
    
    if bot.is_shuffled:
        # Shuffle the queue
        import random
        queue_items = MusicQueue.query.filter_by(channel_id=cid, is_played=False).all()
        random.shuffle(queue_items)
        for idx, item in enumerate(queue_items, start=1):
            item.position = idx
    else:
        # Restore original order (by id)
        queue_items = MusicQueue.query.filter_by(channel_id=cid, is_played=False).order_by(MusicQueue.id).all()
        for idx, item in enumerate(queue_items, start=1):
            item.position = idx
    
    bot.last_activity = datetime.utcnow()
    db.session.commit()
    
    return {"success": True, "shuffled": bot.is_shuffled}

@app.route("/api/music/bot/remove/<int:cid>/<int:queue_id>", methods=["POST"])
def music_bot_remove(cid, queue_id):
    """Remove a song from queue"""
    user = current_user()
    if not user:
        return {"error": "Not logged in"}, 401
    
    queue_item = MusicQueue.query.filter_by(id=queue_id, channel_id=cid, is_played=False).first()
    if not queue_item:
        return {"error": "Song not found in queue"}, 404
    
    db.session.delete(queue_item)
    
    # Reorder remaining queue items
    remaining = MusicQueue.query.filter_by(channel_id=cid, is_played=False).order_by(MusicQueue.position).all()
    for idx, item in enumerate(remaining, start=1):
        item.position = idx
    
    db.session.commit()
    return {"success": True}

@app.route("/api/music/bot/queue/<int:cid>")
def music_bot_queue(cid):
    """Get current queue"""
    bot = MusicBot.query.filter_by(channel_id=cid).first()
    if not bot:
        return {"error": "Bot not found"}, 404
    
    queue = MusicQueue.query.filter_by(
        channel_id=cid, is_played=False
    ).order_by(MusicQueue.position).all()
    
    return {
        "bot_active": bot.is_active,
        "is_playing": bot.is_playing,
        "is_paused": bot.is_paused,
        "current_song": bot.current_song_title,
        "loop_mode": bot.loop_mode,
        "is_shuffled": bot.is_shuffled,
        "queue": [{"id": q.id, "title": q.song_title, "url": q.song_url, "position": q.position} for q in queue]
    }

@app.route("/api/music/bot/status/<int:cid>")
def music_bot_status(cid):
    """Get bot status"""
    bot = MusicBot.query.filter_by(channel_id=cid).first()
    
    return {
        "active": bot.is_active if bot else False,
        "playing": bot.is_playing if bot else False,
        "paused": bot.is_paused if bot else False,
        "current_song": bot.current_song if bot else None,  # URL for playing
        "current_song_title": bot.current_song_title if bot else None,  # Title for display
        "loop_mode": bot.loop_mode if bot else "off",
        "is_shuffled": bot.is_shuffled if bot else False
    }

@app.route("/api/music/search")
def music_search():
    """Search YouTube videos"""
    query = request.args.get("q", "")
    if not query:
        return {"error": "No query provided"}, 400
    
    try:
        import urllib.request
        import json
        
        # Use YouTube's internal API (no key needed, used by youtube.com itself)
        search_url = f"https://www.youtube.com/results?search_query={urllib.parse.quote(query)}"
        
        # Fetch the page
        req = urllib.request.Request(search_url, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        with urllib.request.urlopen(req, timeout=5) as response:
            html = response.read().decode('utf-8')
        
        # Extract JSON data from the page
        start = html.find('var ytInitialData = ') + len('var ytInitialData = ')
        end = html.find(';</script>', start)
        json_str = html[start:end]
        data = json.loads(json_str)
        
        # Parse video results
        results = []
        try:
            contents = data['contents']['twoColumnSearchResultsRenderer']['primaryContents']['sectionListRenderer']['contents'][0]['itemSectionRenderer']['contents']
            
            for item in contents[:10]:
                if 'videoRenderer' in item:
                    video = item['videoRenderer']
                    video_id = video.get('videoId', '')
                    title = video.get('title', {}).get('runs', [{}])[0].get('text', 'Unknown')
                    channel = video.get('longBylineText', {}).get('runs', [{}])[0].get('text', 'Unknown')
                    
                    # Get duration
                    duration_text = video.get('lengthText', {}).get('simpleText', '0:00')
                    
                    results.append({
                        'videoId': video_id,
                        'title': title,
                        'author': channel,
                        'duration': duration_text
                    })
        except:
            pass
        
        return {"results": results}
    
    except Exception as e:
        print(f"Search error: {e}")
        return {"error": str(e), "results": []}, 500

@app.route("/api/music/bot/cleanup")
def music_bot_cleanup():
    """Remove inactive bots from empty channels"""
    from datetime import timedelta
    
    # Get all active bots
    active_bots = MusicBot.query.filter_by(is_active=True).all()
    kicked_count = 0
    
    for bot in active_bots:
        # Check if channel has any participants
        participant_count = VoiceParticipant.query.filter_by(channel_id=bot.channel_id).count()
        
        # If empty for more than 1 minute (60 seconds)
        if participant_count == 0:
            time_inactive = datetime.utcnow() - bot.last_activity
            if time_inactive > timedelta(seconds=60):
                # Kick the bot
                bot.is_active = False
                bot.is_playing = False
                bot.is_paused = False
                bot.current_song = None
                bot.current_song_title = None
                
                # Clear queue
                MusicQueue.query.filter_by(channel_id=bot.channel_id, is_played=False).delete()
                
                kicked_count += 1
    
    if kicked_count > 0:
        db.session.commit()
    
    return {"kicked": kicked_count}

# ============ Friends & Messaging ============
@app.route("/friends")
def friends():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    
    # Get accepted friends
    friends_list = db.session.query(User).join(
        Friendship, 
        ((Friendship.user_id == user.id) & (Friendship.friend_id == User.id)) |
        ((Friendship.friend_id == user.id) & (Friendship.user_id == User.id))
    ).filter(Friendship.status == "accepted").all()
    
    # Get pending friend requests (received)
    pending = db.session.query(User, Friendship).join(
        Friendship, Friendship.user_id == User.id
    ).filter(
        Friendship.friend_id == user.id,
        Friendship.status == "pending"
    ).all()
    
    return render_template("friends.html", user=user, friends=friends_list, pending=pending, servers=Server.query.all(), sponsors=Sponsor.query.all(), app_version=APP_VERSION)

@app.route("/members")
def members():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    
    # Get all users except current user
    all_members = User.query.filter(User.id != user.id).all()
    
    # Get user's friend IDs (both accepted and pending)
    friend_ids = set()
    friendships = Friendship.query.filter(
        ((Friendship.user_id == user.id) | (Friendship.friend_id == user.id))
    ).all()
    
    for f in friendships:
        if f.user_id == user.id:
            friend_ids.add(f.friend_id)
        else:
            friend_ids.add(f.user_id)
    
    return render_template("members.html", user=user, members=all_members, friend_ids=friend_ids, servers=Server.query.all(), sponsors=Sponsor.query.all(), app_version=APP_VERSION)

@app.route("/messages")
@app.route("/messages/<int:friend_id>")
def messages(friend_id=None):
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    
    # Get friends list
    friends_list = db.session.query(User).join(
        Friendship,
        ((Friendship.user_id == user.id) & (Friendship.friend_id == User.id)) |
        ((Friendship.friend_id == user.id) & (Friendship.user_id == User.id))
    ).filter(Friendship.status == "accepted").all()
    
    # Get conversation if friend selected
    conversation = []
    active_friend = None
    if friend_id:
        active_friend = User.query.get(friend_id)
        if active_friend:
            conversation = DirectMessage.query.filter(
                ((DirectMessage.sender_id == user.id) & (DirectMessage.recipient_id == friend_id)) |
                ((DirectMessage.sender_id == friend_id) & (DirectMessage.recipient_id == user.id))
            ).order_by(DirectMessage.created_at).all()
            
            # Mark messages as read
            DirectMessage.query.filter_by(sender_id=friend_id, recipient_id=user.id, is_read=False).update({"is_read": True})
            db.session.commit()
    
    # Get unread message counts
    unread_counts = {}
    for friend in friends_list:
        count = DirectMessage.query.filter_by(sender_id=friend.id, recipient_id=user.id, is_read=False).count()
        unread_counts[friend.id] = count
    
    return render_template("messages.html", user=user, friends=friends_list, active_friend=active_friend, 
                         conversation=conversation, unread_counts=unread_counts, servers=Server.query.all(), 
                         sponsors=Sponsor.query.all(), app_version=APP_VERSION)

# ============ API: Friends ============
@app.route("/api/friend/add/<int:friend_id>", methods=["POST"])
def add_friend(friend_id):
    user = current_user()
    if not user:
        return {"error": "Not logged in"}, 401
    
    # Check if already friends or pending
    existing = Friendship.query.filter(
        ((Friendship.user_id == user.id) & (Friendship.friend_id == friend_id)) |
        ((Friendship.user_id == friend_id) & (Friendship.friend_id == user.id))
    ).first()
    
    if existing:
        return {"error": "Friend request already exists"}, 400
    
    # Create friend request
    friendship = Friendship(user_id=user.id, friend_id=friend_id, status="pending")
    db.session.add(friendship)
    db.session.commit()
    
    # Create notification for recipient
    friend = User.query.get(friend_id)
    if friend:
        notif = Notification(user_id=friend_id, message=f"{user.username} sent you a friend request", link=url_for("friends"))
        db.session.add(notif)
        db.session.commit()
    
    return {"success": True}

@app.route("/api/friend/accept/<int:friendship_id>", methods=["POST"])
def accept_friend(friendship_id):
    user = current_user()
    if not user:
        return {"error": "Not logged in"}, 401
    
    friendship = Friendship.query.get(friendship_id)
    if not friendship or friendship.friend_id != user.id:
        return {"error": "Invalid request"}, 400
    
    friendship.status = "accepted"
    friendship.accepted_at = datetime.utcnow()
    db.session.commit()
    
    # Notify requester
    notif = Notification(user_id=friendship.user_id, message=f"{user.username} accepted your friend request", link=url_for("messages", friend_id=user.id))
    db.session.add(notif)
    db.session.commit()
    
    return {"success": True}

@app.route("/api/friend/remove/<int:friend_id>", methods=["POST"])
def remove_friend(friend_id):
    user = current_user()
    if not user:
        return {"error": "Not logged in"}, 401
    
    friendship = Friendship.query.filter(
        ((Friendship.user_id == user.id) & (Friendship.friend_id == friend_id)) |
        ((Friendship.user_id == friend_id) & (Friendship.friend_id == user.id))
    ).first()
    
    if friendship:
        db.session.delete(friendship)
        db.session.commit()
    
    return {"success": True}

# ============ API: Messages ============
@app.route("/api/message/send/<int:recipient_id>", methods=["POST"])
def send_message(recipient_id):
    user = current_user()
    if not user:
        return {"error": "Not logged in"}, 401
    
    content = request.json.get("content", "").strip()
    if not content:
        return {"error": "Message cannot be empty"}, 400
    
    # Check if friends
    friendship = Friendship.query.filter(
        ((Friendship.user_id == user.id) & (Friendship.friend_id == recipient_id)) |
        ((Friendship.user_id == recipient_id) & (Friendship.friend_id == user.id)),
        Friendship.status == "accepted"
    ).first()
    
    if not friendship:
        return {"error": "You must be friends to send messages"}, 403
    
    msg = DirectMessage(sender_id=user.id, recipient_id=recipient_id, content=content)
    db.session.add(msg)
    db.session.commit()
    
    # Create notification
    notif = Notification(user_id=recipient_id, message=f"New message from {user.username}", link=url_for("messages", friend_id=user.id))
    db.session.add(notif)
    db.session.commit()
    
    return {"success": True, "message": {
        "id": msg.id,
        "sender_id": msg.sender_id,
        "content": msg.content,
        "created_at": msg.created_at.isoformat()
    }}

@app.route("/api/messages/unread")
def unread_messages():
    user = current_user()
    if not user:
        return {"error": "Not logged in"}, 401
    
    count = DirectMessage.query.filter_by(recipient_id=user.id, is_read=False).count()
    return {"count": count}

@app.route("/api/status/update", methods=["POST"])
def update_status():
    user = current_user()
    if not user:
        return {"error": "Not logged in"}, 401
    
    data = request.json
    new_status = data.get("status")
    
    if new_status not in ["online", "offline", "too_stoned"]:
        return {"error": "Invalid status"}, 400
    
    user.status = new_status
    user.last_seen = datetime.utcnow()
    db.session.commit()
    
    return {"success": True, "status": new_status}

@app.route("/api/status/heartbeat", methods=["POST"])
def status_heartbeat():
    """Update last_seen timestamp to track online status"""
    user = current_user()
    if not user:
        return {"error": "Not logged in"}, 401
    
    user.last_seen = datetime.utcnow()
    if user.status == "offline":
        user.status = "online"
    db.session.commit()
    
    return {"success": True}

@app.route("/api/emojis")
def get_custom_emojis():
    """Return custom emojis for emoji picker"""
    emojis = CustomEmoji.query.filter_by(is_active=True).order_by(CustomEmoji.category, CustomEmoji.sort_order).all()
    grouped = {}
    for e in emojis:
        if e.category not in grouped:
            grouped[e.category] = []
        # Return object with char/image for each emoji
        emoji_data = {
            'id': e.id,
            'label': e.label
        }
        if e.image_path:
            emoji_data['image'] = url_for('uploads', filename=e.image_path, _external=True)
        else:
            emoji_data['char'] = e.emoji_char
        grouped[e.category].append(emoji_data)
    return {"success": True, "emojis": grouped}

@app.route("/api/friends/status")
def api_friends_status():
    """Return the statuses for accepted friends of the current user.
    Used by the friends page to update presence without full reload.
    """
    u = current_user()
    if not u:
        return {"error": "Not logged in"}, 401
    # Accepted friendships where current user is either side
    friends_a = db.session.query(User).join(Friendship, Friendship.friend_id == User.id) \
        .filter(Friendship.user_id == u.id, Friendship.status == 'accepted').all()
    friends_b = db.session.query(User).join(Friendship, Friendship.user_id == User.id) \
        .filter(Friendship.friend_id == u.id, Friendship.status == 'accepted').all()
    friends = {f.id: f for f in friends_a}
    for f in friends_b:
        friends[f.id] = f
    data = []
    for f in friends.values():
        data.append({
            "id": f.id,
            "status": f.status or "offline",
            "last_seen": f.last_seen.isoformat() if f.last_seen else None
        })
    return {"success": True, "friends": data}

@app.route("/health")
def health_check():
    """Health check endpoint for deployment platforms."""
    try:
        # Check database connection
        db.session.execute(db.text("SELECT 1"))
        db_status = "healthy"
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"
    
    return {
        "status": "healthy" if db_status == "healthy" else "degraded",
        "version": APP_VERSION,
        "database": db_status,
        "upload_dirs": {
            "videos": os.path.exists(VIDEO_DIR),
            "thumbnails": os.path.exists(THUMB_DIR),
            "avatars": os.path.exists(AVATAR_DIR)
        }
    }

if __name__ == "__main__":
    # Production: Set debug=False and use gunicorn
    # Development: debug=True
    import os
    debug_mode = os.environ.get("FLASK_ENV") != "production"
    app.run(host="0.0.0.0", port=5000, debug=debug_mode)

 
