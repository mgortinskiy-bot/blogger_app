from __future__ import annotations

import os
import secrets
from collections import defaultdict
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

import bcrypt
from flask import Flask, flash, g, redirect, render_template, request, session, url_for
from sqlalchemy import func, or_, text

from email_service import send_reset_email
from models import (
    Base,
    BloggerPost,
    BloggerPostAnalysis,
    Order,
    OrderOffer,
    OrderOfferStatus,
    OrderStatus,
    PasswordResetToken,
    User,
    UserRole,
    make_engine,
    make_session_factory,
)

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "hype.db"

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-change-me-proekt-hayp")

_database_url = os.environ.get("DATABASE_URL", "").strip() or None
engine = make_engine(
    database_url=_database_url,
    sqlite_path=str(DB_PATH) if not _database_url else None,
)
SessionLocal = make_session_factory(engine)


def get_db():
    if "db" not in g:
        g.db = SessionLocal()
    return g.db


@app.teardown_appcontext
def teardown_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def hash_password(raw: str) -> str:
    return bcrypt.hashpw(raw.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(raw: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(raw.encode("utf-8"), hashed.encode("utf-8"))
    except ValueError:
        return False


def init_db():
    Base.metadata.create_all(engine)
    ensure_schema()
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.username == "admin").first()
        if not admin:
            admin = User(
                email="admin@proekt-hayp.local",
                username="admin",
                password_hash=hash_password("admin1612"),
                role=UserRole.ADMIN,
                blocked=False,
                points=0,
            )
            db.add(admin)
            db.commit()
    finally:
        db.close()


def ensure_schema():
    """Простейшая миграция без Alembic: добавляет недостающие колонки/таблицы.

    Работает для SQLite и PostgreSQL. Для существующих инсталляций Render это критично.
    """
    dialect = engine.dialect.name

    def has_column_sqlite(table_name: str, col: str) -> bool:
        rows = engine.execute(text(f"PRAGMA table_info({table_name})")).fetchall()  # type: ignore[attr-defined]
        return any(r[1] == col for r in rows)

    def has_column_pg(table_name: str, col: str) -> bool:
        q = text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = :t AND column_name = :c LIMIT 1"
        )
        with engine.connect() as conn:
            return conn.execute(q, {"t": table_name, "c": col}).first() is not None

    def has_column(table_name: str, col: str) -> bool:
        if dialect == "sqlite":
            with engine.connect() as conn:
                rows = conn.execute(text(f"PRAGMA table_info({table_name})")).fetchall()
            return any(r[1] == col for r in rows)
        return has_column_pg(table_name, col)

    def add_column(table_name: str, col_ddl: str):
        with engine.begin() as conn:
            conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {col_ddl}"))

    # users additions
    user_cols = {
        "display_name": "display_name VARCHAR(120)",
        "blog_url": "blog_url VARCHAR(600)",
        "bio": "bio VARCHAR(800)",
        "niche_tags": "niche_tags VARCHAR(500)",
    }
    for c, ddl in user_cols.items():
        if not has_column("users", c):
            add_column("users", ddl)

    # orders additions
    order_cols = {
        "budget_rub": "budget_rub INTEGER",
        "payout_rub": "payout_rub INTEGER",
        "result_notes": "result_notes VARCHAR(1200)",
    }
    for c, ddl in order_cols.items():
        if not has_column("orders", c):
            add_column("orders", ddl)

    # new tables (safe via create_all)
    Base.metadata.create_all(engine)


init_db()


UNETHICAL_KEYWORDS = {
    "ненависть",
    "расизм",
    "нацизм",
    "террор",
    "суицид",
    "наркот",
    "порн",
    "экстрем",
    "насили",
}


def summarize_text(text_in: str, max_sentences: int = 4) -> str:
    # простое экстрактивное саммари: первые предложения + наиболее частотные слова
    t = " ".join((text_in or "").split())
    if not t:
        return ""
    parts = [p.strip() for p in t.replace("!", ".").replace("?", ".").split(".") if p.strip()]
    return ". ".join(parts[:max_sentences]) + ("." if parts else "")


def unethical_flags(text_in: str) -> list[str]:
    t = (text_in or "").lower()
    flags = []
    for k in UNETHICAL_KEYWORDS:
        if k in t:
            flags.append(k)
    return sorted(set(flags))


def login_user(user: User):
    session["user_id"] = user.id
    session["role"] = user.role


def logout_user():
    session.pop("user_id", None)
    session.pop("role", None)


def current_user() -> User | None:
    uid = session.get("user_id")
    if not uid:
        return None
    db = get_db()
    return db.get(User, uid)


def require_login(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user:
            flash("Войдите в аккаунт.", "warning")
            return redirect(url_for("login"))
        if user.blocked:
            logout_user()
            flash("Аккаунт заблокирован.", "danger")
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return wrapped


def require_role(*roles: str):
    def deco(f):
        @wraps(f)
        @require_login
        def wrapped(*args, **kwargs):
            user = current_user()
            if user.role not in roles:
                flash("Недостаточно прав.", "danger")
                return redirect(url_for("index"))
            return f(*args, **kwargs)

        return wrapped

    return deco


@app.context_processor
def inject_user():
    return {"current_user": current_user()}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ident = (request.form.get("login") or "").strip()
        password = request.form.get("password") or ""
        db = get_db()
        user = db.query(User).filter(User.username == ident).first()
        if not user:
            user = db.query(User).filter(func.lower(User.email) == ident.lower()).first()
        if not user or not verify_password(password, user.password_hash):
            flash("Неверный логин или пароль.", "danger")
            return render_template("login.html")
        if user.blocked:
            flash("Аккаунт заблокирован.", "danger")
            return render_template("login.html")
        user.last_login = datetime.utcnow()
        db.commit()
        login_user(user)
        flash("Добро пожаловать!", "success")
        if user.role == UserRole.ADMIN:
            return redirect(url_for("admin_dashboard"))
        if user.role == UserRole.BLOGGER:
            return redirect(url_for("blogger_orders"))
        return redirect(url_for("advertiser_orders"))
    return render_template("login.html")


@app.route("/logout")
def logout():
    logout_user()
    flash("Вы вышли из системы.", "info")
    return redirect(url_for("index"))


@app.route("/register/blogger", methods=["GET", "POST"])
def register_blogger():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        password2 = request.form.get("password2") or ""
        if not email or "@" not in email:
            flash("Укажите корректный email.", "danger")
            return render_template("register_blogger.html")
        if len(password) < 6:
            flash("Пароль не короче 6 символов.", "danger")
            return render_template("register_blogger.html")
        if password != password2:
            flash("Пароли не совпадают.", "danger")
            return render_template("register_blogger.html")
        db = get_db()
        if db.query(User).filter(func.lower(User.email) == email).first():
            flash("Этот email уже зарегистрирован.", "danger")
            return render_template("register_blogger.html")
        u = User(
            email=email,
            username=None,
            password_hash=hash_password(password),
            role=UserRole.BLOGGER,
            blocked=False,
            points=0,
        )
        db.add(u)
        db.commit()
        flash("Регистрация успешна. Войдите.", "success")
        return redirect(url_for("login"))
    return render_template("register_blogger.html")


@app.route("/register/advertiser", methods=["GET", "POST"])
def register_advertiser():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        password2 = request.form.get("password2") or ""
        if not email or "@" not in email:
            flash("Укажите корректный email.", "danger")
            return render_template("register_advertiser.html")
        if len(password) < 6:
            flash("Пароль не короче 6 символов.", "danger")
            return render_template("register_advertiser.html")
        if password != password2:
            flash("Пароли не совпадают.", "danger")
            return render_template("register_advertiser.html")
        db = get_db()
        if db.query(User).filter(func.lower(User.email) == email).first():
            flash("Этот email уже зарегистрирован.", "danger")
            return render_template("register_advertiser.html")
        u = User(
            email=email,
            username=None,
            password_hash=hash_password(password),
            role=UserRole.ADVERTISER,
            blocked=False,
            points=0,
        )
        db.add(u)
        db.commit()
        flash("Регистрация успешна. Войдите.", "success")
        return redirect(url_for("login"))
    return render_template("register_advertiser.html")


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        db = get_db()
        user = db.query(User).filter(func.lower(User.email) == email).first()
        if not user or user.role == UserRole.ADMIN:
            flash("Если аккаунт существует, на почту отправлена ссылка.", "info")
            return redirect(url_for("login"))
        raw = secrets.token_urlsafe(32)
        tok = PasswordResetToken(
            user_id=user.id,
            token=raw,
            expires_at=datetime.utcnow() + timedelta(hours=2),
            used=False,
        )
        db.add(tok)
        db.commit()
        reset_url = request.url_root.rstrip("/") + url_for("reset_password", token=raw)
        ok, err = send_reset_email(user.email, reset_url)
        if ok:
            flash("Письмо со ссылкой отправлено.", "success")
        else:
            flash(
                f"Почта не отправлена: {err}. Ссылка для сброса (скопируйте): {reset_url}",
                "warning",
            )
        return redirect(url_for("login"))
    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token: str):
    db = get_db()
    tok = db.query(PasswordResetToken).filter(PasswordResetToken.token == token).first()
    if not tok or tok.used or tok.expires_at < datetime.utcnow():
        flash("Ссылка недействительна или истекла.", "danger")
        return redirect(url_for("forgot_password"))
    if request.method == "POST":
        p1 = request.form.get("password") or ""
        p2 = request.form.get("password2") or ""
        if len(p1) < 6:
            flash("Пароль не короче 6 символов.", "danger")
            return render_template("reset_password.html", token=token)
        if p1 != p2:
            flash("Пароли не совпадают.", "danger")
            return render_template("reset_password.html", token=token)
        user = db.get(User, tok.user_id)
        if user:
            user.password_hash = hash_password(p1)
        tok.used = True
        db.commit()
        flash("Пароль обновлён. Войдите.", "success")
        return redirect(url_for("login"))
    return render_template("reset_password.html", token=token)


# ——— Admin ———


@app.route("/admin")
@require_role(UserRole.ADMIN)
def admin_dashboard():
    db = get_db()
    total_users = db.query(func.count(User.id)).scalar() or 0
    bloggers = db.query(func.count(User.id)).filter(User.role == UserRole.BLOGGER).scalar() or 0
    advertisers = db.query(func.count(User.id)).filter(User.role == UserRole.ADVERTISER).scalar() or 0
    orders_total = db.query(func.count(Order.id)).scalar() or 0
    orders_done = (
        db.query(func.count(Order.id)).filter(Order.status == OrderStatus.COMPLETED).scalar() or 0
    )

    since = datetime.utcnow() - timedelta(days=14)
    new_users = (
        db.query(User)
        .filter(User.created_at >= since, User.role != UserRole.ADMIN)
        .order_by(User.created_at.desc())
        .limit(200)
        .all()
    )
    by_day: dict[str, int] = defaultdict(int)
    for u in new_users:
        key = u.created_at.strftime("%Y-%m-%d") if u.created_at else ""
        by_day[key] += 1
    chart_labels = sorted(by_day.keys())
    chart_values = [by_day[k] for k in chart_labels]
    chart_max = max(chart_values) if chart_values else 1

    recent_orders = db.query(Order).order_by(Order.created_at.desc()).limit(15).all()

    active_bloggers = (
        db.query(User)
        .filter(User.role == UserRole.BLOGGER, User.last_login.isnot(None))
        .order_by(User.last_login.desc())
        .limit(20)
        .all()
    )

    return render_template(
        "admin_dashboard.html",
        total_users=total_users,
        bloggers=bloggers,
        advertisers=advertisers,
        orders_total=orders_total,
        orders_done=orders_done,
        chart_labels=chart_labels,
        chart_values=chart_values,
        chart_max=chart_max,
        recent_orders=recent_orders,
        active_bloggers=active_bloggers,
    )


@app.route("/admin/users")
@require_role(UserRole.ADMIN)
def admin_users():
    db = get_db()
    users = db.query(User).order_by(User.created_at.desc()).all()
    return render_template("admin_users.html", users=users)


@app.route("/admin/users/<int:user_id>/toggle-block", methods=["POST"])
@require_role(UserRole.ADMIN)
def admin_toggle_block(user_id: int):
    db = get_db()
    u = db.get(User, user_id)
    if not u or u.role == UserRole.ADMIN:
        flash("Действие невозможно.", "danger")
        return redirect(url_for("admin_users"))
    u.blocked = not u.blocked
    db.commit()
    flash("Статус блокировки обновлён.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@require_role(UserRole.ADMIN)
def admin_delete_user(user_id: int):
    db = get_db()
    u = db.get(User, user_id)
    if not u or u.role == UserRole.ADMIN:
        flash("Действие невозможно.", "danger")
        return redirect(url_for("admin_users"))
    db.delete(u)
    db.commit()
    flash("Пользователь удалён.", "success")
    return redirect(url_for("admin_users"))


# ——— Blogger ———


@app.route("/blogger/orders")
@require_role(UserRole.BLOGGER)
def blogger_orders():
    db = get_db()
    q = (request.args.get("q") or "").strip()
    query = db.query(Order).filter(Order.status == OrderStatus.OPEN)
    if q:
        like = f"%{q.lower()}%"
        query = query.filter(
            or_(
                func.lower(Order.title).like(like),
                func.lower(Order.description).like(like),
            )
        )
    orders_open = query.order_by(Order.created_at.desc()).all()
    user = current_user()
    my_active = (
        db.query(Order)
        .filter(Order.blogger_id == user.id, Order.status == OrderStatus.ASSIGNED)
        .order_by(Order.created_at.desc())
        .all()
    )
    return render_template("blogger_orders.html", orders_open=orders_open, my_active=my_active, q=q)


@app.route("/blogger/profile", methods=["GET", "POST"])
@require_role(UserRole.BLOGGER)
def blogger_profile():
    db = get_db()
    user = current_user()
    if request.method == "POST":
        user.display_name = (request.form.get("display_name") or "").strip() or None
        user.blog_url = (request.form.get("blog_url") or "").strip() or None
        user.bio = (request.form.get("bio") or "").strip() or None
        user.niche_tags = (request.form.get("niche_tags") or "").strip() or None
        db.commit()
        flash("Профиль обновлён.", "success")
        return redirect(url_for("blogger_profile"))

    posts = (
        db.query(BloggerPost)
        .filter(BloggerPost.blogger_id == user.id)
        .order_by(BloggerPost.created_at.desc())
        .limit(3)
        .all()
    )
    last_analysis = (
        db.query(BloggerPostAnalysis)
        .filter(BloggerPostAnalysis.blogger_id == user.id)
        .order_by(BloggerPostAnalysis.checked_at.desc())
        .first()
    )
    return render_template("blogger_profile.html", posts=posts, last_analysis=last_analysis)


@app.route("/blogger/posts", methods=["POST"])
@require_role(UserRole.BLOGGER)
def blogger_update_posts():
    db = get_db()
    user = current_user()
    # очищаем и сохраняем 3 последних поста (текст+ссылка вводятся вручную)
    db.query(BloggerPost).filter(BloggerPost.blogger_id == user.id).delete()
    for i in range(1, 4):
        urlv = (request.form.get(f"url{i}") or "").strip() or None
        textv = (request.form.get(f"text{i}") or "").strip()
        if textv:
            db.add(BloggerPost(blogger_id=user.id, url=urlv, text=textv))
    db.commit()
    flash("Посты обновлены.", "success")
    return redirect(url_for("blogger_profile"))


@app.route("/blogger/analyze-posts", methods=["POST"])
@require_role(UserRole.BLOGGER)
def blogger_analyze_posts():
    db = get_db()
    user = current_user()
    posts = (
        db.query(BloggerPost)
        .filter(BloggerPost.blogger_id == user.id)
        .order_by(BloggerPost.created_at.desc())
        .limit(3)
        .all()
    )
    joined = "\n\n".join([p.text for p in posts])
    summary = summarize_text(joined)
    flags = unethical_flags(joined)
    db.add(BloggerPostAnalysis(blogger_id=user.id, summary=summary, flags=",".join(flags)))
    db.commit()
    if flags:
        flash("Найдены потенциально неэтичные темы/слова: " + ", ".join(flags), "warning")
    else:
        flash("Проверка пройдена: явных неэтичных слов/тем не найдено.", "success")
    return redirect(url_for("blogger_profile"))


@app.route("/blogger/orders/<int:order_id>/take", methods=["POST"])
@require_role(UserRole.BLOGGER)
def blogger_take_order(order_id: int):
    db = get_db()
    user = current_user()
    order = db.get(Order, order_id)
    if not order or order.status != OrderStatus.OPEN:
        flash("Заказ недоступен.", "danger")
        return redirect(url_for("blogger_orders"))
    order.status = OrderStatus.ASSIGNED
    order.blogger_id = user.id
    db.commit()
    flash("Заказ взят в работу.", "success")
    return redirect(url_for("blogger_orders"))


@app.route("/blogger/orders/<int:order_id>/complete", methods=["POST"])
@require_role(UserRole.BLOGGER)
def blogger_complete_order(order_id: int):
    db = get_db()
    user = current_user()
    order = db.get(Order, order_id)
    if not order or order.blogger_id != user.id or order.status != OrderStatus.ASSIGNED:
        flash("Нельзя завершить этот заказ.", "danger")
        return redirect(url_for("blogger_orders"))
    order.status = OrderStatus.COMPLETED
    order.completed_at = datetime.utcnow()
    user.points = (user.points or 0) + max(0, order.points_reward)
    db.commit()
    flash(f"Заказ выполнен. Начислено {order.points_reward} баллов.", "success")
    return redirect(url_for("blogger_stats"))


@app.route("/blogger/stats")
@require_role(UserRole.BLOGGER)
def blogger_stats():
    db = get_db()
    user = current_user()
    completed = (
        db.query(Order)
        .filter(Order.blogger_id == user.id, Order.status == OrderStatus.COMPLETED)
        .order_by(Order.completed_at.desc())
        .all()
    )
    total_points = sum(o.points_reward for o in completed)
    return render_template(
        "blogger_stats.html",
        completed=completed,
        total_points=total_points,
        balance=user.points or 0,
    )


# ——— Advertiser ———


@app.route("/advertiser/orders")
@require_role(UserRole.ADVERTISER)
def advertiser_orders():
    db = get_db()
    user = current_user()
    orders = (
        db.query(Order)
        .filter(Order.advertiser_id == user.id)
        .order_by(Order.created_at.desc())
        .all()
    )
    return render_template("advertiser_orders.html", orders=orders)


def recommend_bloggers(db, advertiser_id: int, limit: int = 8):
    # MVP-рекомендации: активные не заблокированные блогеры, сортировка по выполненным заказам и совпадению тегов
    adv = db.get(User, advertiser_id)
    adv_tags = set((adv.niche_tags or "").lower().split(",")) if adv else set()

    bloggers = (
        db.query(User)
        .filter(User.role == UserRole.BLOGGER, User.blocked.is_(False))
        .all()
    )
    scored = []
    for b in bloggers:
        b_tags = set((b.niche_tags or "").lower().split(","))
        overlap = len({t.strip() for t in adv_tags if t.strip()} & {t.strip() for t in b_tags if t.strip()})
        done = db.query(func.count(Order.id)).filter(Order.blogger_id == b.id, Order.status == OrderStatus.COMPLETED).scalar() or 0
        score = overlap * 5 + done
        scored.append((score, b, overlap, done))
    scored.sort(key=lambda x: x[0], reverse=True)
    return scored[:limit]


@app.route("/advertiser/bloggers")
@require_role(UserRole.ADVERTISER)
def advertiser_bloggers():
    db = get_db()
    user = current_user()
    q = (request.args.get("q") or "").strip().lower()
    bloggers_q = db.query(User).filter(User.role == UserRole.BLOGGER, User.blocked.is_(False))
    if q:
        like = f"%{q}%"
        bloggers_q = bloggers_q.filter(or_(func.lower(User.email).like(like), func.lower(User.display_name).like(like)))
    bloggers = bloggers_q.order_by(User.created_at.desc()).limit(200).all()
    reco = recommend_bloggers(db, user.id, limit=8)
    return render_template("advertiser_bloggers.html", bloggers=bloggers, reco=reco, q=q)


@app.route("/advertiser/orders/<int:order_id>/offer", methods=["POST"])
@require_role(UserRole.ADVERTISER)
def advertiser_offer(order_id: int):
    db = get_db()
    user = current_user()
    blogger_id = int(request.form.get("blogger_id") or "0")
    order = db.get(Order, order_id)
    blogger = db.get(User, blogger_id)
    if not order or order.advertiser_id != user.id or not blogger or blogger.role != UserRole.BLOGGER:
        flash("Нельзя создать предложение.", "danger")
        return redirect(url_for("advertiser_orders"))
    if order.status != OrderStatus.OPEN:
        flash("Предложения возможны только для открытых заказов.", "warning")
        return redirect(url_for("advertiser_orders"))
    exists = (
        db.query(OrderOffer)
        .filter(OrderOffer.order_id == order.id, OrderOffer.blogger_id == blogger.id)
        .first()
    )
    if exists:
        flash("Предложение этому блогеру уже отправлено.", "info")
        return redirect(url_for("advertiser_orders"))
    db.add(OrderOffer(order_id=order.id, blogger_id=blogger.id, status=OrderOfferStatus.PENDING))
    db.commit()
    flash("Предложение отправлено.", "success")
    return redirect(url_for("advertiser_orders"))


@app.route("/blogger/offers")
@require_role(UserRole.BLOGGER)
def blogger_offers():
    db = get_db()
    user = current_user()
    offers = (
        db.query(OrderOffer, Order)
        .join(Order, Order.id == OrderOffer.order_id)
        .filter(OrderOffer.blogger_id == user.id)
        .order_by(OrderOffer.created_at.desc())
        .all()
    )
    return render_template("blogger_offers.html", offers=offers)


@app.route("/blogger/offers/<int:offer_id>/<action>", methods=["POST"])
@require_role(UserRole.BLOGGER)
def blogger_offer_action(offer_id: int, action: str):
    db = get_db()
    user = current_user()
    offer = db.get(OrderOffer, offer_id)
    if not offer or offer.blogger_id != user.id:
        flash("Предложение не найдено.", "danger")
        return redirect(url_for("blogger_offers"))
    if action == "accept":
        offer.status = OrderOfferStatus.ACCEPTED
        order = db.get(Order, offer.order_id)
        if order and order.status == OrderStatus.OPEN and not order.blogger_id:
            order.status = OrderStatus.ASSIGNED
            order.blogger_id = user.id
        db.commit()
        flash("Предложение принято.", "success")
    elif action == "reject":
        offer.status = OrderOfferStatus.REJECTED
        db.commit()
        flash("Предложение отклонено.", "info")
    return redirect(url_for("blogger_offers"))


@app.route("/tools/generate", methods=["GET", "POST"])
@require_login
def tools_generate():
    # MVP: генерируем текст + изображение-черновик без внешних API
    from PIL import Image, ImageDraw, ImageFont
    prompt = ""
    generated_text = ""
    img_url = None
    if request.method == "POST":
        prompt = (request.form.get("prompt") or "").strip()
        if prompt:
            generated_text = (
                "Черновик поста:\n\n"
                f"Тема: {prompt}\n\n"
                "1) Захват внимания: короткий факт/вопрос.\n"
                "2) Польза: 2–3 тезиса.\n"
                "3) Личный опыт/пример.\n"
                "4) Призыв к действию.\n"
            )
            img = Image.new("RGB", (1024, 576), (24, 9, 40))
            d = ImageDraw.Draw(img)
            title = "Проект Хайп"
            text_body = (prompt[:140] + "…") if len(prompt) > 140 else prompt
            d.rounded_rectangle([40, 40, 984, 536], radius=28, outline=(200, 160, 252), width=4)
            d.text((70, 70), title, fill=(233, 213, 255))
            d.text((70, 120), text_body, fill=(244, 240, 255))
            out_dir = BASE_DIR / "static" / "gen"
            out_dir.mkdir(parents=True, exist_ok=True)
            name = f"gen_{secrets.token_hex(6)}.png"
            path = out_dir / name
            img.save(path, format="PNG")
            img_url = url_for("static", filename=f"gen/{name}")
    return render_template("tools_generate.html", prompt=prompt, generated_text=generated_text, img_url=img_url)


@app.route("/advertiser/orders/new", methods=["GET", "POST"])
@require_role(UserRole.ADVERTISER)
def advertiser_new_order():
    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        description = (request.form.get("description") or "").strip()
        try:
            points = int(request.form.get("points_reward") or "0")
        except ValueError:
            points = 0
        try:
            budget_rub = int(request.form.get("budget_rub") or "0")
        except ValueError:
            budget_rub = 0
        try:
            payout_rub = int(request.form.get("payout_rub") or "0")
        except ValueError:
            payout_rub = 0
        if not title or not description:
            flash("Заполните название и описание.", "danger")
            return render_template("advertiser_new_order.html")
        if points < 1:
            flash("Награда в баллах — не менее 1.", "danger")
            return render_template("advertiser_new_order.html")
        db = get_db()
        user = current_user()
        o = Order(
            advertiser_id=user.id,
            title=title,
            description=description,
            points_reward=points,
            budget_rub=budget_rub or None,
            payout_rub=payout_rub or None,
            status=OrderStatus.OPEN,
        )
        db.add(o)
        db.commit()
        flash("Заказ опубликован.", "success")
        return redirect(url_for("advertiser_orders"))
    return render_template("advertiser_new_order.html")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=True)
