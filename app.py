from __future__ import annotations

import html
import math
import os
import re
import secrets
import xml.etree.ElementTree as ET
from urllib.parse import quote, urljoin, urlparse
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

import bcrypt
from flask import Flask, flash, g, redirect, render_template, request, session, url_for, Response
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

# Стартовый баланс баллов; при создании заказа рекламодатель тратит points_reward с этого баланса.
STARTING_POINTS = 1000


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
                points=STARTING_POINTS,
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
        "full_name": "full_name VARCHAR(200)",
        "phone": "phone VARCHAR(40)",
        "telegram": "telegram VARCHAR(120)",
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

    # blogger_post_analyses
    analysis_cols = {
        "audience_text": "audience_text TEXT",
        "audience_insights": "audience_insights TEXT",
    }
    for c, ddl in analysis_cols.items():
        if not has_column("blogger_post_analyses", c):
            add_column("blogger_post_analyses", ddl)

    # new tables (safe via create_all)
    Base.metadata.create_all(engine)

    _grant_existing_users_starting_bonus_once()


def _grant_existing_users_starting_bonus_once() -> None:
    """Один раз: +STARTING_POINTS всем пользователям (идемпотентно, для уже существующих БД)."""
    meta_key = "users_starting_points_bonus_v1"
    with engine.begin() as conn:
        conn.execute(
            text(
                "CREATE TABLE IF NOT EXISTS app_meta ("
                "key VARCHAR(80) PRIMARY KEY, value VARCHAR(255) NOT NULL)"
            )
        )
        done = conn.execute(
            text("SELECT 1 FROM app_meta WHERE key = :k LIMIT 1"), {"k": meta_key}
        ).first()
        if done:
            return
        conn.execute(text("UPDATE users SET points = COALESCE(points, 0) + :p"), {"p": STARTING_POINTS})
        conn.execute(
            text("INSERT INTO app_meta (key, value) VALUES (:k, '1')"), {"k": meta_key}
        )


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

def _clean_text_excerpt(s: str, max_len: int = 900) -> str:
    t = html.unescape(" ".join((s or "").split()))
    if not t:
        return ""
    if len(t) <= max_len:
        return t
    return t[: max_len - 1].rstrip() + "…"


def _ensure_http_url(u: str) -> str:
    raw = (u or "").strip()
    if not raw:
        return ""
    if raw.startswith(("http://", "https://")):
        return raw
    return "https://" + raw


def _looks_like_feed(xml_text: str) -> bool:
    head = (xml_text or "").lstrip()[:200].lower()
    return head.startswith("<?xml") or "<rss" in head or "<feed" in head


def _parse_feed_entries(xml_text: str) -> list[dict[str, str]]:
    """Парсер RSS/Atom (без внешних зависимостей). Возвращает список {title, url, text}."""
    if not (xml_text or "").strip():
        return []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    def strip_ns(tag: str) -> str:
        return tag.split("}", 1)[-1] if "}" in tag else tag

    entries: list[dict[str, str]] = []
    rtag = strip_ns(root.tag).lower()

    # RSS: <rss><channel><item>...</item></channel></rss>
    if rtag == "rss":
        channel = None
        for ch in root:
            if strip_ns(ch.tag).lower() == "channel":
                channel = ch
                break
        if channel is None:
            return []
        for it in list(channel):
            if strip_ns(it.tag).lower() != "item":
                continue
            title = ""
            link = ""
            desc = ""
            for el in list(it):
                k = strip_ns(el.tag).lower()
                v = (el.text or "").strip()
                if k == "title":
                    title = v
                elif k == "link":
                    link = v
                elif k in ("description", "encoded"):
                    if v and len(v) > len(desc):
                        desc = v
            if title or desc or link:
                entries.append(
                    {
                        "title": _clean_text_excerpt(title, 140),
                        "url": link.strip(),
                        "text": _clean_text_excerpt(desc or title, 1200),
                    }
                )
        return entries

    # Atom: <feed><entry>...</entry></feed>
    if rtag == "feed":
        for e in root.findall(".//"):
            if strip_ns(e.tag).lower() != "entry":
                continue
            title = ""
            link = ""
            summary = ""
            content = ""
            for el in list(e):
                k = strip_ns(el.tag).lower()
                if k == "title":
                    title = (el.text or "").strip()
                elif k == "link":
                    href = (el.attrib or {}).get("href", "").strip()
                    rel = (el.attrib or {}).get("rel", "").strip().lower()
                    if href and (not rel or rel == "alternate") and not link:
                        link = href
                elif k == "summary":
                    summary = (el.text or "").strip()
                elif k == "content":
                    content = (el.text or "").strip()
            txt = content or summary or title
            if title or txt or link:
                entries.append(
                    {
                        "title": _clean_text_excerpt(title, 140),
                        "url": link.strip(),
                        "text": _clean_text_excerpt(txt, 1200),
                    }
                )
        return entries

    return []


def _discover_feed_candidates(blog_url: str) -> list[str]:
    u = _ensure_http_url(blog_url)
    if not u:
        return []
    parsed = urlparse(u)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/")
    return [
        u,  # иногда сам URL уже RSS/Atom
        base + "/feed",
        base + "/feed/",
        base + "/rss",
        base + "/rss/",
        base + "/rss.xml",
        base + "/atom.xml",
        base + "/feed.xml",
        base + "/index.xml",
        base + "/?feed=rss2",
        base + "/?feed=atom",
    ]


def _telegram_channel_from_url(url0: str) -> str | None:
    """Из t.me URL пытается вытащить username канала."""
    try:
        p = urlparse(url0)
    except Exception:
        return None
    host = (p.netloc or "").lower()
    if host not in ("t.me", "telegram.me", "www.t.me", "www.telegram.me"):
        return None
    path = (p.path or "").strip("/")
    if not path:
        return None
    parts = [x for x in path.split("/") if x]
    if not parts:
        return None
    # варианты: /channel, /s/channel, /channel/123
    if parts[0] == "s" and len(parts) >= 2:
        cand = parts[1]
    else:
        cand = parts[0]
    cand = cand.lstrip("@")
    if not cand:
        return None
    if not all(ch.isalnum() or ch == "_" for ch in cand):
        return None
    return cand


def _telegram_rsshub_candidates(url0: str) -> list[str]:
    """RSSHub для Telegram каналов. Требует доступный RSSHub и публичный канал."""
    ch = _telegram_channel_from_url(url0)
    if not ch:
        return []
    base = (os.environ.get("RSSHUB_BASE_URL") or "https://rsshub.app").rstrip("/")
    return [
        f"{base}/telegram/channel/{ch}",
        f"{base}/telegram/channel/{ch}/rss",
    ]


def _telegram_html_candidates(url0: str) -> list[str]:
    """Кандидаты Telegram Web pages (t.me/s/...) для парсинга HTML."""
    ch = _telegram_channel_from_url(url0)
    if not ch:
        return []
    return [
        f"https://t.me/s/{ch}",
        f"https://t.me/{ch}",
    ]


def _fetch_telegram_posts_from_html(session, url0: str, limit: int) -> list[dict[str, str]]:
    """Парсит публичную web-страницу Telegram канала и вытаскивает несколько последних постов."""
    try:
        from bs4 import BeautifulSoup  # type: ignore
    except Exception:
        return []

    for page_url in _telegram_html_candidates(url0):
        try:
            r = session.get(page_url, timeout=12)
        except Exception:
            continue
        if r.status_code >= 400:
            continue
        soup = BeautifulSoup(r.text or "", "html.parser")
        # Telegram web показывает сообщения в .tgme_widget_message_wrap / .tgme_widget_message
        blocks = soup.select(".tgme_widget_message_wrap")
        if not blocks:
            blocks = soup.select(".tgme_widget_message")
        items: list[dict[str, str]] = []
        for b in blocks:
            txt_node = b.select_one(".tgme_widget_message_text")
            if not txt_node:
                continue
            txt = txt_node.get_text(" ", strip=True)
            txt = _clean_text_excerpt(txt, 1400)
            if not txt:
                continue
            link = ""
            a = b.select_one("a.tgme_widget_message_date")
            if a and a.get("href"):
                link = str(a.get("href"))
            items.append({"title": "", "url": link, "text": txt})
            if len(items) >= limit:
                break
        if items:
            return items[:limit]
    return []


def fetch_latest_posts_from_blog(blog_url: str, limit: int = 3) -> list[dict[str, str]]:
    """Best-effort: RSS/Atom → HTML fallback. Returns newest-first list."""
    import requests

    url0 = _ensure_http_url(blog_url)
    if not url0:
        return []

    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": "proekt-hayp/1.0 (+auto-fetch posts; contact: admin@proekt-hayp.local)",
            "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, text/html;q=0.9, */*;q=0.8",
        }
    )

    # 0) Telegram: сначала пытаемся вытащить посты прямо со страницы t.me/s/<канал>.
    if _telegram_channel_from_url(url0):
        items = _fetch_telegram_posts_from_html(session, url0, limit)
        if items:
            return items[:limit]

    # 0) Telegram: t.me обычно не отдаёт RSS/Atom, поэтому используем RSSHub (если доступен).
    for cand in _telegram_rsshub_candidates(url0):
        try:
            r = session.get(cand, timeout=10)
        except requests.RequestException:
            continue
        if r.status_code >= 400:
            continue
        txt = (r.text or "").strip()
        if not txt:
            continue
        entries = _parse_feed_entries(txt)
        if entries:
            out: list[dict[str, str]] = []
            for e in entries:
                link = (e.get("url") or "").strip()
                if link and not link.startswith(("http://", "https://")):
                    link = urljoin(cand, link)
                out.append({"title": e.get("title", ""), "url": link, "text": e.get("text", "")})
            return out[:limit]

    # 1) RSS/Atom candidates
    for cand in _discover_feed_candidates(url0):
        try:
            r = session.get(cand, timeout=8)
        except requests.RequestException:
            continue
        if r.status_code >= 400:
            continue
        txt = (r.text or "").strip()
        if not txt:
            continue
        ctype = (r.headers.get("content-type") or "").lower()
        if "xml" in ctype or _looks_like_feed(txt):
            entries = _parse_feed_entries(txt)
            if entries:
                out: list[dict[str, str]] = []
                for e in entries:
                    link = (e.get("url") or "").strip()
                    if link and not link.startswith(("http://", "https://")):
                        link = urljoin(cand, link)
                    out.append({"title": e.get("title", ""), "url": link, "text": e.get("text", "")})
                return out[:limit]

    # 2) HTML fallback: parse <article> blocks (requires bs4)
    try:
        from bs4 import BeautifulSoup  # type: ignore
    except Exception:
        return []

    try:
        r = session.get(url0, timeout=10)
        r.raise_for_status()
    except requests.RequestException:
        return []

    soup = BeautifulSoup(r.text or "", "html.parser")
    articles = soup.find_all("article")
    items: list[dict[str, str]] = []

    for a in articles:
        title = ""
        h = a.find(["h1", "h2", "h3"])
        if h:
            title = h.get_text(" ", strip=True)

        link = ""
        al = a.find("a", href=True)
        if al and al.get("href"):
            link = urljoin(url0, al["href"])

        ps = a.find_all("p")
        txt = " ".join([p.get_text(" ", strip=True) for p in ps]) if ps else a.get_text(" ", strip=True)
        txt = _clean_text_excerpt(txt, 1200)
        title = _clean_text_excerpt(title, 140)

        if txt:
            combined = f"{title}\n\n{txt}" if title and not txt.lower().startswith(title.lower()) else txt
            items.append({"title": title, "url": link, "text": combined})

        if len(items) >= limit:
            break

    return items[:limit]


def generate_post_text(prompt: str) -> str:
    """Готовый текст поста: польза, условия/ожидания и шаг — в содержании, не в виде мета-списка."""
    p = " ".join((prompt or "").split())
    if not p:
        return ""
    hashtags = ["#реклама", "#партнерство", "#блогер", "#контент"]
    lead = p[0].upper() + p[1:] if len(p) > 1 else p.upper()
    hook = f"Сохраните, если вам актуально: {lead}"

    benefit = (
        f"В чём польза: разберём {p.lower()} так, чтобы подписчикам было понятно «зачем мне это» "
        f"и как это улучшит их повседневность — без давления и без лишних обещаний. "
        f"Я показываю сценарий использования и отвечаю на типичные сомнения, чтобы решение выглядело живым и проверяемым."
    )
    terms = (
        f"Условия и ожидания: заранее фиксируем формат (сторис/пост/обзор), сроки, обязательные формулировки и маркировку "
        f"({hashtags[0]}). Ориентир по срокам — как договоримся; правки — в разумных пределах согласно брифу. "
        f"Если что-то невозможно честно показать — скажу прямо, чтобы не подводить ни аудиторию, ни бренд."
    )
    cta = (
        f"Следующий шаг: напишите в комментариях одно слово «ХОЧУ» или в директ — «интеграция», "
        f"и я пришлю короткий план контента и варианты заголовков под ваш запрос: «{lead}»."
    )
    closing = (
        "Вопрос к вам: что для вас важнее в такой интеграции — скорость, детальность или эмоция? Ответьте одним словом.\n\n"
        f"{' '.join(hashtags)}"
    )
    return "\n\n".join([hook, benefit, terms, cta, closing])


def _pick_font_path() -> str | None:
    candidates = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "C:/Windows/Fonts/segoeuib.ttf",
        "C:/Windows/Fonts/segoeui.ttf",
        "C:/Windows/Fonts/arial.ttf",
    ]
    for p in candidates:
        if os.path.exists(p):
            return p
    return None


def _theme_from_prompt(prompt: str) -> tuple[str, tuple[int, int, int], tuple[int, int, int]]:
    """Сцена + два цвета для вертикального градиента (верх → низ)."""
    low = (prompt or "").lower()
    if any(k in low for k in ("спорт", "фитнес", "трен", "зал", "марафон")):
        return "fitness", (18, 32, 64), (255, 94, 58)
    if any(k in low for k in ("еда", "рецепт", "кафе", "рестор", "кухн", "продукт", "меню")):
        return "food", (60, 24, 8), (255, 186, 72)
    if any(k in low for k in ("прилож", "it", "сайт", "техн", "гаджет", "софт", "код")):
        return "tech", (8, 18, 48), (0, 180, 220)
    if any(k in low for k in ("красот", "космет", "уход", "макияж", "салон")):
        return "beauty", (48, 12, 40), (255, 120, 160)
    if any(k in low for k in ("путешеств", "тур", "отель", "авиа", "город")):
        return "travel", (12, 40, 72), (255, 210, 120)
    if any(k in low for k in ("курс", "обучен", "урок", "школ", "лекци")):
        return "edu", (20, 36, 70), (120, 200, 255)
    return "default", (14, 10, 36), (90, 40, 140)


def _gradient_vertical(img, top: tuple[int, int, int], bottom: tuple[int, int, int]) -> None:
    from PIL import ImageDraw

    W, H = img.size
    draw = ImageDraw.Draw(img)
    for y in range(H):
        t = y / max(H - 1, 1)
        r = int(top[0] + (bottom[0] - top[0]) * t)
        g = int(top[1] + (bottom[1] - top[1]) * t)
        b = int(top[2] + (bottom[2] - top[2]) * t)
        draw.line([(0, y), (W, y)], fill=(r, g, b))


def _draw_cover_motif(d, scene: str, W: int, H: int) -> None:
    """Тематические фигуры: акцент на образе, не на наборе строк."""
    cx, cy = W // 2, H // 2 + 10

    def star(x: int, y: int, r: int, fill):
        pts = [
            (x, y - r),
            (x + r // 3, y - r // 4),
            (x + r, y),
            (x + r // 3, y + r // 4),
            (x, y + r),
            (x - r // 3, y + r // 4),
            (x - r, y),
            (x - r // 3, y - r // 4),
        ]
        d.polygon(pts, fill=fill)

    if scene == "fitness":
        d.rounded_rectangle([cx - 140, cy - 28, cx - 48, cy + 28], radius=12, fill=(255, 255, 255, 38))
        d.rounded_rectangle([cx + 48, cy - 28, cx + 140, cy + 28], radius=12, fill=(255, 255, 255, 38))
        d.rounded_rectangle([cx - 48, cy - 14, cx + 48, cy + 14], radius=6, fill=(255, 255, 255, 55))
        for i, ox in enumerate(range(-200, 220, 55)):
            star(cx + ox, cy - 120 - (i % 3) * 15, 12 + (i % 4), (255, 220, 180))
    elif scene == "food":
        d.ellipse([cx - 90, cy - 40, cx + 90, cy + 50], outline=(255, 230, 200), width=8)
        d.arc([cx - 70, cy - 80, cx + 70, cy + 20], start=200, end=340, fill=(255, 200, 140), width=10)
        d.ellipse([cx - 22, cy - 8, cx + 22, cy + 28], fill=(255, 140, 90))
    elif scene == "tech":
        d.rounded_rectangle([cx - 100, cy - 130, cx + 100, cy + 110], radius=28, outline=(180, 240, 255), width=10)
        d.rounded_rectangle([cx - 85, cy - 115, cx + 85, cy + 70], radius=8, fill=(20, 60, 90))
        d.ellipse([cx - 8, cy + 88, cx + 8, cy + 102], fill=(180, 240, 255))
        for i in range(5):
            d.line([(cx - 70 + i * 35, cy - 95), (cx - 50 + i * 35, cy - 40)], fill=(0, 220, 200), width=4)
    elif scene == "beauty":
        for ang in range(0, 360, 45):
            rad = math.radians(ang)
            x1 = cx + int(100 * math.cos(rad))
            y1 = cy + int(100 * math.sin(rad))
            d.line([(cx, cy), (x1, y1)], fill=(255, 180, 210), width=6)
        d.ellipse([cx - 40, cy - 40, cx + 40, cy + 40], fill=(255, 120, 160))
    elif scene == "travel":
        d.polygon([(cx - 160, cy + 80), (cx, cy - 120), (cx + 160, cy + 80)], fill=(40, 90, 140))
        d.circle((cx - 220, cy - 40), 48, fill=(255, 220, 140))
        d.polygon([(cx + 200, cy + 40), (cx + 260, cy + 40), (cx + 230, cy + 10)], fill=(200, 220, 255))
    elif scene == "edu":
        d.rounded_rectangle([cx - 70, cy - 100, cx + 70, cy + 100], radius=8, fill=(255, 255, 255, 25))
        for i in range(4):
            d.line([(cx - 55, cy - 70 + i * 35), (cx + 55, cy - 70 + i * 35)], fill=(200, 230, 255), width=4)
        d.polygon([(cx - 30, cy - 130), (cx + 30, cy - 130), (cx, cy - 70)], fill=(255, 210, 120))
    else:
        # мотивация «к действию»: ракета / рост
        d.polygon([(cx - 40, cy + 60), (cx + 40, cy + 60), (cx + 10, cy - 100), (cx - 10, cy - 100)], fill=(255, 200, 120))
        d.polygon([(cx - 12, cy + 20), (cx + 12, cy + 20), (cx, cy + 90)], fill=(255, 120, 90))
        for i in range(8):
            y0 = cy + 100 + i * 18
            d.line([(cx - 30 - i * 5, y0), (cx + 30 + i * 5, y0)], fill=(255, 180, 100), width=3)
        star(cx, cy - 140, 28, (255, 255, 200))

    # лёгкие блики (общие)
    for x, y, r in [(80, 100, 3), (W - 120, 80, 4), (W - 90, H - 140, 3), (100, H - 100, 2)]:
        d.ellipse([x - r, y - r, x + r, y + r], fill=(255, 255, 255, 60))


def generate_cover_png(prompt: str) -> bytes:
    from PIL import Image, ImageDraw, ImageFont

    W, H = 1200, 675
    scene, c_top, c_bot = _theme_from_prompt(prompt)
    img = Image.new("RGBA", (W, H), (0, 0, 0, 255))
    rgb = Image.new("RGB", (W, H))
    _gradient_vertical(rgb, c_top, c_bot)
    img.paste(rgb)

    overlay = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    od = ImageDraw.Draw(overlay)
    _draw_cover_motif(od, scene, W, H)
    img = Image.alpha_composite(img, overlay)
    d = ImageDraw.Draw(img)

    font_path = _pick_font_path()
    if font_path:
        brand_font = ImageFont.truetype(font_path, 30)
        cta_font = ImageFont.truetype(font_path, 36)
    else:
        brand_font = ImageFont.load_default()
        cta_font = ImageFont.load_default()

    d.rounded_rectangle([36, 36, W - 36, H - 36], radius=28, outline=(255, 255, 255, 55), width=4)
    d.text((56, 48), "Проект Хайп", fill=(255, 255, 255, 230), font=brand_font)

    ctas = {
        "fitness": "Сильнее с каждым шагом",
        "food": "Попробуйте новый вкус",
        "tech": "Упростите себе задачу",
        "beauty": "Выберите заботу о себе",
        "travel": "Откройте новый маршрут",
        "edu": "Начните с ясного плана",
        "default": "Ваш следующий шаг — сейчас",
    }
    line = ctas[scene]
    bbox = d.textbbox((0, 0), line, font=cta_font)
    tw = bbox[2] - bbox[0]
    d.text(((W - tw) // 2, H - 95), line, fill=(255, 255, 255, 245), font=cta_font)

    import io

    buf = io.BytesIO()
    out = img.convert("RGB")
    out.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


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


def llm_pollinations_text(prompt: str, *, max_prompt_chars: int = 2800) -> str | None:
    """Бесплатная генерация текста через Pollinations (без API-ключа): GET text.pollinations.ai/{prompt}."""
    import requests

    p = " ".join((prompt or "").split())
    if not p:
        return None
    if len(p) > max_prompt_chars:
        p = p[: max_prompt_chars - 1].rstrip() + "…"
    try:
        url = "https://text.pollinations.ai/" + quote(p, safe="")
        r = requests.get(url, timeout=55, headers={"Accept": "text/plain, text/*;q=0.9, */*;q=0.8"})
    except Exception:
        return None
    if r.status_code >= 400:
        return None
    out = (r.text or "").strip()
    return out or None


def llm_chat_openai(system: str, user_msg: str) -> str | None:
    api_key = (os.environ.get("OPENAI_API_KEY") or "").strip()
    if not api_key:
        return None
    try:
        import requests

        model = (os.environ.get("OPENAI_MODEL") or "gpt-4o-mini").strip()
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user_msg},
            ],
            "temperature": 0.4,
        }
        r = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json=payload,
            timeout=25,
        )
        if r.status_code >= 400:
            return None
        data = r.json()
        msg = (((data.get("choices") or [{}])[0]).get("message") or {}).get("content") or ""
        msg = msg.strip()
        return msg or None
    except Exception:
        return None


def llm_assistant_reply(system: str, user_msg: str, *, user_role: str | None) -> str | None:
    """Сначала OpenAI (если есть ключ), иначе бесплатный Pollinations."""
    u = llm_chat_openai(system, f"Роль пользователя: {user_role or 'unknown'}\n\nВопрос:\n{user_msg}")
    if u:
        return u
    combined = (
        f"{system}\n\n"
        f"Роль пользователя: {user_role or 'не указана'}.\n"
        f"Вопрос пользователя:\n{user_msg}\n\n"
        f"Ответь по-русски кратко (до 12 предложений), без воды."
    )
    return llm_pollinations_text(combined)


def _heuristic_audience_analysis(text_in: str) -> str:
    """Заглушка без LLM: грубая оценка тональности и темы по ключевым словам."""
    t = (text_in or "").lower()
    pos = (
        "спасибо",
        "класс",
        "супер",
        "круто",
        "огонь",
        "отлично",
        "рад",
        "люблю",
        "👍",
        "❤",
        "🔥",
        "хорошо",
        "соглас",
        "умница",
        "топ",
    )
    neg = (
        "ужас",
        "плохо",
        "ненавижу",
        "скам",
        "развод",
        "минус",
        "👎",
        "возмут",
        "отврат",
        "гадост",
        "достал",
        "хватит",
        "неправда",
    )
    pc = sum(1 for w in pos if w in t)
    nc = sum(1 for w in neg if w in t)
    if pc > nc and pc >= 1:
        tone = "позитивное"
    elif nc > pc and nc >= 1:
        tone = "негативное"
    elif pc == 0 and nc == 0:
        tone = "нейтральное или неоднозначное"
    else:
        tone = "смешанное"
    snippet = " ".join((text_in or "").split())[:320]
    if len((text_in or "")) > 320:
        snippet += "…"
    return (
        f"Основная тема реакций (по ключевым словам, грубо): обсуждение вокруг: «{snippet}».\n"
        f"Тональность (эвристика): {tone}.\n"
        f"Для точного разбора добавьте больше комментариев или используйте анализ с подключением к сети."
    )


def _telegram_preview_url(url: str) -> str:
    """Публичное превью Telegram с разметкой tgme — у страниц вида /s/…"""
    u = _ensure_http_url(url)
    try:
        p = urlparse(u)
    except Exception:
        return url
    host = (p.netloc or "").lower()
    if host.startswith("www."):
        host = host[4:]
    if host not in ("t.me", "telegram.me"):
        return u
    parts = [x for x in (p.path or "").strip("/").split("/") if x]
    if not parts:
        return u
    if parts[0] == "s":
        return f"https://t.me/{'/'.join(parts)}"
    # t.me/username/123 — без /s/ Telegram отдаёт «лёгкую» страницу без виджетов
    if len(parts) >= 2 and re.match(r"^\d+$", parts[1]):
        return f"https://t.me/s/{parts[0]}/{parts[1]}"
    return u


def _telegram_engagement_from_page(session, url: str) -> str:
    """Со страницы t.me извлекает просмотры, реакции и дату (комментарии в HTML обычно недоступны)."""
    try:
        from bs4 import BeautifulSoup  # type: ignore
    except Exception:
        return "BeautifulSoup недоступен."
    candidates: list[str] = []
    pu = _telegram_preview_url(url)
    candidates.append(pu)
    canon = _ensure_http_url(url).rstrip("/")
    if pu.rstrip("/") != canon:
        candidates.append(canon)
    last_exc: Exception | None = None
    w = None
    for fetch_url in candidates:
        try:
            r = session.get(fetch_url, timeout=14)
            r.raise_for_status()
            soup = BeautifulSoup(r.text, "html.parser")
            w = soup.select_one(".tgme_widget_message_wrap") or soup.select_one(".tgme_widget_message")
            if w:
                break
        except Exception as exc:
            last_exc = exc
            continue
    if not w:
        return (
            "Не удалось найти блок поста в HTML (пост удалён, приватный или недоступная ссылка). "
            f"{'Ошибка: ' + str(last_exc) if last_exc else ''}"
        )
    views_el = w.select_one(".tgme_widget_message_views")
    views = views_el.get_text(strip=True) if views_el else "—"
    reactions = [x.get_text(strip=True) for x in w.select("span.tgme_reaction")]
    rx = ", ".join(reactions) if reactions else "реакции не найдены в HTML"
    dt_el = w.select_one("time")
    when = (dt_el.get("datetime") or dt_el.get_text(strip=True) or "—") if dt_el else "—"
    return (
        f"Дата поста: {when}. Просмотры: {views}. Реакции (эмодзи+число): {rx}. "
        f"Примечание: в открытом HTML Telegram редко доступны комментарии; ориентируйся на реакции и просмотры."
    )


def _generic_comments_from_page(session, url: str) -> str:
    try:
        from bs4 import BeautifulSoup  # type: ignore
    except Exception:
        return "BeautifulSoup недоступен."
    try:
        r = session.get(url, timeout=14)
        r.raise_for_status()
    except Exception as exc:
        return f"Ошибка загрузки: {exc}"
    soup = BeautifulSoup(r.text, "html.parser")
    texts: list[str] = []
    for sel in (
        "article.comment",
        ".comment-content",
        ".comment-body",
        "li.comment",
        ".wp-block-comment-content",
        ".comments-area .comment",
    ):
        for node in soup.select(sel):
            t = node.get_text(" ", strip=True)
            if 12 < len(t) < 1500:
                texts.append(t)
        if len(texts) >= 12:
            break
    if texts:
        uniq = []
        seen = set()
        for t in texts:
            key = t[:80]
            if key in seen:
                continue
            seen.add(key)
            uniq.append(t)
        lines = [f"- {x[:500]}" for x in uniq[:30]]
        return "Найденные комментарии (фрагменты):\n" + "\n".join(lines)
    return "Комментарии на странице не найдены (другая вёрстка или подгрузка через JavaScript)."


def build_audience_raw_from_posts(posts: list) -> str:
    """По ссылкам 3 постов подтягивает реакции/просмотры (Telegram) или комментарии (блог)."""
    import requests

    if not posts:
        return ""
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": "proekt-hayp/1.0 (+audience; blogger analytics)",
            "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
        }
    )
    blocks: list[str] = []
    for i, p in enumerate(posts, 1):
        u = (getattr(p, "url", None) or "").strip()
        frag = _clean_text_excerpt(getattr(p, "text", None) or "", 500)
        if not u:
            blocks.append(f"Пост {i} (ссылка не указана — подтяните посты из блога или добавьте URL вручную).\nФрагмент текста: {frag}")
            continue
        try:
            parsed = urlparse(u)
        except Exception:
            blocks.append(f"Пост {i}: некорректная ссылка {u}")
            continue
        host = (parsed.netloc or "").lower().removeprefix("www.")
        if host in ("t.me", "telegram.me"):
            eng = _telegram_engagement_from_page(session, u)
            blocks.append(f"Пост {i}: {u}\n{eng}\nФрагмент текста поста: {frag}")
        else:
            cm = _generic_comments_from_page(session, u)
            blocks.append(f"Пост {i}: {u}\n{cm}\nФрагмент текста поста: {frag}")
    return "\n\n".join(blocks).strip()


def analyze_audience_feedback(comments: str) -> str:
    """Тема реакций + позитив/негатив; сначала LLM (Pollinations), иначе эвристика."""
    raw = " ".join((comments or "").split())
    if not raw:
        return ""
    prompt = (
        "Ты аналитик соцсетей. Ниже — данные по аудитории для 1–3 постов блогера: "
        "комментарии (если удалось извлечь с сайта) и/или просмотры и эмодзи-реакции Telegram.\n"
        "Если комментариев нет, делай выводы по реакциям и просмотрам + по фрагментам текста постов.\n"
        "Ответ структурируй по-русски:\n"
        "1) Основная тема реакций / интереса аудитории (1–3 предложения).\n"
        "2) Тональность: позитивно / негативно / смешанно / нейтрально — одно слово и краткое объяснение.\n"
        "3) Рекомендация блогеру (2–4 предложения).\n\n"
        "Данные:\n"
        f"{raw[:4000]}"
    )
    llm = llm_pollinations_text(prompt, max_prompt_chars=3000)
    if llm:
        return llm
    return _heuristic_audience_analysis(raw)


def _assistant_knowledge_base() -> list[tuple[list[str], str]]:
    """Простая база знаний для ответа без внешних AI API."""
    return [
        (
            ["концепц", "идея", "зачем", "мисси", "бизнес"],
            "Концепция «блогер как бизнес»: мы собираем в одном месте заказы от брендов, профиль/портфолио, аналитику и сервисы.\n"
            "Дальше планируется школа блогеров и продвинутая аналитика, чтобы блогер мог расти системно (контент → метрики → монетизация).",
        ),
        (
            ["как", "заказ", "блогер", "взять", "предложен"],
            "Блогеру: откройте «Заказы», выберите подходящий и нажмите «Взять в работу». Предложения от брендов — во вкладке «Предложения».",
        ),
        (
            ["бренд", "реклам", "блогер", "найти"],
            "Бренду: создайте заказ («Создать заказ»), затем в разделе «Блогеры» можно искать и отправлять предложения по конкретному заказу.",
        ),
        (
            ["балл", "вывод", "счёт", "деньги"],
            "Баллы начисляются за выполненные заказы. Вывод на банковский счёт сейчас в проработке (кнопка есть как заглушка).",
        ),
        (
            ["телеграм", "telegram", "t.me", "пост", "подтянуть"],
            "Telegram не отдаёт RSS напрямую. Мы подтягиваем посты через RSSHub.\n"
            "Если у вас `blog_url` вида `t.me/<канал>`, убедитесь, что канал публичный, а RSSHub доступен. "
            "При необходимости задайте переменную `RSSHUB_BASE_URL` (например, на свой инстанс RSSHub).",
        ),
        (
            ["генератор", "обложк", "пост", "картинк"],
            "В «Генераторе» вы вводите задачу/идею — система выдаёт готовый текст (с пользой, условиями и следующим шагом) и тематическую обложку PNG.",
        ),
    ]


def assistant_answer(question: str, *, user_role: str | None) -> str:
    q = " ".join((question or "").split())
    if not q:
        return "Сформулируйте вопрос — и я подскажу."

    system = (
        "Ты помощник веб-сервиса «Проект Хайп».\n"
        "Задача: помогать пользователю разобраться в функциях сайта и в концепции "
        "«блогер как бизнес»: сервис и аналитика в одном месте. Отвечай по-русски, кратко и по делу.\n"
        "Если спрашивают про будущие функции (школа блогеров, продвинутая аналитика) — говори, что это в планах."
    )
    llm = llm_assistant_reply(system, q, user_role=user_role)
    if llm:
        return llm

    # Fallback: встроенная база знаний
    low = q.lower()
    for keys, answer in _assistant_knowledge_base():
        if any(k in low for k in keys):
            return answer

    return (
        "Я могу подсказать по функциям сайта: заказы, предложения, профиль, генератор, анализ постов.\n"
        "Уточните, что именно хотите сделать, и вашу роль (блогер/бренд)."
    )


@app.route("/assistant", methods=["GET", "POST"])
@require_login
def assistant_chat():
    chat = session.get("assistant_chat") or []
    if not isinstance(chat, list):
        chat = []

    if request.method == "POST":
        if request.form.get("reset") == "1":
            session["assistant_chat"] = []
            flash("Чат очищен.", "info")
            return redirect(url_for("assistant_chat"))

        msg = (request.form.get("message") or "").strip()
        if msg:
            chat.append({"role": "user", "content": msg})
            user = current_user()
            ans = assistant_answer(msg, user_role=getattr(user, "role", None) if user else None)
            chat.append({"role": "assistant", "content": ans})
            # ограничим историю
            session["assistant_chat"] = chat[-20:]
        return redirect(url_for("assistant_chat"))

    return render_template("assistant.html", chat=session.get("assistant_chat") or [])


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/how-it-works")
def how_it_works():
    return render_template("how_it_works.html")


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
        full_name = (request.form.get("full_name") or "").strip() or None
        phone = (request.form.get("phone") or "").strip() or None
        telegram = (request.form.get("telegram") or "").strip() or None
        raw_blog = (request.form.get("blog_url") or "").strip()
        blog_url = (_ensure_http_url(raw_blog)[:600] if raw_blog else None) or None
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        password2 = request.form.get("password2") or ""
        if not email or "@" not in email:
            flash("Укажите корректный email.", "danger")
            return render_template("register_blogger.html")
        if not full_name:
            flash("Укажите ФИО.", "danger")
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
            points=STARTING_POINTS,
            full_name=full_name,
            phone=phone,
            telegram=telegram,
            blog_url=blog_url,
        )
        db.add(u)
        db.commit()
        db.refresh(u)
        login_user(u)
        flash("Регистрация выполнена. Добро пожаловать!", "success")
        return redirect(url_for("blogger_profile"))
    return render_template("register_blogger.html")


@app.route("/register/advertiser", methods=["GET", "POST"])
def register_advertiser():
    # единая регистрация (без разделения на роли)
    return redirect(url_for("register_blogger"))


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
        .limit(40)
        .all()
    )

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
        new_users=new_users,
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
    user = current_user()
    q = (request.args.get("q") or "").strip()
    query = db.query(Order).filter(Order.status == OrderStatus.OPEN, Order.advertiser_id != user.id)
    if q:
        like = f"%{q.lower()}%"
        query = query.filter(
            or_(
                func.lower(Order.title).like(like),
                func.lower(Order.description).like(like),
            )
        )
    orders_open = query.order_by(Order.created_at.desc()).all()
    my_active = (
        db.query(Order)
        .filter(Order.blogger_id == user.id, Order.status == OrderStatus.ASSIGNED)
        .order_by(Order.created_at.desc())
        .all()
    )
    return render_template("blogger_orders.html", orders_open=orders_open, my_active=my_active, q=q)


@app.route("/orders/<int:order_id>")
@require_login
def order_detail(order_id: int):
    db = get_db()
    user = current_user()
    order = db.get(Order, order_id)
    if not order:
        flash("Заказ не найден.", "danger")
        return redirect(url_for("index"))
    my_active = []
    if user and getattr(user, "role", None) == UserRole.BLOGGER:
        my_active = (
            db.query(Order)
            .filter(Order.blogger_id == user.id, Order.status == OrderStatus.ASSIGNED)
            .order_by(Order.created_at.desc())
            .limit(1)
            .all()
        )
    return render_template("order_detail.html", order=order, my_active=my_active)


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


@app.route("/blogger/posts/fetch", methods=["POST"])
@require_role(UserRole.BLOGGER)
def blogger_fetch_posts():
    db = get_db()
    user = current_user()
    blog_url = (user.blog_url or "").strip()
    if not blog_url:
        flash("Сначала укажите ссылку на блог в профиле.", "warning")
        return redirect(url_for("blogger_profile"))

    posts = fetch_latest_posts_from_blog(blog_url, limit=3)
    if not posts:
        flash(
            "Не удалось автоматически найти последние посты по этой ссылке. "
            "Проверьте URL (лучше RSS/Atom) или используйте ручной ввод ниже.",
            "warning",
        )
        return redirect(url_for("blogger_profile"))

    db.query(BloggerPost).filter(BloggerPost.blogger_id == user.id).delete()
    for p in posts:
        txt = (p.get("text") or "").strip()
        urlv = (p.get("url") or "").strip() or None
        if txt:
            db.add(BloggerPost(blogger_id=user.id, url=urlv, text=txt))
    db.commit()
    flash("Посты подтянуты из блога.", "success")
    return redirect(url_for("blogger_profile"))


@app.route("/blogger/legal/self-employed", methods=["POST"])
@require_role(UserRole.BLOGGER)
def blogger_self_employed():
    flash("Функция оформления самозанятости в проработке.", "info")
    return redirect(url_for("blogger_profile"))


@app.route("/blogger/legal/ip", methods=["POST"])
@require_role(UserRole.BLOGGER)
def blogger_register_ip():
    flash("Функция оформления ИП в проработке.", "info")
    return redirect(url_for("blogger_profile"))


@app.route("/blogger/payouts/bank", methods=["POST"])
@require_role(UserRole.BLOGGER)
def blogger_payout_to_bank():
    flash("Вывод баллов на банковский счёт в проработке.", "info")
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
    if not posts:
        flash("Нет сохранённых постов. Сначала подтяните из блога или введите тексты постов.", "warning")
        return redirect(url_for("blogger_profile"))
    joined = "\n\n".join([p.text for p in posts])
    summary = summarize_text(joined)
    flags = unethical_flags(joined)
    audience_raw = build_audience_raw_from_posts(posts)
    audience_insights = analyze_audience_feedback(audience_raw) if audience_raw.strip() else None
    db.add(
        BloggerPostAnalysis(
            blogger_id=user.id,
            summary=summary,
            flags=",".join(flags),
            audience_text=audience_raw or None,
            audience_insights=audience_insights,
        )
    )
    db.commit()
    if flags:
        flash("Найдены потенциально неэтичные темы/слова: " + ", ".join(flags), "warning")
    else:
        flash("Проверка пройдена: явных неэтичных слов/тем не найдено.", "success")
    flash("Аудитория: собраны просмотры/реакции (Telegram) или комментарии (сайт) по ссылкам постов.", "info")
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
    if order.advertiser_id == user.id:
        flash("Нельзя взять в работу собственный заказ.", "danger")
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
    notes = (request.form.get("result_notes") or "").strip() or None
    order.status = OrderStatus.COMPLETED
    order.completed_at = datetime.utcnow()
    order.result_notes = notes
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
@require_login
def advertiser_orders():
    db = get_db()
    user = current_user()
    orders_as_advertiser = (
        db.query(Order)
        .filter(Order.advertiser_id == user.id)
        .order_by(Order.created_at.desc())
        .all()
    )
    orders_as_blogger = (
        db.query(Order)
        .filter(Order.blogger_id == user.id)
        .order_by(Order.created_at.desc())
        .all()
    )
    return render_template(
        "advertiser_orders.html",
        orders_as_advertiser=orders_as_advertiser,
        orders_as_blogger=orders_as_blogger,
    )


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
@require_login
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
@require_login
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
    prompt = ""
    generated_text = ""
    img_url = None
    if request.method == "POST":
        prompt = (request.form.get("prompt") or "").strip()
        if prompt:
            generated_text = generate_post_text(prompt)
            img_url = url_for("tools_generate_image") + "?prompt=" + quote(prompt, safe="")
    return render_template(
        "tools_generate.html",
        prompt=prompt,
        generated_text=generated_text,
        img_url=img_url,
    )


@app.route("/tools/generate/image")
@require_login
def tools_generate_image():
    prompt = (request.args.get("prompt") or "").strip()
    if not prompt:
        return Response("prompt required", status=400, mimetype="text/plain")
    png = generate_cover_png(prompt)
    return Response(png, mimetype="image/png")


@app.route("/advertiser/orders/new", methods=["GET", "POST"])
@require_login
def advertiser_new_order():
    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        description = (request.form.get("description") or "").strip()
        try:
            points = int(request.form.get("points_reward") or "0")
        except ValueError:
            points = 0
        if not title or not description:
            flash("Заполните название и описание.", "danger")
            return render_template("advertiser_new_order.html")
        if points < 1:
            flash("Награда в баллах — не менее 1.", "danger")
            return render_template("advertiser_new_order.html")
        db = get_db()
        user = current_user()
        balance = int(user.points or 0)
        if balance < points:
            flash(f"Недостаточно баллов: нужно {points}, на счёте {balance}.", "danger")
            return render_template("advertiser_new_order.html")
        user.points = balance - points
        o = Order(
            advertiser_id=user.id,
            title=title,
            description=description,
            points_reward=points,
            budget_rub=None,
            payout_rub=None,
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
