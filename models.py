from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, scoped_session, sessionmaker


class Base(DeclarativeBase):
    pass


class UserRole:
    ADMIN = "admin"
    BLOGGER = "blogger"
    ADVERTISER = "advertiser"


class OrderStatus:
    OPEN = "open"
    ASSIGNED = "assigned"
    COMPLETED = "completed"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    username: Mapped[str | None] = mapped_column(String(64), unique=True, nullable=True)
    password_hash: Mapped[str] = mapped_column(String(128))
    role: Mapped[str] = mapped_column(String(20), index=True)
    blocked: Mapped[bool] = mapped_column(Boolean, default=False)
    points: Mapped[int] = mapped_column(Integer, default=1000)
    full_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    phone: Mapped[str | None] = mapped_column(String(40), nullable=True)
    telegram: Mapped[str | None] = mapped_column(String(120), nullable=True)
    display_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    blog_url: Mapped[str | None] = mapped_column(String(600), nullable=True)
    bio: Mapped[str | None] = mapped_column(String(800), nullable=True)
    niche_tags: Mapped[str | None] = mapped_column(String(500), nullable=True)  # comma-separated
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_login: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    orders_as_advertiser: Mapped[list["Order"]] = relationship(
        "Order", back_populates="advertiser", foreign_keys="Order.advertiser_id"
    )
    orders_as_blogger: Mapped[list["Order"]] = relationship(
        "Order", back_populates="blogger", foreign_keys="Order.blogger_id"
    )


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    used: Mapped[bool] = mapped_column(Boolean, default=False)


class Order(Base):
    __tablename__ = "orders"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    advertiser_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    blogger_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[Text] = mapped_column(Text)
    points_reward: Mapped[int] = mapped_column(Integer, default=100)
    budget_rub: Mapped[int | None] = mapped_column(Integer, nullable=True)
    payout_rub: Mapped[int | None] = mapped_column(Integer, nullable=True)
    result_notes: Mapped[str | None] = mapped_column(String(1200), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default=OrderStatus.OPEN, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    advertiser: Mapped["User"] = relationship(
        "User", back_populates="orders_as_advertiser", foreign_keys=[advertiser_id]
    )
    blogger: Mapped["User | None"] = relationship(
        "User", back_populates="orders_as_blogger", foreign_keys=[blogger_id]
    )


class OrderOfferStatus:
    PENDING = "pending"
    ACCEPTED = "accepted"
    REJECTED = "rejected"


class OrderOffer(Base):
    __tablename__ = "order_offers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    order_id: Mapped[int] = mapped_column(ForeignKey("orders.id", ondelete="CASCADE"), index=True)
    blogger_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(20), default=OrderOfferStatus.PENDING, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class BloggerPost(Base):
    __tablename__ = "blogger_posts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    blogger_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    url: Mapped[str | None] = mapped_column(String(800), nullable=True)
    text: Mapped[Text] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class BloggerPostAnalysis(Base):
    __tablename__ = "blogger_post_analyses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    blogger_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    summary: Mapped[Text] = mapped_column(Text)
    flags: Mapped[str] = mapped_column(String(800))  # comma-separated
    audience_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    audience_insights: Mapped[str | None] = mapped_column(Text, nullable=True)
    checked_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


def _normalize_postgres_url(url: str) -> str:
    u = url.strip()
    if u.startswith("postgres://"):
        u = "postgresql://" + u[len("postgres://") :]
    if "://" not in u:
        return u
    scheme, rest = u.split("://", 1)
    if "+psycopg" in scheme:
        return u
    if scheme == "postgresql":
        return f"postgresql+psycopg2://{rest}"
    return u


def make_engine(*, database_url: str | None = None, sqlite_path: str | None = None):
    """PostgreSQL (Render, Neon и т.д.) или локальный SQLite."""
    if database_url:
        return create_engine(
            _normalize_postgres_url(database_url),
            echo=False,
            future=True,
            pool_pre_ping=True,
        )
    if sqlite_path:
        return create_engine(
            f"sqlite:///{sqlite_path}",
            echo=False,
            future=True,
            connect_args={"check_same_thread": False},
        )
    raise ValueError("Нужен database_url или sqlite_path")


def make_session_factory(engine):
    return scoped_session(sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True))
