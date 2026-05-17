import os
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, create_engine, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./voidwatch.db")
_is_sqlite   = DATABASE_URL.startswith("sqlite")

if _is_sqlite:
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False},
    )
    from sqlalchemy import event as _sa_event

    @_sa_event.listens_for(engine, "connect")
    def _set_sqlite_pragmas(dbapi_conn, _record):
        dbapi_conn.execute("PRAGMA journal_mode=WAL")
        dbapi_conn.execute("PRAGMA busy_timeout=5000")
else:
    engine = create_engine(
        DATABASE_URL,
        pool_size=10,
        max_overflow=20,
        pool_pre_ping=True,
        pool_recycle=300,
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


class ProcessRecord(Base):
    __tablename__ = "processes"

    id               = Column(Integer, primary_key=True, index=True)
    agent_id         = Column(String, index=True)
    timestamp        = Column(DateTime, default=_utcnow)
    name             = Column(String)
    parent_name      = Column(String)
    command_line     = Column(String)
    path             = Column(String)
    pid              = Column(Integer)
    parent_pid       = Column(Integer)
    cpu_usage        = Column(Float)
    mem_usage        = Column(Float)
    is_signed        = Column(Boolean)
    sha256           = Column(String)
    connection_count  = Column(Integer)
    destination_ips   = Column(String)  # JSON
    destination_ports = Column(String)  # JSON
    protocols         = Column(String)  # JSON
    ml_score          = Column(Float, default=0.0)


class AlertRecord(Base):
    __tablename__ = "alerts"

    id               = Column(Integer, primary_key=True, index=True)
    agent_id         = Column(String, index=True)
    timestamp        = Column(DateTime, default=_utcnow)
    pid              = Column(Integer)
    process_name     = Column(String)
    parent_name      = Column(String)
    risk_score       = Column(Integer)
    risk_level       = Column(String, index=True)
    confidence       = Column(Float)
    confidence_label = Column(String)
    category         = Column(String, index=True)
    reasons          = Column(String)   # JSON
    mitre            = Column(String)   # JSON
    ml_score         = Column(Float)
    timeline         = Column(String)   # JSON


class AgentRecord(Base):
    __tablename__ = "agents"

    id           = Column(Integer, primary_key=True, index=True)
    agent_id     = Column(String, unique=True, index=True)
    hostname     = Column(String)
    os           = Column(String)
    ip           = Column(String)
    username     = Column(String)
    first_seen   = Column(DateTime, default=_utcnow)
    last_seen    = Column(DateTime, default=_utcnow)
    mode         = Column(String, default="detect")       # collect_only | detect | debug
    agent_secret = Column(String, nullable=True)


class EnrollmentToken(Base):
    __tablename__ = "enrollment_tokens"

    id         = Column(Integer, primary_key=True, index=True)
    token      = Column(String, unique=True, index=True)
    label      = Column(String, default="")
    created_at = Column(DateTime, default=_utcnow)
    expires_at = Column(DateTime, nullable=True)
    used       = Column(Boolean, default=False)
    used_by    = Column(String, nullable=True)


class RevokedAgent(Base):
    __tablename__ = "revoked_agents"

    id         = Column(Integer, primary_key=True, index=True)
    agent_id   = Column(String, unique=True, index=True)
    reason     = Column(String, default="")
    revoked_at = Column(DateTime, default=_utcnow)


class AlertFeedback(Base):
    __tablename__ = "alert_feedback"

    id            = Column(Integer, primary_key=True, index=True)
    alert_id      = Column(Integer, index=True)
    agent_id      = Column(String, index=True)
    process_name  = Column(String)
    feedback_type = Column(String)   # true_positive | false_positive | ignore | suspicious_ok
    reason        = Column(String, default="")
    timestamp     = Column(DateTime, default=_utcnow)


class Allowlist(Base):
    __tablename__ = "allowlist"

    id         = Column(Integer, primary_key=True, index=True)
    kind       = Column(String, index=True)   # process | publisher | path | hash | parent_child
    value      = Column(String)
    note       = Column(String, default="")
    created_at = Column(DateTime, default=_utcnow)


def _migrate(conn):
    """Add columns that exist in the ORM but not yet in the DB (SQLite has no IF NOT EXISTS for columns)."""
    migrations = [
        ("agents",           "mode",         "TEXT DEFAULT 'detect'"),
        ("agents",           "agent_secret",  "TEXT"),
        ("alert_feedback",   "agent_id",      "TEXT"),
        ("alert_feedback",   "process_name",  "TEXT"),
        ("alerts",           "ml_score",      "REAL DEFAULT 0"),
        ("alerts",           "timeline",      "TEXT"),
        ("processes",        "ml_score",      "REAL DEFAULT 0"),
    ]
    existing: dict[str, set[str]] = {}
    for table, col, typedef in migrations:
        if table not in existing:
            rows = conn.execute(text(f"PRAGMA table_info({table})")).fetchall()
            existing[table] = {r[1] for r in rows}
        if col not in existing[table]:
            conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {typedef}"))
            existing[table].add(col)


def init_db():
    Base.metadata.create_all(bind=engine)
    with engine.connect() as conn:
        _migrate(conn)
        conn.commit()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
