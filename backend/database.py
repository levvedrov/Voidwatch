from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

DATABASE_URL = "sqlite:///./voidwatch.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)

from sqlalchemy import event as _sa_event

@_sa_event.listens_for(engine, "connect")
def _set_sqlite_pragmas(dbapi_conn, _record):
    dbapi_conn.execute("PRAGMA journal_mode=WAL")
    dbapi_conn.execute("PRAGMA busy_timeout=5000")
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


class ProcessRecord(Base):
    __tablename__ = "processes"

    id               = Column(Integer, primary_key=True, index=True)
    agent_id         = Column(String, index=True)
    timestamp        = Column(DateTime, default=datetime.utcnow)
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


class AlertRecord(Base):
    __tablename__ = "alerts"

    id               = Column(Integer, primary_key=True, index=True)
    agent_id         = Column(String, index=True)
    timestamp        = Column(DateTime, default=datetime.utcnow)
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

    id         = Column(Integer, primary_key=True, index=True)
    agent_id   = Column(String, unique=True, index=True)
    hostname   = Column(String)
    os         = Column(String)
    ip         = Column(String)
    username   = Column(String)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen  = Column(DateTime, default=datetime.utcnow)


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
