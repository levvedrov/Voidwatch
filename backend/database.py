from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

DATABASE_URL = "sqlite:///./voidwatch.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


class ProcessRecord(Base):
    __tablename__ = "processes"

    id              = Column(Integer, primary_key=True, index=True)
    agent_id        = Column(String, index=True)
    timestamp       = Column(DateTime, default=datetime.utcnow)
    name            = Column(String)
    parent_name     = Column(String)
    command_line    = Column(String)
    path            = Column(String)
    pid             = Column(Integer)
    parent_pid      = Column(Integer)
    cpu_usage       = Column(Float)
    mem_usage       = Column(Float)
    is_signed       = Column(Boolean)
    sha256          = Column(String)
    connection_count = Column(Integer)
    destination_ips   = Column(String)   # JSON array
    destination_ports = Column(String)   # JSON array
    protocols         = Column(String)   # JSON array


class AlertRecord(Base):
    __tablename__ = "alerts"

    id           = Column(Integer, primary_key=True, index=True)
    agent_id     = Column(String, index=True)
    pid          = Column(Integer)
    process_name = Column(String)
    reason       = Column(String)
    score        = Column(Float)
    timestamp    = Column(DateTime, default=datetime.utcnow)


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
