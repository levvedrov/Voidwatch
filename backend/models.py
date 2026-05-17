from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class AgentMetadata(BaseModel):
    hostname: str
    os: str
    ip: str
    username: str


class ProcessData(BaseModel):
    name: str
    parent_name: str
    command_line: str
    path: str
    pid: int
    parent_pid: int
    cpu_usage: float
    mem_usage: float
    is_signed: bool
    sha256: str
    connection_count: int
    destination_ips: list[str]
    destination_ports: list[int]
    protocols: list[str]
    # Extended fields — populated from OTRF events; optional so live agent telemetry still works
    integrity_level: str = ""        # "Low" | "Medium" | "High" | "System"
    parent_command_line: str = ""    # full command line of the parent process
    original_filename: str = ""      # PE OriginalFileName — detects renamed binaries
    token_is_elevated: bool = False  # TokenElevationType == elevated (EventID 4688)
    has_dns_destination: bool = False  # any network event resolved a hostname
    connection_is_outbound: bool = False  # any outbound-initiated connection


class RegisterPayload(BaseModel):
    agent_id: str
    metadata: AgentMetadata


class TelemetryPayload(BaseModel):
    agent_id: str
    timestamp: datetime
    metadata: AgentMetadata | None = None
    processes: list[ProcessData]


class ProcessOut(BaseModel):
    id: int
    agent_id: str
    timestamp: datetime
    name: str
    parent_name: str
    command_line: str
    path: str
    pid: int
    parent_pid: int
    cpu_usage: float
    mem_usage: float
    is_signed: bool
    sha256: str
    connection_count: int
    destination_ips: list[str]
    destination_ports: list[int]
    protocols: list[str]
    ml_score: float = 0.0


class AlertOut(BaseModel):
    id: int
    agent_id: str
    timestamp: datetime
    pid: int
    process_name: str
    parent_name: str
    risk_score: int
    risk_level: str
    confidence: float
    confidence_label: str
    category: str
    reasons: list[str]
    mitre: list[str]
    ml_score: float
    timeline: list[dict]


class RetentionPayload(BaseModel):
    process_retain_days: Optional[int] = None
    alert_retain_days: Optional[int] = None


class AgentOut(BaseModel):
    agent_id: str
    hostname: str
    os: str
    ip: str
    username: str
    first_seen: datetime
    last_seen: datetime
