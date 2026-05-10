from datetime import datetime
from pydantic import BaseModel


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


class TelemetryPayload(BaseModel):
    agent_id: str
    timestamp: datetime
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


class AlertOut(BaseModel):
    id: int
    agent_id: str
    pid: int
    process_name: str
    reason: str
    score: float
    timestamp: datetime
