from dataclasses import dataclass
from enum import Enum

class PortState(Enum):
    OPEN = 0
    CLOSED = 1
    FILTERED = 2

@dataclass
class ProbeResult:
    protocol: str
    port: int
    state: PortState
    elapsed_ms: float | None
    app_protocol: str | None