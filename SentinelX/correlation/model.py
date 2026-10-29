from dataclasses import dataclass
from datetime import datetime

from backend.models.event import SentinelXEvent


@dataclass
class CorrelationEvent:
    event: SentinelXEvent
    detection_rule: str
    timestamp: datetime