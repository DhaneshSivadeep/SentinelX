from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class SentinelXEvent(BaseModel):
    event_id: str = Field(..., description="Unique event identifier")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC time when the event was generated",
    )
    host: str = Field(..., description="Endpoint hostname")
    os: str = Field(..., description="Operating system")
    source: str = Field(..., description="Telemetry source")
    event_type: str = Field(..., description="Normalized event type")
    severity: str = Field(..., description="Event severity")
    data: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional event-specific data",
    )