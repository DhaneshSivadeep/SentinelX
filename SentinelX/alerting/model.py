from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from mitre.mapping import MitreTechnique


@dataclass
class Alert:
    alert_id: str
    title: str
    severity: str
    host: str
    timestamp: datetime
    status: str
    description: str
    rule_name: Optional[str] = None
    event_id: Optional[str] = None
    mitre: Optional[MitreTechnique] = None

    def to_dict(self):
        result = {
            "alert_id": self.alert_id,
            "title": self.title,
            "severity": self.severity,
            "host": self.host,
            "timestamp": self.timestamp.isoformat(),
            "status": self.status,
            "description": self.description,
            "rule_name": self.rule_name,
            "event_id": self.event_id,
        }

        if self.mitre:
            result["mitre"] = {
                "technique_id": self.mitre.technique_id,
                "technique_name": self.mitre.technique_name,
                "tactic": self.mitre.tactic,
            }
        else:
            result["mitre"] = None

        return result