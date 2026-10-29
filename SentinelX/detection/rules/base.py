from typing import Optional

from backend.models.event import SentinelXEvent
from mitre.mapping import MitreTechnique


class DetectionResult:
    def __init__(
        self,
        rule_name: str,
        severity: str,
        description: str,
        event: SentinelXEvent,
        mitre: Optional[MitreTechnique] = None,
    ):
        self.rule_name = rule_name
        self.severity = severity
        self.description = description
        self.event = event
        self.mitre = mitre

    def to_dict(self):
        result = {
            "rule_name": self.rule_name,
            "severity": self.severity,
            "description": self.description,
            "event_id": self.event.event_id,
            "timestamp": self.event.timestamp,
            "host": self.event.host,
            "event_type": self.event.event_type,
        }

        if self.mitre:
            result["mitre"] = {
                "technique_id": self.mitre.technique_id,
                "technique_name": self.mitre.technique_name,
                "tactic": self.mitre.tactic,
                "description": self.mitre.description,
            }

        return result


class DetectionRule:
    name: str = "Unnamed Rule"

    def evaluate(
        self,
        event: SentinelXEvent,
    ) -> Optional[DetectionResult]:
        raise NotImplementedError