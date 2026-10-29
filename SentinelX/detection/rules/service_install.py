from typing import Optional

from backend.models.event import SentinelXEvent
from detection.rules.base import DetectionResult, DetectionRule


class ServiceInstallRule(DetectionRule):
    name = "service_installation"

    def evaluate(
        self,
        event: SentinelXEvent,
    ) -> Optional[DetectionResult]:
        if event.event_type != "service_installed":
            return None

        return DetectionResult(
            rule_name=self.name,
            severity="high",
            description="Windows service installation detected",
            event=event,
        )