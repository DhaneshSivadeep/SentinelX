from typing import Optional

from backend.models.event import SentinelXEvent
from detection.rules.base import DetectionResult, DetectionRule


class FailedLoginRule(DetectionRule):
    name = "failed_login"

    def evaluate(
        self,
        event: SentinelXEvent,
    ) -> Optional[DetectionResult]:
        if event.event_type != "failed_logon":
            return None

        return DetectionResult(
            rule_name=self.name,
            severity="medium",
            description="Failed Windows logon detected",
            event=event,
        )