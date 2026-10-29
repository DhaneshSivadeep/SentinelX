from typing import Optional

from backend.models.event import SentinelXEvent
from detection.rules.base import DetectionResult, DetectionRule


class SuspiciousProcessRule(DetectionRule):
    name = "suspicious_powershell"

    def evaluate(
        self,
        event: SentinelXEvent,
    ) -> Optional[DetectionResult]:
        if event.event_type != "process_creation":
            return None

        image = str(event.data.get("Image", "")).lower()
        command_line = str(event.data.get("CommandLine", "")).lower()

        if "powershell.exe" not in image and "powershell" not in command_line:
            return None

        return DetectionResult(
            rule_name=self.name,
            severity="high",
            description="PowerShell process execution detected",
            event=event,
        )