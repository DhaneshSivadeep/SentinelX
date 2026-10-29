from backend.models.event import SentinelXEvent
from detection.rules.base import DetectionResult, DetectionRule
from detection.rules.failed_login import FailedLoginRule
from detection.rules.service_install import ServiceInstallRule
from detection.rules.suspicious_process import SuspiciousProcessRule
from mitre.mapping import get_mitre_mapping
from detection.rules.linux_suspicious_process import LinuxSuspiciousProcessRule

class DetectionEngine:
    def __init__(self):
        self.rules: list[DetectionRule] = [
            FailedLoginRule(),
            SuspiciousProcessRule(),
            ServiceInstallRule(),
            LinuxSuspiciousProcessRule(),
        ]

    def evaluate(self, event: SentinelXEvent) -> list[DetectionResult]:
        detections = []

        for rule in self.rules:
            result = rule.evaluate(event)

            if result is not None:
                mitre = get_mitre_mapping(result.rule_name)

                enriched_result = DetectionResult(
                    rule_name=result.rule_name,
                    severity=result.severity,
                    description=result.description,
                    event=result.event,
                    mitre=mitre,
                )

                detections.append(enriched_result)

        return detections