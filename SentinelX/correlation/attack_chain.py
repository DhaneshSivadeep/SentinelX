from correlation.correlator import EventCorrelator
from correlation.model import CorrelationEvent
from mitre.mapping import get_mitre_mapping


class AttackChainResult:
    def __init__(self, events):
        self.events = events
        self.host = events[0].event.host

    def to_dict(self):
        stages = []

        for event in self.events:
            mitre = get_mitre_mapping(event.detection_rule)

            stage = {
                "rule": event.detection_rule,
                "event_id": event.event.event_id,
                "timestamp": event.timestamp.isoformat(),
            }

            if mitre:
                stage["mitre"] = {
                    "technique_id": mitre.technique_id,
                    "technique_name": mitre.technique_name,
                    "tactic": mitre.tactic,
                }

            stages.append(stage)

        return {
            "type": "multi_stage_attack_chain",
            "host": self.host,
            "stages": stages,
        }


class AttackChainRule:
    def __init__(self, window_minutes: int = 10):
        self.correlator = EventCorrelator(window_minutes)

    def evaluate(
        self,
        first: CorrelationEvent,
        second: CorrelationEvent,
        third: CorrelationEvent,
    ):
        expected_rules = [
            "failed_login",
            "suspicious_powershell",
            "service_installation",
        ]

        actual_rules = [
            first.detection_rule,
            second.detection_rule,
            third.detection_rule,
        ]

        if actual_rules != expected_rules:
            return None

        hosts = {
            first.event.host,
            second.event.host,
            third.event.host,
        }

        if len(hosts) != 1:
            return None

        if not self.correlator.within_window(first, second):
            return None

        if not self.correlator.within_window(second, third):
            return None

        return AttackChainResult([first, second, third])