from correlation.correlator import EventCorrelator
from correlation.model import CorrelationEvent


class PersistenceSequenceRule:
    def __init__(self, window_minutes: int = 10):
        self.correlator = EventCorrelator(window_minutes)

    def evaluate(
        self,
        first: CorrelationEvent,
        second: CorrelationEvent,
    ) -> bool:
        if first.detection_rule != "suspicious_powershell":
            return False

        if second.detection_rule != "service_installation":
            return False

        if first.event.host != second.event.host:
            return False

        return self.correlator.within_window(first, second)