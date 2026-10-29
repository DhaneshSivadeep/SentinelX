from datetime import timedelta

from correlation.model import CorrelationEvent


class EventCorrelator:
    def __init__(self, window_minutes: int = 10):
        self.window = timedelta(minutes=window_minutes)

    def within_window(
        self,
        first: CorrelationEvent,
        second: CorrelationEvent,
    ) -> bool:
        difference = abs(second.timestamp - first.timestamp)

        return difference <= self.window