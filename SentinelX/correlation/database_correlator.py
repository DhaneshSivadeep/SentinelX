from backend.database import SessionLocal
from backend.models.database import EventRecord
from backend.models.event import SentinelXEvent

from detection.engine import DetectionEngine

from correlation.model import CorrelationEvent
from correlation.attack_chain import AttackChainRule


def scan_for_attack_chains():
    db = SessionLocal()

    try:
        records = (
            db.query(EventRecord)
            .order_by(EventRecord.timestamp.asc())
            .all()
        )

        print(f"[*] Loaded {len(records)} events from PostgreSQL")

        detection_engine = DetectionEngine()
        correlation_events = []

        for record in records:
            event = SentinelXEvent(
                event_id=record.event_id,
                timestamp=record.timestamp,
                host=record.host,
                os=record.os,
                source=record.source,
                event_type=record.event_type,
                severity=record.severity,
                data=record.data,
            )

            detections = detection_engine.evaluate(event)

            for detection in detections:
                correlation_events.append(
                    CorrelationEvent(
                        event=event,
                        detection_rule=detection.rule_name,
                        timestamp=event.timestamp,
                    )
                )

        print(
            f"[*] Generated {len(correlation_events)} "
            "correlation events"
        )

        attack_chain_rule = AttackChainRule()

        total_chains = 0

        for index, first in enumerate(correlation_events):
            for second in correlation_events[index + 1:]:
                for third in correlation_events[
                    correlation_events.index(second) + 1:
                ]:
                    result = attack_chain_rule.evaluate(
                        first,
                        second,
                        third,
                    )

                    if result:
                        total_chains += 1

                        print("\n[!] ATTACK CHAIN DETECTED")
                        print(f"    Host: {result.host}")

                        for stage in result.to_dict()["stages"]:
                            print(
                                f"    {stage['rule']} "
                                f"-> {stage['event_id']}"
                            )

                            if "mitre" in stage:
                                print(
                                    f"       MITRE: "
                                    f"{stage['mitre']['technique_id']} "
                                    f"- "
                                    f"{stage['mitre']['technique_name']}"
                                )

        print(f"\n[*] Total attack chains: {total_chains}")

    finally:
        db.close()


if __name__ == "__main__":
    scan_for_attack_chains()