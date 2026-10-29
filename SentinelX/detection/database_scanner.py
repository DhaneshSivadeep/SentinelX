from backend.database import SessionLocal
from backend.models.database import EventRecord
from backend.models.event import SentinelXEvent
from detection.engine import DetectionEngine
from alerting.manager import AlertManager


def scan_database_events():
    db = SessionLocal()
    engine = DetectionEngine()
    alert_manager = AlertManager()

    try:
        events = db.query(EventRecord).order_by(EventRecord.timestamp.asc()).all()

        print(f"[*] Loaded {len(events)} events from PostgreSQL")

        total_detections = 0
        total_alerts = 0

        for record in events:
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

            detections = engine.evaluate(event)

            for detection in detections:
                total_detections += 1

                print("\n[!] DETECTION")
                print(f"    Rule: {detection.rule_name}")
                print(f"    Severity: {detection.severity}")
                print(f"    Description: {detection.description}")
                print(f"    Event ID: {detection.event.event_id}")
                print(f"    Host: {detection.event.host}")

                if detection.mitre:
                    print(
                        f"    MITRE: {detection.mitre.technique_id} "
                        f"- {detection.mitre.technique_name}"
                    )
                    print(f"    Tactic: {detection.mitre.tactic}")

                if alert_manager.alert_exists(detection):
                    print("    ALERT SKIPPED: already exists")
                else:
                    alert = alert_manager.create_alert(detection)
                    alert_manager.save_alert(alert)

                    total_alerts += 1

                    print(f"    ALERT CREATED: {alert.alert_id}")

        print(f"\n[*] Total detections: {total_detections}")
        print(f"[*] Total alerts created: {total_alerts}")

    finally:
        db.close()


if __name__ == "__main__":
    scan_database_events()