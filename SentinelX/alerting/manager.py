from datetime import datetime, timezone
from uuid import uuid4

from alerting.model import Alert
from backend.database import SessionLocal
from backend.models.database import AlertRecord
from detection.rules.base import DetectionResult


class AlertManager:
    def create_alert(self, detection: DetectionResult) -> Alert:
        mitre = detection.mitre

        return Alert(
            alert_id=str(uuid4()),
            title=f"{detection.rule_name.replace('_', ' ').title()} Detected",
            severity=detection.severity,
            host=detection.event.host,
            timestamp=datetime.now(timezone.utc),
            status="new",
            description=detection.description,
            rule_name=detection.rule_name,
            event_id=detection.event.event_id,
            mitre=mitre,
        )

    def alert_exists(self, detection: DetectionResult) -> bool:
        db = SessionLocal()

        try:
            existing = (
                db.query(AlertRecord)
                .filter(
                    AlertRecord.event_id == detection.event.event_id,
                    AlertRecord.rule_name == detection.rule_name,
                )
                .first()
            )

            return existing is not None

        finally:
            db.close()

    def save_alert(self, alert: Alert) -> None:
        mitre = alert.mitre

        record = AlertRecord(
            alert_id=alert.alert_id,
            title=alert.title,
            severity=alert.severity,
            host=alert.host,
            timestamp=alert.timestamp,
            status=alert.status,
            description=alert.description,
            rule_name=alert.rule_name,
            event_id=alert.event_id,
            mitre_technique_id=mitre.technique_id if mitre else None,
            mitre_technique_name=mitre.technique_name if mitre else None,
            mitre_tactic=mitre.tactic if mitre else None,
        )

        db = SessionLocal()

        try:
            db.add(record)
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()