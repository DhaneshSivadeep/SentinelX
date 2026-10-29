from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session
from backend.api.alerts import router as alerts_router
from backend.database import SessionLocal, get_db
from backend.models.database import EventRecord
from backend.models.event import SentinelXEvent
from detection.engine import DetectionEngine
from alerting.manager import AlertManager
from detection.engine import DetectionEngine
from alerting.manager import AlertManager

app = FastAPI(
    title="SentinelX API",
    description="Cross-Platform Endpoint Security Monitoring Platform",
    version="0.1.0",
)
app.include_router(alerts_router)

@app.get("/")
def root():
    return {
        "service": "SentinelX API",
        "status": "online",
    }


@app.post("/events")
def ingest_event(
    event: SentinelXEvent,
    db: Session = Depends(get_db),
):
    event_record = EventRecord(
        event_id=event.event_id,
        timestamp=event.timestamp,
        host=event.host,
        os=event.os,
        source=event.source,
        event_type=event.event_type,
        severity=event.severity,
        data=event.data,
    )

    db.add(event_record)
    db.commit()
    db.refresh(event_record)

    print("\n[+] Event stored in PostgreSQL")
    print(event.model_dump_json(indent=2))

    # Run detection immediately
    detection_engine = DetectionEngine()
    alert_manager = AlertManager()

    detections = detection_engine.evaluate(event)

    created_alerts = []

    for detection in detections:
        print("\n[!] REAL-TIME DETECTION")
        print(f"    Rule: {detection.rule_name}")
        print(f"    Severity: {detection.severity}")
        print(f"    Event ID: {detection.event.event_id}")

        if detection.mitre:
            print(
                f"    MITRE: {detection.mitre.technique_id} "
                f"- {detection.mitre.technique_name}"
            )
            print(f"    Tactic: {detection.mitre.tactic}")

        # Prevent duplicate alerts
        if alert_manager.alert_exists(detection):
            print("    ALERT SKIPPED: already exists")
            continue

        alert = alert_manager.create_alert(detection)
        alert_manager.save_alert(alert)

        created_alerts.append(alert)

        print(f"    ALERT CREATED: {alert.alert_id}")

    return {
        "status": "accepted",
        "event_id": event.event_id,
        "database_id": event_record.id,
        "detections": [
            detection.to_dict()
            for detection in detections
        ],
        "alerts": [
            alert.to_dict()
            for alert in created_alerts
        ],
    }

    print("\n[+] Event stored in PostgreSQL")
    print(event.model_dump_json(indent=2))

    return {
        "status": "accepted",
        "event_id": event.event_id,
        "database_id": event_record.id,
    }


@app.get("/events")
def get_events(db: Session = Depends(get_db)):
    events = (
        db.query(EventRecord)
        .order_by(EventRecord.timestamp.desc())
        .all()
    )

    return {
        "count": len(events),
        "events": [
            {
                "id": event.id,
                "event_id": event.event_id,
                "timestamp": event.timestamp,
                "host": event.host,
                "os": event.os,
                "source": event.source,
                "event_type": event.event_type,
                "severity": event.severity,
                "data": event.data,
            }
            for event in events
        ],
    }