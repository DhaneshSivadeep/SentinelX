from datetime import datetime, timezone

from backend.database import SessionLocal
from backend.models.database import EventRecord


TEST_EVENTS = [
    EventRecord(
        event_id="day4-test-4625",
        timestamp=datetime.now(timezone.utc),
        host="Len-Laptop",
        os="windows",
        source="windows_security",
        event_type="failed_logon",
        severity="medium",
        data={
            "EventID": "4625",
            "TargetUserName": "test-user",
            "LogonType": "2",
        },
    ),
    EventRecord(
        event_id="day4-test-powershell",
        timestamp=datetime.now(timezone.utc),
        host="Len-Laptop",
        os="windows",
        source="sysmon",
        event_type="process_creation",
        severity="info",
        data={
            "EventID": "1",
            "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "CommandLine": "powershell.exe -NoProfile",
        },
    ),
    EventRecord(
        event_id="day4-test-7045",
        timestamp=datetime.now(timezone.utc),
        host="Len-Laptop",
        os="windows",
        source="windows_security",
        event_type="service_installed",
        severity="high",
        data={
            "EventID": "7045",
            "ServiceName": "SentinelX-TestService",
        },
    ),
]


def seed_events():
    db = SessionLocal()

    try:
        for event in TEST_EVENTS:
            existing = (
                db.query(EventRecord)
                .filter(EventRecord.event_id == event.event_id)
                .first()
            )

            if existing:
                print(f"[=] Already exists: {event.event_id}")
                continue

            db.add(event)
            print(f"[+] Added: {event.event_id}")

        db.commit()

    finally:
        db.close()


if __name__ == "__main__":
    seed_events()