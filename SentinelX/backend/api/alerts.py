from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel

from backend.database import get_db
from backend.models.database import AlertRecord, EventRecord


router = APIRouter(
    prefix="/alerts",
    tags=["Alerts"],
)


# ============================================================
# GET ALL ALERTS
# Supports filtering, sorting, and pagination
# ============================================================

@router.get("")
def get_alerts(
    severity: str | None = None,
    status: str | None = None,
    rule_name: str | None = None,
    host: str | None = None,
    limit: int = 50,
    offset: int = 0,
    sort: str = "latest",
    db: Session = Depends(get_db),
):
    # --------------------------------------------------------
    # Validate pagination
    # --------------------------------------------------------

    if limit < 1:
        raise HTTPException(
            status_code=400,
            detail="limit must be greater than 0",
        )

    if offset < 0:
        raise HTTPException(
            status_code=400,
            detail="offset must be 0 or greater",
        )

    query = db.query(AlertRecord)

    # --------------------------------------------------------
    # Filters
    # --------------------------------------------------------

    if severity:
        query = query.filter(
            AlertRecord.severity == severity
        )

    if status:
        query = query.filter(
            AlertRecord.status == status
        )

    if rule_name:
        query = query.filter(
            AlertRecord.rule_name == rule_name
        )

    if host:
        query = query.filter(
            AlertRecord.host == host
        )

    # --------------------------------------------------------
    # Sorting
    # --------------------------------------------------------

    if sort == "latest":
        query = query.order_by(
            AlertRecord.id.desc()
        )

    elif sort == "oldest":
        query = query.order_by(
            AlertRecord.id.asc()
        )

    elif sort == "severity":
        query = query.order_by(
            AlertRecord.severity.desc(),
            AlertRecord.id.desc(),
        )

    else:
        raise HTTPException(
            status_code=400,
            detail=(
                "Invalid sort. Allowed values: "
                "latest, oldest, severity"
            ),
        )

    # --------------------------------------------------------
    # Pagination
    # --------------------------------------------------------

    alerts = (
        query
        .offset(offset)
        .limit(limit)
        .all()
    )

    # --------------------------------------------------------
    # Response
    # --------------------------------------------------------

    return {
        "count": len(alerts),
        "limit": limit,
        "offset": offset,
        "sort": sort,
        "filters": {
            "severity": severity,
            "status": status,
            "rule_name": rule_name,
            "host": host,
        },
        "alerts": [
            {
                "id": alert.id,
                "alert_id": alert.alert_id,
                "title": alert.title,
                "severity": alert.severity,
                "host": alert.host,
                "timestamp": alert.timestamp,
                "status": alert.status,
                "description": alert.description,
                "rule_name": alert.rule_name,
                "event_id": alert.event_id,
                "mitre": (
                    {
                        "technique_id": alert.mitre_technique_id,
                        "technique_name": alert.mitre_technique_name,
                        "tactic": alert.mitre_tactic,
                    }
                    if alert.mitre_technique_id
                    else None
                ),
            }
            for alert in alerts
        ],
    }


# ============================================================
# GET ALERT STATISTICS
# ============================================================

@router.get("/stats")
def get_alert_stats(
    db: Session = Depends(get_db),
):
    alerts = db.query(AlertRecord).all()

    total = len(alerts)

    severity_counts = {}
    status_counts = {}

    for alert in alerts:
        severity = alert.severity
        severity_counts[severity] = (
            severity_counts.get(severity, 0) + 1
        )

        alert_status = alert.status
        status_counts[alert_status] = (
            status_counts.get(alert_status, 0) + 1
        )

    return {
        "total": total,
        "by_severity": severity_counts,
        "by_status": status_counts,
    }


# ============================================================
# GET SINGLE ALERT
# ============================================================

@router.get("/{alert_id}")
def get_alert(
    alert_id: str,
    db: Session = Depends(get_db),
):
    alert = (
        db.query(AlertRecord)
        .filter(
            AlertRecord.alert_id == alert_id
        )
        .first()
    )

    if alert is None:
        raise HTTPException(
            status_code=404,
            detail="Alert not found",
        )

    return {
        "id": alert.id,
        "alert_id": alert.alert_id,
        "title": alert.title,
        "severity": alert.severity,
        "host": alert.host,
        "timestamp": alert.timestamp,
        "status": alert.status,
        "description": alert.description,
        "rule_name": alert.rule_name,
        "event_id": alert.event_id,
        "mitre": (
            {
                "technique_id": alert.mitre_technique_id,
                "technique_name": alert.mitre_technique_name,
                "tactic": alert.mitre_tactic,
            }
            if alert.mitre_technique_id
            else None
        ),
    }

# ============================================================
# GET ALERT + ORIGINATING EVENT
# ============================================================

@router.get("/{alert_id}/event")
def get_alert_event(
    alert_id: str,
    db: Session = Depends(get_db),
):
    # --------------------------------------------------------
    # Find the alert
    # --------------------------------------------------------

    alert = (
        db.query(AlertRecord)
        .filter(AlertRecord.alert_id == alert_id)
        .first()
    )

    if alert is None:
        raise HTTPException(
            status_code=404,
            detail="Alert not found",
        )

    # --------------------------------------------------------
    # Make sure the alert has an event ID
    # --------------------------------------------------------

    if not alert.event_id:
        raise HTTPException(
            status_code=404,
            detail="No originating event associated with this alert",
        )

    # --------------------------------------------------------
    # Find the originating event
    # --------------------------------------------------------

    event = (
        db.query(EventRecord)
        .filter(EventRecord.event_id == alert.event_id)
        .first()
    )

    if event is None:
        raise HTTPException(
            status_code=404,
            detail="Originating event not found",
        )

    # --------------------------------------------------------
    # Return alert + event + MITRE information
    # --------------------------------------------------------

    return {
        "alert": {
            "id": alert.id,
            "alert_id": alert.alert_id,
            "title": alert.title,
            "severity": alert.severity,
            "host": alert.host,
            "timestamp": alert.timestamp,
            "status": alert.status,
            "description": alert.description,
            "rule_name": alert.rule_name,
            "event_id": alert.event_id,
        },

        "event": {
            "id": event.id,
            "event_id": event.event_id,
            "timestamp": event.timestamp,
            "host": event.host,
            "os": event.os,
            "source": event.source,
            "event_type": event.event_type,
            "severity": event.severity,
            "data": event.data,
        },

        "mitre": (
            {
                "technique_id": alert.mitre_technique_id,
                "technique_name": alert.mitre_technique_name,
                "tactic": alert.mitre_tactic,
            }
            if alert.mitre_technique_id
            else None
        ),
    }

# ============================================================
# UPDATE ALERT STATUS
# ============================================================

class AlertStatusUpdate(BaseModel):
    status: str


@router.patch("/{alert_id}")
def update_alert_status(
    alert_id: str,
    payload: AlertStatusUpdate,
    db: Session = Depends(get_db),
):
    allowed_statuses = {
        "new",
        "acknowledged",
        "resolved",
    }

    # --------------------------------------------------------
    # Validate status
    # --------------------------------------------------------

    if payload.status not in allowed_statuses:
        raise HTTPException(
            status_code=400,
            detail=(
                "Invalid status. Allowed values: "
                "new, acknowledged, resolved"
            ),
        )

    # --------------------------------------------------------
    # Find alert
    # --------------------------------------------------------

    alert = (
        db.query(AlertRecord)
        .filter(
            AlertRecord.alert_id == alert_id
        )
        .first()
    )

    if alert is None:
        raise HTTPException(
            status_code=404,
            detail="Alert not found",
        )

    # --------------------------------------------------------
    # Update status
    # --------------------------------------------------------

    alert.status = payload.status

    db.commit()
    db.refresh(alert)

    return {
        "status": "updated",
        "alert_id": alert.alert_id,
        "new_status": alert.status,
    }