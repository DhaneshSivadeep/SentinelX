from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text, JSON
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Column, DateTime, Integer, String, Text

class Base(DeclarativeBase):
    pass


class EventRecord(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    event_id: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )

    host: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )

    os: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    source: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    event_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )

    severity: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )

    data: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
    )
class AlertRecord(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String, unique=True, nullable=False, index=True)

    title = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    host = Column(String, nullable=False)

    timestamp = Column(DateTime(timezone=True), nullable=False)

    status = Column(String, nullable=False, default="new")

    description = Column(Text, nullable=False)

    rule_name = Column(String, nullable=True)
    event_id = Column(String, nullable=True)

    mitre_technique_id = Column(String, nullable=True)
    mitre_technique_name = Column(String, nullable=True)
    mitre_tactic = Column(String, nullable=True)