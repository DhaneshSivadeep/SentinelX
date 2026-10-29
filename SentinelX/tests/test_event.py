from backend.models.event import SentinelXEvent


event = SentinelXEvent(
    event_id="test-001",
    host="Len-Laptop",
    os="windows",
    source="sentinelx_agent",
    event_type="agent_started",
    severity="info",
    data={
        "message": "SentinelX agent started successfully"
    },
)

print(event)
print()
print(event.model_dump_json(indent=2))