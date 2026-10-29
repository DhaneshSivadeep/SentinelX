import subprocess
import xml.etree.ElementTree as ET
import requests
from backend.models.event import SentinelXEvent

def query_security_log(count=5):
    """Query recent Windows Security events."""

    command = [
    "wevtutil",
    "qe",
    "Security",
    "/q:*[System[(EventID=4624 or EventID=4625 or EventID=4688 or EventID=4720 or EventID=4728 or EventID=7045)]]",
    f"/c:{count}",
    "/rd:true",
    "/f:xml",
]
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        error = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(
            f"Failed to query Security log: {error}"
        )

    return result.stdout


def parse_event(event_xml):
    """Parse one Windows Event XML document."""

    root = ET.fromstring(event_xml)

    namespace = {
        "event": "http://schemas.microsoft.com/win/2004/08/events/event"
    }

    system = root.find("event:System", namespace)

    event_id = system.findtext(
        "event:EventID",
        default="unknown",
        namespaces=namespace,
    )

    time_created = system.find(
        "event:TimeCreated",
        namespace,
    )

    timestamp = ""

    if time_created is not None:
        timestamp = time_created.attrib.get(
            "SystemTime",
            "",
        )

    computer = system.findtext(
        "event:Computer",
        default="unknown",
        namespaces=namespace,
    )

    channel = system.findtext(
        "event:Channel",
        default="unknown",
        namespaces=namespace,
    )

    data = {}

    event_data = root.find(
        "event:EventData",
        namespace,
    )

    if event_data is not None:
        for item in event_data.findall(
            "event:Data",
            namespace,
        ):
            name = item.attrib.get("Name")

            if name:
                data[name] = item.text

    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "host": computer,
        "channel": channel,
        "data": data,
    }
EVENT_METADATA = {
    "4624": {
        "event_type": "successful_logon",
        "severity": "info",
    },
    "4625": {
        "event_type": "failed_logon",
        "severity": "medium",
    },
    "4688": {
        "event_type": "process_creation",
        "severity": "info",
    },
    "4720": {
        "event_type": "user_account_created",
        "severity": "high",
    },
    "4728": {
        "event_type": "user_added_to_privileged_group",
        "severity": "high",
    },
    "7045": {
        "event_type": "service_installed",
        "severity": "high",
    },
}

def normalize_event(parsed_event):
    """Convert a Windows event into the SentinelX schema."""

    windows_event_id = parsed_event["event_id"]

    metadata = EVENT_METADATA.get(
        windows_event_id,
        {
            "event_type": "windows_event",
            "severity": "info",
        },
    )

    return SentinelXEvent(
        event_id=(
            f"windows-{windows_event_id}-"
            f"{parsed_event['timestamp']}"
        ),
        timestamp=parsed_event["timestamp"],
        host=parsed_event["host"],
        os="windows",
        source="windows_security",
        event_type=metadata["event_type"],
        severity=metadata["severity"],
        data=parsed_event["data"],
    )

def send_event(event):
    """Send a normalized event to the SentinelX API."""

    api_url = "http://127.0.0.1:8000/events"

    response = requests.post(
        api_url,
        json=event.model_dump(mode="json"),
        timeout=5,
    )

    response.raise_for_status()

    return response.json()


if __name__ == "__main__":
    raw_events = query_security_log(10)

    # wevtutil can return multiple XML Event documents
    # without a single surrounding root element.
    wrapped_xml = f"<Events>{raw_events}</Events>"

    root = ET.fromstring(wrapped_xml)

    namespace = {
        "event": "http://schemas.microsoft.com/win/2004/08/events/event"
    }

    events = []

    for event_element in root.findall(
        "event:Event",
        namespace,
    ):
        event_xml = ET.tostring(
            event_element,
            encoding="unicode",
        )

        parsed_event = parse_event(event_xml)
        events.append(parsed_event)

    print("=" * 60)
    print("NORMALIZED SENTINELX EVENT")
    print("=" * 60)

    for event in events:
        sentinelx_event = normalize_event(event)

        print(
            sentinelx_event.model_dump_json(
                indent=2
            )
        )

        api_response = send_event(sentinelx_event)

        print(f"[+] API response: {api_response}")

    print("=" * 60)
    print("Normalization and API transmission successful")
    print("=" * 60)