import subprocess
import xml.etree.ElementTree as ET
import requests
from backend.models.event import SentinelXEvent


SYSMON_EVENT_METADATA = {
    "1": {
        "event_type": "process_creation",
        "severity": "info",
    },
    "3": {
        "event_type": "network_connection",
        "severity": "info",
    },
    "11": {
        "event_type": "file_creation",
        "severity": "info",
    },
    "13": {
        "event_type": "registry_modification",
        "severity": "info",
    },
}


def query_sysmon_log(count=10):
    command = [
        "wevtutil",
        "qe",
        "Microsoft-Windows-Sysmon/Operational",
        "/q:*[System[(EventID=1 or EventID=3 or EventID=11 or EventID=13)]]",
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
        raise RuntimeError(f"Failed to query Sysmon log: {error}")

    return result.stdout


def parse_event(event_xml):
    namespace = {
        "event": "http://schemas.microsoft.com/win/2004/08/events/event"
    }

    root = ET.fromstring(event_xml)

    system = root.find("event:System", namespace)

    event_id = system.find(
        "event:EventID",
        namespace,
    ).text

    time_created = system.find(
        "event:TimeCreated",
        namespace,
    )

    timestamp = time_created.attrib["SystemTime"]

    computer = system.find(
        "event:Computer",
        namespace,
    ).text

    channel = system.find(
        "event:Channel",
        namespace,
    ).text

    data = {}

    event_data = root.find(
        "event:EventData",
        namespace,
    )

    if event_data is not None:
        for item in event_data.findall("event:Data", namespace):
            name = item.attrib.get("Name", "unknown")
            data[name] = item.text or ""

    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "host": computer,
        "channel": channel,
        "data": data,
    }


def normalize_event(parsed_event):
    metadata = SYSMON_EVENT_METADATA.get(
        parsed_event["event_id"],
        {
            "event_type": f"sysmon_event_{parsed_event['event_id']}",
            "severity": "info",
        },
    )

    return SentinelXEvent(
        event_id=(
            f"sysmon-{parsed_event['event_id']}-"
            f"{parsed_event['timestamp']}"
        ),
        timestamp=parsed_event["timestamp"],
        host=parsed_event["host"],
        os="windows",
        source="sysmon",
        event_type=metadata["event_type"],
        severity=metadata["severity"],
        data=parsed_event["data"],
    )
def send_event(event):
    api_url = "http://127.0.0.1:8000/events"

    response = requests.post(
        api_url,
        json=event.model_dump(mode="json"),
        timeout=5,
    )

    response.raise_for_status()

    return response.json()

if __name__ == "__main__":
    raw_events = query_sysmon_log(10)

    wrapped_xml = f"<Events>{raw_events}</Events>"

    root = ET.fromstring(wrapped_xml)

    namespace = {
        "event": "http://schemas.microsoft.com/win/2004/08/events/event"
    }

    print("\n========================================")
    print("       SENTINELX SYSMON COLLECTOR")
    print("========================================")

    events = []

    for event_element in root.findall("event:Event", namespace):
        event_xml = ET.tostring(
            event_element,
            encoding="unicode",
        )

        parsed_event = parse_event(event_xml)
        normalized_event = normalize_event(parsed_event)

        events.append(normalized_event)

        if len(events) == 1:
            print("\n[+] First Sysmon event data:")
            for key, value in normalized_event.data.items():
                print(f"    {key}: {value}")

    print(f"\n[+] Sysmon events collected: {len(events)}")

    for event in events:
        print("\n----------------------------------------")
        print(f"Event ID    : {event.event_id}")
        print(f"Event Type  : {event.event_type}")
        print(f"Severity    : {event.severity}")
        print(f"Host        : {event.host}")
        print(f"Data fields : {len(event.data)}")
        result = send_event(event)
        print(f"API Response: {result}")