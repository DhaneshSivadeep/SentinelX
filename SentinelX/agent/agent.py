import getpass
import platform
import socket
import uuid

import psutil
import requests

from agent.collectors.windows_event_collector import (
    query_security_log,
    parse_event,
    normalize_event,
)

from agent.collectors.sysmon_collector import (
    query_sysmon_log,
    parse_event as parse_sysmon_event,
    normalize_event as normalize_sysmon_event,
)

API_URL = "http://127.0.0.1:8000/events"


def get_system_info():
    """Collect basic information about the endpoint."""

    hostname = socket.gethostname()
    username = getpass.getuser()
    operating_system = platform.system()

    cpu_usage = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()

    return {
        "hostname": hostname,
        "username": username,
        "os": operating_system,
        "cpu_percent": cpu_usage,
        "memory_percent": memory.percent,
    }


def get_ip_addresses():
    """Collect IPv4 addresses from the endpoint."""

    ip_addresses = []

    interfaces = psutil.net_if_addrs()

    for interface_name, addresses in interfaces.items():
        for address in addresses:
            if address.family == socket.AF_INET:
                ip_addresses.append(
                    {
                        "interface": interface_name,
                        "ip": address.address,
                    }
                )

    return ip_addresses


def get_running_processes():
    """Collect currently running processes."""

    processes = []

    for process in psutil.process_iter(["pid", "name"]):
        try:
            processes.append(
                {
                    "pid": process.info["pid"],
                    "name": process.info["name"],
                }
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return processes


def create_agent_event(system_info, ip_addresses, processes):
    """Create a normalized SentinelX event."""

    return {
        "event_id": str(uuid.uuid4()),
        "host": system_info["hostname"],
        "os": system_info["os"].lower(),
        "source": "sentinelx_agent",
        "event_type": "agent_started",
        "severity": "info",
        "data": {
            "username": system_info["username"],
            "cpu_percent": system_info["cpu_percent"],
            "memory_percent": system_info["memory_percent"],
            "ip_addresses": ip_addresses,
            "process_count": len(processes),
            "processes": processes[:20],
        },
    }


def send_event(event):
    """Send a SentinelX event to the backend API."""

    try:
        if hasattr(event, "model_dump"):
            payload = event.model_dump(mode="json")
        else:
            payload = event

        response = requests.post(
            API_URL,
            json=payload,
            timeout=5,
        )

        response.raise_for_status()

        print("\n[+] Event sent successfully")
        print(f"[+] API status: {response.status_code}")
        print(f"[+] API response: {response.json()}")

    except requests.RequestException as error:
        print("\n[-] Failed to send event")
        print(f"[-] Error: {error}")
def main():
    print("=" * 40)
    print("       SENTINELX WINDOWS AGENT")
    print("=" * 40)

    system_info = get_system_info()

    print(f"\nHostname         : {system_info['hostname']}")
    print(f"Operating System : {system_info['os']}")
    print(f"Username         : {system_info['username']}")
    print(f"CPU Usage        : {system_info['cpu_percent']} %")
    print(f"Memory Usage     : {system_info['memory_percent']} %")

    print("\nCollecting IP addresses...")
    ip_addresses = get_ip_addresses()

    print("\nCollecting running processes...")
    processes = get_running_processes()

    print(f"[+] Processes collected: {len(processes)}")

    event = create_agent_event(
        system_info,
        ip_addresses,
        processes,
    )

    print("\nSending event to SentinelX API...")

    send_event(event)

    print("\n" + "=" * 40)
    print("Agent execution completed")
    print("=" * 40)

def collect_windows_security_events(count=5):
    """Collect and normalize Windows Security events."""

    raw_events = query_security_log(count)

    wrapped_xml = f"<Events>{raw_events}</Events>"

    import xml.etree.ElementTree as ET

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

        normalized_event = normalize_event(
            parsed_event
        )

        events.append(normalized_event)

    return events

def collect_sysmon_events(count=5):
    raw_events = query_sysmon_log(count)

    wrapped_xml = f"<Events>{raw_events}</Events>"

    import xml.etree.ElementTree as ET

    root = ET.fromstring(wrapped_xml)

    namespace = {
        "event": "http://schemas.microsoft.com/win/2004/08/events/event"
    }

    events = []

    for event_element in root.findall("event:Event", namespace):
        event_xml = ET.tostring(
            event_element,
            encoding="unicode",
        )

        parsed_event = parse_sysmon_event(event_xml)
        normalized_event = normalize_sysmon_event(parsed_event)

        events.append(normalized_event)

    return events

if __name__ == "__main__":
    main()
    print("\nCollecting Windows Security events...")

try:
    security_events = collect_windows_security_events(5)

    print(
        f"[+] Windows Security events collected: "
        f"{len(security_events)}"
    )

    for security_event in security_events:
        send_event(security_event)
    
except Exception as error:
    print("\n[-] Windows Security collection failed")
    print(f"[-] Error: {error}")
print("\nCollecting Sysmon events...")
try:
        sysmon_events = collect_sysmon_events(5)
        print(f"[+] Sysmon events collected: {len(sysmon_events)}")

        for sysmon_event in sysmon_events:
            send_event(sysmon_event)
except Exception as error:
        print("\n[-] Sysmon collection failed")
        print(f"[-] Error: {error}")
