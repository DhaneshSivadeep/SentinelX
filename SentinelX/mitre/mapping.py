from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class MitreTechnique:
    technique_id: str
    technique_name: str
    tactic: str
    description: str


MITRE_MAPPINGS: dict[str, MitreTechnique] = {
    "failed_login": MitreTechnique(
        technique_id="T1110",
        technique_name="Brute Force",
        tactic="Credential Access",
        description="Repeated authentication attempts can be associated with brute-force activity.",
    ),
    "suspicious_powershell": MitreTechnique(
        technique_id="T1059.001",
        technique_name="PowerShell",
        tactic="Execution",
        description="PowerShell can be used to execute commands and scripts on Windows systems.",
    ),
    "service_installation": MitreTechnique(
        technique_id="T1543.003",
        technique_name="Windows Service",
        tactic="Persistence",
        description="Windows services can be created or modified to establish persistence.",
    ),
        "linux_suspicious_process": MitreTechnique(
        technique_id="T1059.004",
        technique_name="Unix Shell",
        tactic="Execution",
        description="Unix shells can be used to execute commands and scripts on Linux systems.",
    ),
}

def get_mitre_mapping(rule_name: str) -> Optional[MitreTechnique]:
    return MITRE_MAPPINGS.get(rule_name)