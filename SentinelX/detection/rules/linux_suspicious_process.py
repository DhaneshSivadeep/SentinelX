from detection.rules.base import DetectionRule, DetectionResult


class LinuxSuspiciousProcessRule(DetectionRule):
    name = "linux_suspicious_process"

    def evaluate(self, event):
        if event.os.lower() != "linux":
            return None

        if event.event_type != "process_creation":
            return None

        data = event.data or {}

        image = str(
            data.get("Image", "")
        ).lower()

        command_line = str(
            data.get("CommandLine", "")
        ).lower()

        suspicious_patterns = [
            "curl ",
            "wget ",
            "| bash",
            "| sh",
            "bash -c",
            "sh -c",
        ]

        suspicious = any(
            pattern in command_line
            for pattern in suspicious_patterns
        )

        if not suspicious:
            return None

        return DetectionResult(
            rule_name=self.name,
            severity="high",
            description="Suspicious Linux shell command execution detected",
            event=event,
        )