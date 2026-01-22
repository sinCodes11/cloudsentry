"""Slack notification handler for CloudSentry."""

import json
from typing import List, Optional
from datetime import datetime

import requests

from ..checks.base import Finding, Severity
from ..config import SlackConfig


SEVERITY_COLORS = {
    Severity.CRITICAL: "#dc3545",  # Red
    Severity.HIGH: "#fd7e14",      # Orange
    Severity.MEDIUM: "#ffc107",    # Yellow
    Severity.LOW: "#17a2b8",       # Blue
}

SEVERITY_EMOJI = {
    Severity.CRITICAL: ":red_circle:",
    Severity.HIGH: ":large_orange_circle:",
    Severity.MEDIUM: ":large_yellow_circle:",
    Severity.LOW: ":large_blue_circle:",
}


class SlackNotifier:
    """Send notifications to Slack via webhook."""

    def __init__(self, config: SlackConfig):
        self.config = config
        self.webhook_url = config.webhook_url
        self.min_severity = Severity.from_string(config.min_severity)

    def should_notify(self, finding: Finding) -> bool:
        """Check if finding meets minimum severity for notification."""
        if not self.config.enabled:
            return False
        return finding.severity >= self.min_severity

    def send_finding(self, finding: Finding) -> bool:
        """Send a single finding notification."""
        if not self.should_notify(finding):
            return False

        emoji = SEVERITY_EMOJI.get(finding.severity, ":grey_question:")
        color = SEVERITY_COLORS.get(finding.severity, "#808080")

        payload = {
            "attachments": [
                {
                    "color": color,
                    "blocks": [
                        {
                            "type": "header",
                            "text": {
                                "type": "plain_text",
                                "text": f"{emoji} CloudSentry Security Finding",
                                "emoji": True,
                            },
                        },
                        {
                            "type": "section",
                            "fields": [
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Severity:*\n{finding.severity.value}",
                                },
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Check ID:*\n{finding.check_id}",
                                },
                            ],
                        },
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": f"*{finding.title}*\n{finding.description}",
                            },
                        },
                        {
                            "type": "section",
                            "fields": [
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Resource:*\n`{finding.resource_name or finding.resource_id[:50]}`",
                                },
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Type:*\n{finding.resource_type}",
                                },
                            ],
                        },
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": f"*Remediation:*\n{finding.remediation}",
                            },
                        },
                        {
                            "type": "context",
                            "elements": [
                                {
                                    "type": "mrkdwn",
                                    "text": f"Detected at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
                                }
                            ],
                        },
                    ],
                }
            ]
        }

        return self._send_webhook(payload)

    def send_scan_summary(
        self,
        findings_count: dict,
        new_findings: int,
        resolved_findings: int,
        scan_duration: float,
        compartments_scanned: int,
    ) -> bool:
        """Send scan summary notification."""
        if not self.config.enabled:
            return False

        total = sum(findings_count.values())
        critical = findings_count.get("CRITICAL", 0)
        high = findings_count.get("HIGH", 0)
        medium = findings_count.get("MEDIUM", 0)
        low = findings_count.get("LOW", 0)

        status_emoji = ":white_check_mark:" if critical == 0 and high == 0 else ":warning:"

        payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"{status_emoji} CloudSentry Scan Complete",
                        "emoji": True,
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Total Findings:*\n{total}",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Compartments Scanned:*\n{compartments_scanned}",
                        },
                    ],
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*By Severity:*\n:red_circle: Critical: {critical}\n:large_orange_circle: High: {high}\n:large_yellow_circle: Medium: {medium}\n:large_blue_circle: Low: {low}",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Changes:*\n:new: New: {new_findings}\n:white_check_mark: Resolved: {resolved_findings}",
                        },
                    ],
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": f"Scan completed in {scan_duration:.1f}s at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
                        }
                    ],
                },
            ]
        }

        return self._send_webhook(payload)

    def _send_webhook(self, payload: dict) -> bool:
        """Send payload to Slack webhook."""
        if not self.webhook_url:
            return False

        try:
            response = requests.post(
                self.webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            return response.status_code == 200
        except Exception as e:
            print(f"Failed to send Slack notification: {e}")
            return False
