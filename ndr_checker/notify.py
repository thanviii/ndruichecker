"""Optional webhook notifications."""

import json
import logging
import os
from typing import Any, Dict, List

import requests


logger = logging.getLogger(__name__)


def send_webhook(results: List[Dict[str, Any]]) -> bool:
    """Send webhook notification if WEBHOOK_URL is set and there are issues.

    Only sends if at least one target is DOWN or WARN.

    Returns:
        True if sent successfully, False otherwise
    """
    webhook_url = os.getenv("WEBHOOK_URL")
    if not webhook_url:
        return False

    # Check if there are any warnings or failures
    has_issues = any(r["status"] in ("DOWN", "WARN") for r in results)
    if not has_issues:
        logger.debug("No issues found; skipping webhook notification")
        return False

    try:
        # Build payload compatible with Teams/Slack webhooks
        down_targets = [r for r in results if r["status"] == "DOWN"]
        warn_targets = [r for r in results if r["status"] == "WARN"]

        payload = {
            "text": "NDR Console Health Check Alert",
            "attachments": [
                {
                    "color": "danger" if down_targets else "warning",
                    "title": "NDR Health Check Summary",
                    "fields": [
                        {
                            "title": "Total Checked",
                            "value": str(len(results)),
                            "short": True,
                        },
                        {
                            "title": "Down",
                            "value": str(len(down_targets)),
                            "short": True,
                        },
                        {
                            "title": "Warning",
                            "value": str(len(warn_targets)),
                            "short": True,
                        },
                    ],
                }
            ],
        }

        # Add down targets
        if down_targets:
            fields = []
            for r in down_targets:
                fields.append({
                    "title": f"DOWN: {r['target']['name']}",
                    "value": r.get("reason", "Unknown error"),
                    "short": False,
                })
            payload["attachments"].append({
                "color": "danger",
                "title": "Failed Targets",
                "fields": fields,
            })

        # Add warning targets
        if warn_targets:
            fields = []
            for r in warn_targets:
                fields.append({
                    "title": f"WARN: {r['target']['name']}",
                    "value": r.get("reason", "Unknown warning"),
                    "short": False,
                })
            payload["attachments"].append({
                "color": "warning",
                "title": "Warning Targets",
                "fields": fields,
            })

        response = requests.post(webhook_url, json=payload, timeout=10)
        response.raise_for_status()

        logger.info(f"Webhook notification sent to {webhook_url}")
        return True

    except Exception as e:
        logger.error(f"Failed to send webhook notification: {e}")
        return False
