"""Configuration loading and validation."""

import yaml
from pathlib import Path
from typing import Any, Dict, List


def load_config(config_path: str) -> Dict[str, Any]:
    """Load and validate YAML config file."""
    with open(config_path, "r") as f:
        config = yaml.safe_load(f)

    if not config:
        raise ValueError("Config file is empty")

    return config


def get_defaults(config: Dict[str, Any]) -> Dict[str, Any]:
    """Extract global defaults section."""
    defaults = config.get("defaults", {})

    # Ensure default values for required fields
    defaults.setdefault("timeout", 10)
    defaults.setdefault("retries", 2)
    defaults.setdefault("verify_tls", True)
    defaults.setdefault("expected_status", [200, 301, 302, 303, 307, 308, 401, 403])
    defaults.setdefault("workers", 10)
    defaults.setdefault("cert_warn_days", 30)
    defaults.setdefault("response_warn_ms", 5000)
    defaults.setdefault("proxy", None)

    return defaults


def validate_target(target: Dict[str, Any], defaults: Dict[str, Any]) -> Dict[str, Any]:
    """Validate a target and apply defaults."""
    required_fields = ["client", "name", "url"]

    for field in required_fields:
        if field not in target:
            raise ValueError(f"Target missing required field: {field}")

    # Apply defaults for optional fields
    target.setdefault("vendor", None)
    target.setdefault("verify_tls", defaults["verify_tls"])
    target.setdefault("expected_status", defaults["expected_status"])
    target.setdefault("timeout", defaults["timeout"])
    target.setdefault("tags", [])
    target.setdefault("proxy", defaults.get("proxy"))

    # Validate URL format
    url = target["url"]
    if not url.startswith("https://"):
        raise ValueError(f"URL must start with https://: {url}")

    return target


def load_targets(config_path: str) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Load targets from config file with defaults applied.

    Returns:
        Tuple of (targets list, defaults dict)
    """
    config = load_config(config_path)
    defaults = get_defaults(config)

    targets_raw = config.get("targets", [])
    if not targets_raw:
        raise ValueError("Config must have at least one target")

    targets = [validate_target(t, defaults) for t in targets_raw]

    return targets, defaults
