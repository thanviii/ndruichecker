"""Concurrent execution with retries."""

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List

from .checks import run_checks


logger = logging.getLogger(__name__)


def run_target_with_retries(
    target: Dict[str, Any], retries: int, backoff_ms: float = 100
) -> Dict[str, Any]:
    """Run checks for a target with retry logic.

    Args:
        target: Target configuration
        retries: Number of retries (0 = no retries, 1 = one retry, etc.)
        backoff_ms: Backoff in milliseconds between retries

    Returns:
        Result dict with final status
    """
    last_result = None

    for attempt in range(retries + 1):
        try:
            result = run_checks(target)
            last_result = result

            # If status is UP, return immediately
            if result["status"] == "UP":
                if attempt > 0:
                    logger.info(
                        f"Target {target['name']} passed on attempt {attempt + 1}"
                    )
                return result

            # If WARN, return (not a hard failure)
            if result["status"] == "WARN":
                return result

            # If DOWN, retry unless this is the last attempt
            if attempt < retries:
                logger.debug(
                    f"Target {target['name']} failed (attempt {attempt + 1}), retrying in {backoff_ms}ms..."
                )
                time.sleep(backoff_ms / 1000.0)

        except Exception as e:
            logger.error(f"Unexpected error checking {target['name']}: {e}")
            last_result = {
                "target": target,
                "checks": [],
                "http_status": None,
                "response_ms": None,
                "cert_days_remaining": None,
                "reason": f"Unexpected error: {str(e)}",
                "status": "DOWN",
            }
            if attempt < retries:
                time.sleep(backoff_ms / 1000.0)

    return last_result or {
        "target": target,
        "checks": [],
        "http_status": None,
        "response_ms": None,
        "cert_days_remaining": None,
        "reason": "No result returned",
        "status": "DOWN",
    }


def run_all_targets(
    targets: List[Dict[str, Any]],
    workers: int = 10,
    retries: int = 2,
    filter_client: str = None,
    filter_tags: List[str] = None,
) -> tuple[List[Dict[str, Any]], int]:
    """Run checks for all targets concurrently.

    Args:
        targets: List of target configurations
        workers: Number of concurrent workers
        retries: Number of retries per target
        filter_client: Only check targets matching this client name
        filter_tags: Only check targets with any of these tags

    Returns:
        Tuple of (results list, max_status_code)
        status_code: 0=all UP, 1=at least one WARN, 2=at least one DOWN
    """
    # Filter targets if requested
    filtered_targets = targets
    if filter_client:
        filtered_targets = [t for t in targets if t["client"].lower() == filter_client.lower()]
        if not filtered_targets:
            logger.warning(f"No targets found for client: {filter_client}")

    if filter_tags:
        filtered_targets = [
            t
            for t in filtered_targets
            if any(tag in t.get("tags", []) for tag in filter_tags)
        ]
        if not filtered_targets:
            logger.warning(f"No targets found with tags: {filter_tags}")

    if not filtered_targets:
        return [], 3  # Configuration error

    logger.info(f"Running checks on {len(filtered_targets)} target(s)...")

    results = []
    max_status = 0

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(run_target_with_retries, target, retries): target
            for target in filtered_targets
        }

        for future in as_completed(futures):
            target = futures[future]
            try:
                result = future.result()
                results.append(result)

                # Track max status code
                if result["status"] == "DOWN":
                    max_status = max(max_status, 2)
                elif result["status"] == "WARN":
                    max_status = max(max_status, 1)

                logger.info(
                    f"[OK] {target['name']} ({target['client']}): {result['status']}"
                )

            except Exception as e:
                logger.error(f"[ERR] {target['name']} ({target['client']}): {e}")
                results.append(
                    {
                        "target": target,
                        "checks": [],
                        "http_status": None,
                        "response_ms": None,
                        "cert_days_remaining": None,
                        "reason": f"Unexpected error: {str(e)}",
                        "status": "DOWN",
                    }
                )
                max_status = max(max_status, 2)

    return results, max_status
