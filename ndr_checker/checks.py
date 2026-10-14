"""Health checks: DNS, TCP, TLS, HTTPS."""

import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning


def parse_url(url: str) -> tuple[str, int]:
    """Extract hostname and port from HTTPS URL."""
    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or 443
    if not hostname:
        raise ValueError(f"Invalid URL: {url}")
    return hostname, port


def check_dns(url: str) -> Dict[str, Any]:
    """Check DNS resolution.

    Returns:
        {
            "check": "dns",
            "status": "pass" | "fail",
            "reason": str or None,
            "elapsed_ms": int
        }
    """
    start = time.perf_counter()
    try:
        hostname, _ = parse_url(url)

        # Skip if hostname is already an IP
        try:
            socket.inet_aton(hostname)
            elapsed = (time.perf_counter() - start) * 1000
            return {
                "check": "dns",
                "status": "pass",
                "reason": None,
                "elapsed_ms": int(elapsed),
            }
        except socket.error:
            pass

        # Resolve hostname
        socket.getaddrinfo(hostname, None)
        elapsed = (time.perf_counter() - start) * 1000
        return {
            "check": "dns",
            "status": "pass",
            "reason": None,
            "elapsed_ms": int(elapsed),
        }
    except Exception as e:
        elapsed = (time.perf_counter() - start) * 1000
        return {
            "check": "dns",
            "status": "fail",
            "reason": f"DNS resolution failed: {str(e)}",
            "elapsed_ms": int(elapsed),
        }


def check_tcp(url: str, timeout: int) -> Dict[str, Any]:
    """Check TCP connectivity.

    Returns:
        {
            "check": "tcp",
            "status": "pass" | "fail",
            "reason": str or None,
            "elapsed_ms": int
        }
    """
    start = time.perf_counter()
    try:
        hostname, port = parse_url(url)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((hostname, port))
        finally:
            sock.close()

        elapsed = (time.perf_counter() - start) * 1000
        return {
            "check": "tcp",
            "status": "pass",
            "reason": None,
            "elapsed_ms": int(elapsed),
        }
    except socket.timeout:
        elapsed = (time.perf_counter() - start) * 1000
        return {
            "check": "tcp",
            "status": "fail",
            "reason": "TCP timeout",
            "elapsed_ms": int(elapsed),
        }
    except Exception as e:
        elapsed = (time.perf_counter() - start) * 1000
        return {
            "check": "tcp",
            "status": "fail",
            "reason": f"TCP connection failed: {str(e)}",
            "elapsed_ms": int(elapsed),
        }


def _parse_cert_expiry_from_notafter(not_after: str) -> Optional[int]:
    """Parse notAfter string and return days remaining, or None on failure."""
    try:
        date_parts = not_after.split()
        cert_expiry = datetime.strptime(f"{' '.join(date_parts[:4])}", "%b %d %H:%M:%S %Y")
        cert_expiry = cert_expiry.replace(tzinfo=timezone.utc)
        return (cert_expiry - datetime.now(timezone.utc)).days
    except (ValueError, IndexError, AttributeError):
        return None


def _parse_cert_expiry_from_der(der_bytes: bytes) -> Optional[int]:
    """Extract days remaining from a DER-encoded certificate.

    Uses ssl.DER_cert_to_PEM_cert + ssl._ssl._test_decode_cert (CPython)
    as a best-effort fallback for unverified connections where
    getpeercert() returns {}.
    """
    try:
        import tempfile
        pem = ssl.DER_cert_to_PEM_cert(der_bytes)
        # Write PEM to a temp file so _ssl can parse it
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False, mode="w") as f:
            f.write(pem)
            tmp_path = f.name
        try:
            cert = ssl._ssl._test_decode_cert(tmp_path)
        finally:
            import os
            os.unlink(tmp_path)
        not_after = cert.get("notAfter")
        if not_after:
            return _parse_cert_expiry_from_notafter(not_after)
    except Exception:
        pass
    return None


def check_tls(
    url: str, timeout: int, verify_tls: bool = True
) -> Dict[str, Any]:
    """Check TLS handshake and extract certificate expiry.

    When verify_tls is False, connects without chain validation but still
    reads the certificate to report expiry days.

    Returns:
        {
            "check": "tls",
            "status": "pass" | "fail",
            "reason": str or None,
            "cert_days_remaining": int or None,
            "elapsed_ms": int
        }
    """
    start = time.perf_counter()
    try:
        hostname, port = parse_url(url)

        context = ssl.create_default_context()
        context.check_hostname = verify_tls
        context.verify_mode = ssl.CERT_REQUIRED if verify_tls else ssl.CERT_NONE

        days_remaining = None

        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()  # {} when CERT_NONE
                if cert:
                    not_after = cert.get("notAfter")
                    if not_after:
                        days_remaining = _parse_cert_expiry_from_notafter(not_after)
                else:
                    # CERT_NONE: getpeercert() returns {}, use binary form
                    der = ssock.getpeercert(binary_form=True)
                    if der:
                        days_remaining = _parse_cert_expiry_from_der(der)

        elapsed = (time.perf_counter() - start) * 1000
        return {
            "check": "tls",
            "status": "pass",
            "reason": None,
            "cert_days_remaining": days_remaining,
            "elapsed_ms": int(elapsed),
        }

    except ssl.SSLError as e:
        elapsed = (time.perf_counter() - start) * 1000
        return {
            "check": "tls",
            "status": "fail",
            "reason": f"TLS: {str(e)}",
            "cert_days_remaining": None,
            "elapsed_ms": int(elapsed),
        }
    except Exception as e:
        elapsed = (time.perf_counter() - start) * 1000
        return {
            "check": "tls",
            "status": "fail",
            "reason": f"TLS handshake failed: {str(e)}",
            "cert_days_remaining": None,
            "elapsed_ms": int(elapsed),
        }


def check_https(
    url: str,
    timeout: int,
    expected_status: list[int],
    verify_tls: bool = True,
    proxy: Optional[str] = None,
) -> Dict[str, Any]:
    """Check HTTPS GET request and response.

    Returns:
        {
            "check": "https",
            "status": "pass" | "fail",
            "reason": str or None,
            "http_status": int or None,
            "elapsed_ms": int
        }
    """
    start = time.perf_counter()

    # Suppress InsecureRequestWarning if verify_tls is False
    if not verify_tls:
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    try:
        proxies = None
        if proxy:
            proxies = {"https": proxy}

        response = requests.get(
            url,
            timeout=timeout,
            verify=verify_tls,
            allow_redirects=True,
            proxies=proxies,
        )

        elapsed = (time.perf_counter() - start) * 1000

        status_code = response.status_code
        if status_code in expected_status:
            return {
                "check": "https",
                "status": "pass",
                "reason": None,
                "http_status": status_code,
                "elapsed_ms": int(elapsed),
            }
        else:
            return {
                "check": "https",
                "status": "fail",
                "reason": f"HTTP {status_code} (expected {expected_status})",
                "http_status": status_code,
                "elapsed_ms": int(elapsed),
            }

    except requests.Timeout:
        elapsed = (time.perf_counter() - start) * 1000
        return {
            "check": "https",
            "status": "fail",
            "reason": "HTTPS request timeout",
            "http_status": None,
            "elapsed_ms": int(elapsed),
        }
    except requests.RequestException as e:
        elapsed = (time.perf_counter() - start) * 1000
        return {
            "check": "https",
            "status": "fail",
            "reason": f"HTTPS request failed: {str(e)}",
            "http_status": None,
            "elapsed_ms": int(elapsed),
        }
    except Exception as e:
        elapsed = (time.perf_counter() - start) * 1000
        return {
            "check": "https",
            "status": "fail",
            "reason": f"HTTPS check failed: {str(e)}",
            "http_status": None,
            "elapsed_ms": int(elapsed),
        }


def run_checks(target: Dict[str, Any]) -> Dict[str, Any]:
    """Run all checks for a target in order.

    Returns result dict with all check results and aggregated status.
    """
    url = target["url"]
    timeout = target["timeout"]
    verify_tls = target["verify_tls"]
    expected_status = target["expected_status"]
    proxy = target.get("proxy")

    results = {
        "target": target,
        "checks": [],
        "http_status": None,
        "response_ms": None,
        "cert_days_remaining": None,
        "reason": None,
        "status": "UP",
    }

    # 1. DNS check
    dns_result = check_dns(url)
    results["checks"].append(dns_result)
    if dns_result["status"] == "fail":
        results["status"] = "DOWN"
        results["reason"] = dns_result["reason"]
        return results

    # 2. TCP check
    tcp_result = check_tcp(url, timeout)
    results["checks"].append(tcp_result)
    if tcp_result["status"] == "fail":
        results["status"] = "DOWN"
        results["reason"] = tcp_result["reason"]
        return results

    # 3. TLS check — best-effort cert expiry extraction. A failure here
    #    does NOT block the HTTPS check because requests/urllib3 may
    #    negotiate TLS differently than the raw ssl module.
    tls_result = check_tls(url, timeout, verify_tls=verify_tls)
    results["checks"].append(tls_result)
    results["cert_days_remaining"] = tls_result.get("cert_days_remaining")

    if tls_result["status"] == "fail":
        # Record the TLS issue but continue to the HTTPS check
        results["tls_reason"] = tls_result["reason"]

    # 4. HTTPS check
    https_result = check_https(url, timeout, expected_status, verify_tls, proxy)
    results["checks"].append(https_result)
    results["http_status"] = https_result.get("http_status")
    results["response_ms"] = https_result.get("elapsed_ms")

    if https_result["status"] == "fail":
        results["status"] = "DOWN"
        results["reason"] = https_result["reason"]
        return results

    # HTTPS succeeded — determine final status based on warnings
    # TLS handshake failed but HTTPS worked (requests negotiated differently)
    tls_reason = results.pop("tls_reason", None)
    if tls_reason:
        results["status"] = "WARN"
        results["reason"] = f"TLS probe failed ({tls_reason}) but HTTPS reachable"

    if results["cert_days_remaining"] is not None:
        cert_warn_days = target.get("cert_warn_days", 30)
        if results["cert_days_remaining"] < 0:
            results["status"] = "WARN"
            results["reason"] = f"Certificate expired {abs(results['cert_days_remaining'])} days ago"
        elif results["cert_days_remaining"] < cert_warn_days:
            results["status"] = "WARN"
            results["reason"] = f"Certificate expires in {results['cert_days_remaining']} days"

    # Check response time warning
    response_warn_ms = target.get("response_warn_ms", 5000)
    if results["response_ms"] and results["response_ms"] > response_warn_ms:
        if results["status"] != "DOWN":
            results["status"] = "WARN"
            results["reason"] = f"Response time {results['response_ms']}ms exceeds threshold {response_warn_ms}ms"

    return results
