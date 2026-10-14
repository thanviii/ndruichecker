"""Unit tests for checks module."""

import json
import socket
import ssl
from unittest.mock import Mock, patch, MagicMock

import pytest
import requests

from ndr_checker.checks import (
    parse_url,
    check_dns,
    check_tcp,
    check_tls,
    check_https,
    run_checks,
)


class TestParseUrl:
    """Tests for URL parsing."""

    def test_parse_url_with_default_port(self):
        hostname, port = parse_url("https://example.com/path")
        assert hostname == "example.com"
        assert port == 443

    def test_parse_url_with_custom_port(self):
        hostname, port = parse_url("https://example.com:8443/path")
        assert hostname == "example.com"
        assert port == 8443

    def test_parse_url_invalid(self):
        with pytest.raises(ValueError):
            parse_url("https:///")


class TestDnsCheck:
    """Tests for DNS resolution check."""

    @patch("socket.getaddrinfo")
    def test_dns_success(self, mock_getaddrinfo):
        result = check_dns("https://example.com")
        assert result["check"] == "dns"
        assert result["status"] == "pass"
        assert result["reason"] is None
        assert "elapsed_ms" in result

    @patch("socket.getaddrinfo")
    def test_dns_failure(self, mock_getaddrinfo):
        mock_getaddrinfo.side_effect = socket.gaierror("Name or service not known")
        result = check_dns("https://invalid-host-12345.example.com")
        assert result["check"] == "dns"
        assert result["status"] == "fail"
        assert "DNS resolution failed" in result["reason"]

    def test_dns_ip_address(self):
        result = check_dns("https://192.168.1.1")
        assert result["check"] == "dns"
        assert result["status"] == "pass"
        assert result["reason"] is None


class TestTcpCheck:
    """Tests for TCP connectivity check."""

    @patch("socket.socket")
    def test_tcp_success(self, mock_socket_class):
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        result = check_tcp("https://example.com", timeout=10)
        assert result["check"] == "tcp"
        assert result["status"] == "pass"
        assert result["reason"] is None
        mock_socket.connect.assert_called_once()
        mock_socket.close.assert_called_once()

    @patch("socket.socket")
    def test_tcp_timeout(self, mock_socket_class):
        mock_socket = MagicMock()
        mock_socket.connect.side_effect = socket.timeout()
        mock_socket_class.return_value = mock_socket
        result = check_tcp("https://example.com", timeout=10)
        assert result["check"] == "tcp"
        assert result["status"] == "fail"
        assert "TCP timeout" in result["reason"]

    @patch("socket.socket")
    def test_tcp_connection_refused(self, mock_socket_class):
        mock_socket = MagicMock()
        mock_socket.connect.side_effect = ConnectionRefusedError("Connection refused")
        mock_socket_class.return_value = mock_socket
        result = check_tcp("https://example.com", timeout=10)
        assert result["check"] == "tcp"
        assert result["status"] == "fail"
        assert "TCP connection failed" in result["reason"]


class TestTlsCheck:
    """Tests for TLS handshake check."""

    @patch("ndr_checker.checks.ssl.create_default_context")
    @patch("socket.create_connection")
    def test_tls_success(self, mock_create_conn, mock_ssl_context):
        # Mock SSL context
        mock_context = MagicMock()
        mock_ssl_context.return_value = mock_context

        # Mock socket
        mock_sock = MagicMock()
        mock_create_conn.return_value.__enter__ = Mock(return_value=mock_sock)
        mock_create_conn.return_value.__exit__ = Mock(return_value=None)

        # Mock wrapped socket
        mock_wrapped = MagicMock()
        mock_wrapped.getpeercert.return_value = {"notAfter": "May 15 10:34:59 2025 GMT"}
        mock_context.wrap_socket.return_value.__enter__ = Mock(return_value=mock_wrapped)
        mock_context.wrap_socket.return_value.__exit__ = Mock(return_value=None)

        result = check_tls("https://example.com", timeout=10, verify_tls=True)
        assert result["check"] == "tls"
        assert result["status"] == "pass"
        assert result["reason"] is None
        assert result["cert_days_remaining"] is not None

    @patch("socket.create_connection")
    def test_tls_ssl_error(self, mock_create_conn):
        mock_create_conn.side_effect = ssl.SSLError("certificate verify failed")
        result = check_tls("https://example.com", timeout=10, verify_tls=True)
        assert result["check"] == "tls"
        assert result["status"] == "fail"
        assert "TLS" in result["reason"]


class TestHttpsCheck:
    """Tests for HTTPS request check."""

    @patch("requests.get")
    def test_https_success_200(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        result = check_https(
            "https://example.com",
            timeout=10,
            expected_status=[200, 301, 401],
            verify_tls=True,
        )
        assert result["check"] == "https"
        assert result["status"] == "pass"
        assert result["http_status"] == 200
        assert result["reason"] is None

    @patch("requests.get")
    def test_https_redirect_301(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 301
        mock_get.return_value = mock_response

        result = check_https(
            "https://example.com",
            timeout=10,
            expected_status=[200, 301, 401],
            verify_tls=True,
        )
        assert result["check"] == "https"
        assert result["status"] == "pass"
        assert result["http_status"] == 301

    @patch("requests.get")
    def test_https_unexpected_status(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 503
        mock_get.return_value = mock_response

        result = check_https(
            "https://example.com",
            timeout=10,
            expected_status=[200, 301, 401],
            verify_tls=True,
        )
        assert result["check"] == "https"
        assert result["status"] == "fail"
        assert result["http_status"] == 503
        assert "HTTP 503" in result["reason"]

    @patch("requests.get")
    def test_https_timeout(self, mock_get):
        mock_get.side_effect = requests.Timeout("Request timeout")
        result = check_https(
            "https://example.com",
            timeout=10,
            expected_status=[200],
            verify_tls=True,
        )
        assert result["check"] == "https"
        assert result["status"] == "fail"
        assert "timeout" in result["reason"].lower()

    @patch("requests.get")
    def test_https_request_exception(self, mock_get):
        mock_get.side_effect = requests.RequestException("Connection error")
        result = check_https(
            "https://example.com",
            timeout=10,
            expected_status=[200],
            verify_tls=True,
        )
        assert result["check"] == "https"
        assert result["status"] == "fail"


class TestRunChecks:
    """Tests for full check sequence."""

    @patch("ndr_checker.checks.check_dns")
    @patch("ndr_checker.checks.check_tcp")
    @patch("ndr_checker.checks.check_tls")
    @patch("ndr_checker.checks.check_https")
    def test_all_checks_pass(
        self, mock_https, mock_tls, mock_tcp, mock_dns
    ):
        mock_dns.return_value = {"check": "dns", "status": "pass", "reason": None, "elapsed_ms": 10}
        mock_tcp.return_value = {"check": "tcp", "status": "pass", "reason": None, "elapsed_ms": 20}
        mock_tls.return_value = {
            "check": "tls",
            "status": "pass",
            "reason": None,
            "cert_days_remaining": 90,
            "elapsed_ms": 50,
        }
        mock_https.return_value = {
            "check": "https",
            "status": "pass",
            "reason": None,
            "http_status": 200,
            "elapsed_ms": 100,
        }

        target = {
            "client": "Test Corp",
            "name": "Test Console",
            "url": "https://example.com",
            "verify_tls": True,
            "timeout": 10,
            "expected_status": [200, 301, 401],
            "tags": [],
        }

        result = run_checks(target)
        assert result["status"] == "UP"
        assert result["reason"] is None
        assert result["http_status"] == 200
        assert result["cert_days_remaining"] == 90

    @patch("ndr_checker.checks.check_dns")
    @patch("ndr_checker.checks.check_tcp")
    @patch("ndr_checker.checks.check_tls")
    @patch("ndr_checker.checks.check_https")
    def test_dns_failure(self, mock_https, mock_tls, mock_tcp, mock_dns):
        mock_dns.return_value = {
            "check": "dns",
            "status": "fail",
            "reason": "DNS resolution failed",
            "elapsed_ms": 5000,
        }

        target = {
            "client": "Test Corp",
            "name": "Test Console",
            "url": "https://invalid.example.com",
            "verify_tls": True,
            "timeout": 10,
            "expected_status": [200],
            "tags": [],
        }

        result = run_checks(target)
        assert result["status"] == "DOWN"
        assert "DNS resolution failed" in result["reason"]
        mock_tcp.assert_not_called()
        mock_tls.assert_not_called()
        mock_https.assert_not_called()

    @patch("ndr_checker.checks.check_dns")
    @patch("ndr_checker.checks.check_tcp")
    @patch("ndr_checker.checks.check_tls")
    @patch("ndr_checker.checks.check_https")
    def test_cert_expiry_warning(
        self, mock_https, mock_tls, mock_tcp, mock_dns
    ):
        mock_dns.return_value = {"check": "dns", "status": "pass", "reason": None, "elapsed_ms": 10}
        mock_tcp.return_value = {"check": "tcp", "status": "pass", "reason": None, "elapsed_ms": 20}
        mock_tls.return_value = {
            "check": "tls",
            "status": "pass",
            "reason": None,
            "cert_days_remaining": 15,  # Less than 30-day warning threshold
            "elapsed_ms": 50,
        }
        mock_https.return_value = {
            "check": "https",
            "status": "pass",
            "reason": None,
            "http_status": 200,
            "elapsed_ms": 100,
        }

        target = {
            "client": "Test Corp",
            "name": "Test Console",
            "url": "https://example.com",
            "verify_tls": True,
            "timeout": 10,
            "expected_status": [200],
            "cert_warn_days": 30,
            "tags": [],
        }

        result = run_checks(target)
        assert result["status"] == "WARN"
        assert "expires in 15 days" in result["reason"]

    @patch("ndr_checker.checks.check_dns")
    @patch("ndr_checker.checks.check_tcp")
    @patch("ndr_checker.checks.check_tls")
    @patch("ndr_checker.checks.check_https")
    def test_response_time_warning(
        self, mock_https, mock_tls, mock_tcp, mock_dns
    ):
        mock_dns.return_value = {"check": "dns", "status": "pass", "reason": None, "elapsed_ms": 10}
        mock_tcp.return_value = {"check": "tcp", "status": "pass", "reason": None, "elapsed_ms": 20}
        mock_tls.return_value = {
            "check": "tls",
            "status": "pass",
            "reason": None,
            "cert_days_remaining": 90,
            "elapsed_ms": 50,
        }
        mock_https.return_value = {
            "check": "https",
            "status": "pass",
            "reason": None,
            "http_status": 200,
            "elapsed_ms": 6000,  # Exceeds 5000ms threshold
        }

        target = {
            "client": "Test Corp",
            "name": "Test Console",
            "url": "https://example.com",
            "verify_tls": True,
            "timeout": 10,
            "expected_status": [200],
            "response_warn_ms": 5000,
            "tags": [],
        }

        result = run_checks(target)
        assert result["status"] == "WARN"
        assert "exceeds threshold" in result["reason"]
