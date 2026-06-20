"""Coverage for the SDK HTTP client error handling.

Every SDK call flows through HTTPClient.request, so its status-code -> exception
mapping is part of the public contract.
"""
import io
import ssl
import urllib.error
import warnings

import pytest
from unittest.mock import patch

from agenttrustid.client import HTTPClient
from agenttrustid.exceptions import (
    AuthenticationError,
    AuthorizationError,
    AgentTrustError,
    ValidationError,
    NetworkError,
)


class _Resp:
    """Minimal context-manager response stub."""

    def __init__(self, body=b""):
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def _http_error(code, body=b'{"message":"nope"}'):
    return urllib.error.HTTPError("http://t/x", code, "err", {}, io.BytesIO(body))


def test_verify_tls_false_warns_and_disables():
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        http = HTTPClient("http://t", verify_tls=False)
    assert any("insecure" in str(w.message).lower() for w in caught)
    assert http._ssl_context.verify_mode == ssl.CERT_NONE
    assert http._ssl_context.check_hostname is False


def test_set_auth_and_api_key():
    http = HTTPClient("http://t")
    http.set_auth("tok")
    http.set_api_key("sk")
    assert http.headers["Authorization"] == "Bearer tok"
    assert http.headers["X-API-Key"] == "sk"


def test_request_empty_body_returns_empty_dict():
    http = HTTPClient("http://t")
    with patch("urllib.request.urlopen", return_value=_Resp(b"")):
        assert http.request("GET", "/x") == {}


@pytest.mark.parametrize(
    "code,exc,err_code",
    [
        (401, AuthenticationError, "AUTH_FAILED"),
        (403, AuthorizationError, "AUTH_DENIED"),
        (404, AgentTrustError, "NOT_FOUND"),
        (400, ValidationError, "VALIDATION_ERROR"),
        (500, AgentTrustError, "HTTP_500"),
    ],
)
def test_http_errors_map_to_exceptions(code, exc, err_code):
    http = HTTPClient("http://t")
    with patch("urllib.request.urlopen", side_effect=_http_error(code)):
        with pytest.raises(exc) as ei:
            http.request("GET", "/x")
    assert ei.value.code == err_code


def test_http_error_non_json_body_uses_raw_text():
    http = HTTPClient("http://t")
    with patch("urllib.request.urlopen", side_effect=_http_error(400, b"plain text error")):
        with pytest.raises(ValidationError) as ei:
            http.request("GET", "/x")
    assert "plain text error" in str(ei.value)


def test_url_error_maps_to_network_error():
    http = HTTPClient("http://t")
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("boom")):
        with pytest.raises(NetworkError):
            http.request("GET", "/x")
