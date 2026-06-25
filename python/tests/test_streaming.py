"""Coverage for StreamingAPI (SIEM destination management, public surface)."""
from unittest.mock import MagicMock

from agenttrustid.streaming import StreamingAPI


_DEST = {"id": "d1", "name": "n", "destination_type": "webhook", "endpoint_url": "https://x"}


def _api():
    http = MagicMock()
    return StreamingAPI(http), http


def test_create_with_all_optional_fields():
    api, http = _api()
    http.post.return_value = _DEST
    api.create(
        name="n", destination_type="webhook", endpoint_url="https://x",
        auth_token="t", batch_size=10, flush_interval_seconds=5,
        filter_event_types=["a"],
    )
    path, data = http.post.call_args[0]
    assert path == "/api/v1/siem/destinations"
    assert data["auth_token"] == "t"
    assert data["batch_size"] == 10
    assert data["flush_interval_seconds"] == 5
    assert data["filter_event_types"] == ["a"]


def test_list_returns_destinations_and_empty_on_non_list():
    api, http = _api()
    http.get.return_value = {"destinations": [_DEST]}
    assert len(api.list()) == 1
    http.get.return_value = {"unexpected": "x"}
    assert api.list() == []


def test_get():
    api, http = _api()
    http.get.return_value = _DEST
    api.get("d1")
    http.get.assert_called_with("/api/v1/siem/destinations/d1")


def test_update_builds_payload():
    api, http = _api()
    http.put.return_value = _DEST
    api.update(
        "d1", name="new", is_active=False, batch_size=20,
        endpoint_url="https://y", auth_token="z",
        flush_interval_seconds=7, filter_event_types=["b"],
    )
    path, data = http.put.call_args[0]
    assert path == "/api/v1/siem/destinations/d1"
    assert data["name"] == "new"
    assert data["is_active"] is False
    assert data["batch_size"] == 20
    assert data["filter_event_types"] == ["b"]


def test_delete():
    api, http = _api()
    api.delete("d1")
    http.delete.assert_called_with("/api/v1/siem/destinations/d1")


def test_delivery_log_returns_records_and_empty_on_non_list():
    api, http = _api()
    http.get.return_value = {"logs": [{"id": "l1"}]}
    assert len(api.delivery_log("d1")) == 1
    http.get.return_value = {"unexpected": "x"}
    assert api.delivery_log("d1") == []


def test_test_endpoint():
    api, http = _api()
    http.post.return_value = {"ok": True}
    assert api.test("d1") == {"ok": True}
    http.post.assert_called_with("/api/v1/siem/destinations/d1/test")
