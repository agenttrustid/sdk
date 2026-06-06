"""AgentTrust SDK SIEM Streaming Management"""

from typing import Dict, List, Optional

from .models import SIEMDeliveryRecord, SIEMDestination


class StreamingAPI:
    """SIEM streaming destination management API."""

    def __init__(self, http_client):
        self._http = http_client

    def create(
        self,
        name: str,
        destination_type: str,
        endpoint_url: str,
        auth_token: Optional[str] = None,
        batch_size: Optional[int] = None,
        flush_interval_seconds: Optional[int] = None,
        filter_event_types: Optional[List[str]] = None,
    ) -> SIEMDestination:
        data = {
            "name": name,
            "destination_type": destination_type,
            "endpoint_url": endpoint_url,
        }
        if auth_token is not None:
            data["auth_token"] = auth_token
        if batch_size is not None:
            data["batch_size"] = batch_size
        if flush_interval_seconds is not None:
            data["flush_interval_seconds"] = flush_interval_seconds
        if filter_event_types is not None:
            data["filter_event_types"] = filter_event_types

        result = self._http.post("/api/v1/siem/destinations", data)
        return SIEMDestination.from_dict(result)

    def list(self) -> List[SIEMDestination]:
        result = self._http.get("/api/v1/siem/destinations")
        destinations = result.get("destinations", result) if isinstance(result, dict) else result
        if isinstance(destinations, list):
            return [SIEMDestination.from_dict(destination) for destination in destinations]
        return []

    def get(self, destination_id: str) -> SIEMDestination:
        result = self._http.get(f"/api/v1/siem/destinations/{destination_id}")
        return SIEMDestination.from_dict(result)

    def update(
        self,
        destination_id: str,
        *,
        name: Optional[str] = None,
        endpoint_url: Optional[str] = None,
        auth_token: Optional[str] = None,
        is_active: Optional[bool] = None,
        batch_size: Optional[int] = None,
        flush_interval_seconds: Optional[int] = None,
        filter_event_types: Optional[List[str]] = None,
    ) -> SIEMDestination:
        data: Dict = {}
        if name is not None:
            data["name"] = name
        if endpoint_url is not None:
            data["endpoint_url"] = endpoint_url
        if auth_token is not None:
            data["auth_token"] = auth_token
        if is_active is not None:
            data["is_active"] = is_active
        if batch_size is not None:
            data["batch_size"] = batch_size
        if flush_interval_seconds is not None:
            data["flush_interval_seconds"] = flush_interval_seconds
        if filter_event_types is not None:
            data["filter_event_types"] = filter_event_types

        result = self._http.put(f"/api/v1/siem/destinations/{destination_id}", data)
        return SIEMDestination.from_dict(result)

    def delete(self, destination_id: str) -> None:
        self._http.delete(f"/api/v1/siem/destinations/{destination_id}")

    def delivery_log(self, destination_id: str) -> List[SIEMDeliveryRecord]:
        result = self._http.get(f"/api/v1/siem/destinations/{destination_id}/logs")
        logs = result.get("logs", result) if isinstance(result, dict) else result
        if isinstance(logs, list):
            return [SIEMDeliveryRecord.from_dict(log) for log in logs]
        return []

    def test(self, destination_id: str) -> dict:
        return self._http.post(f"/api/v1/siem/destinations/{destination_id}/test")
