import pytest
from unittest.mock import MagicMock
from azure.core.exceptions import HttpResponseError

from services.detection_service import DetectionService
from telemetry.log_analytics import LogAnalyticsClient, LogAnalyticsQueryError


def test_detection_service_with_telemetry_client(mock_db, detector, orchestrator, vm_creation_event):
    mock_log_client = MagicMock(spec=LogAnalyticsClient)
    mock_log_client.query_workspace.return_value = [vm_creation_event]

    service = DetectionService(
        db_repo=mock_db,
        log_client=mock_log_client,
        detector=detector,
        orchestrator=orchestrator,
    )

    result = service.run_detection(lookback_minutes=15)
    assert result["status"] == "success"
    assert result["events_analyzed"] == 1
    assert result["findings_detected"] == 1
    assert result["new_findings_persisted"] == 1
    assert result["incidents_created_or_updated"] == 1
    mock_log_client.query_workspace.assert_called_once()


def test_detection_service_propagates_log_analytics_error(mock_db, detector, orchestrator):
    mock_log_client = MagicMock(spec=LogAnalyticsClient)
    mock_log_client.query_workspace.side_effect = LogAnalyticsQueryError("API unreachable")

    service = DetectionService(
        db_repo=mock_db,
        log_client=mock_log_client,
        detector=detector,
        orchestrator=orchestrator,
    )

    with pytest.raises(LogAnalyticsQueryError):
        service.run_detection()
