import logging
from datetime import timedelta
from typing import List, Dict, Any, Optional

from azure.core.exceptions import HttpResponseError, ClientAuthenticationError
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus

logger = logging.getLogger("cloudpulse.telemetry.log_analytics")


class LogAnalyticsQueryError(Exception):
    """Raised when querying Azure Log Analytics fails."""
    pass


class LogAnalyticsClient:
    """
    Client for querying Azure Log Analytics workspaces using Managed Identity or DefaultAzureCredential.
    """

    def __init__(self, credential=None, client: Optional[LogsQueryClient] = None):
        """
        Initialize the Log Analytics client.
        Uses DefaultAzureCredential by default (supporting UserAssigned Managed Identity, Azure CLI, etc.).
        """
        if client is not None:
            self._client = client
        else:
            if credential is not None:
                self._credential = credential
            else:
                from config import config
                if config.AZURE_CLIENT_ID:
                    self._credential = DefaultAzureCredential(
                        managed_identity_client_id=config.AZURE_CLIENT_ID
                    )
                else:
                    self._credential = DefaultAzureCredential()
            self._client = LogsQueryClient(self._credential)

    def query_workspace(
        self,
        workspace_id: str,
        kql: str,
        timespan: Optional[timedelta] = None,
    ) -> List[Dict[str, Any]]:
        """
        Execute a KQL query against the specified Log Analytics workspace.

        Args:
            workspace_id: Customer ID / Workspace GUID or resource ID
            kql: Kusto Query Language query string
            timespan: Optional timedelta lookback window

        Returns:
            List of row dictionaries where keys correspond to column names.
        """
        if not workspace_id:
            raise LogAnalyticsQueryError("workspace_id cannot be empty")
        if not kql or not kql.strip():
            raise LogAnalyticsQueryError("KQL query cannot be empty")

        logger.info(
            "Executing Log Analytics query on workspace %s (timespan: %s)",
            workspace_id,
            timespan,
        )

        try:
            response = self._client.query_workspace(
                workspace_id=workspace_id,
                query=kql,
                timespan=timespan or timedelta(hours=1),
            )

            if response.status == LogsQueryStatus.FAILURE:
                error_msg = f"Log Analytics query failed: {response.partial_error}"
                logger.error(error_msg)
                raise LogAnalyticsQueryError(error_msg)

            results: List[Dict[str, Any]] = []
            for table in response.tables:
                columns = [col for col in table.columns]
                for row in table.rows:
                    record = {col: val for col, val in zip(columns, row)}
                    results.append(record)

            logger.info("Successfully fetched %d records from Log Analytics", len(results))
            return results

        except ClientAuthenticationError as auth_err:
            logger.error("Authentication error accessing Log Analytics workspace: %s", auth_err.message)
            raise LogAnalyticsQueryError(f"Authentication failed for Log Analytics: {auth_err.message}") from auth_err
        except HttpResponseError as http_err:
            logger.error("HTTP error during Log Analytics query: %s (status code %s)", http_err.message, http_err.status_code)
            raise LogAnalyticsQueryError(f"Log Analytics API error ({http_err.status_code}): {http_err.message}") from http_err
        except Exception as ex:
            if isinstance(ex, LogAnalyticsQueryError):
                raise
            logger.error("Unexpected error executing Log Analytics query: %s", str(ex))
            raise LogAnalyticsQueryError(f"Unexpected query error: {str(ex)}") from ex
