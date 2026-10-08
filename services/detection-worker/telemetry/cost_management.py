import json
import logging
import random
import time
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional

from azure.identity import DefaultAzureCredential

from config import config
from models.cost_record import (
    CostRecord,
    generate_cost_record_id,
    classify_cost_category,
    parse_usage_date,
    extract_arm_metadata,
)

logger = logging.getLogger("cloudpulse.telemetry.cost_management")


class CostManagementQueryError(Exception):
    """Base exception for Cost Management Query API failures."""
    pass


class CostManagementAuthenticationError(CostManagementQueryError):
    """Raised when authentication or token acquisition fails (HTTP 401)."""
    pass


class CostManagementRbacError(CostManagementQueryError):
    """Raised when the Managed Identity lacks the required Cost Management Reader role (HTTP 403)."""
    pass


class CostManagementRateLimitError(CostManagementQueryError):
    """Raised when the Cost Management API rate limit is exhausted (HTTP 429)."""
    pass


class CostManagementBadRequestError(CostManagementQueryError):
    """Raised when the query syntax or scope is invalid (HTTP 400)."""
    pass


class CostManagementNotFoundError(CostManagementQueryError):
    """Raised when the target scope (subscription or resource group) does not exist (HTTP 404)."""
    pass


class CostManagementClient:
    """
    Azure Cost Management Query API client.
    Implements synchronous REST queries, DefaultAzureCredential authentication,
    exponential backoff with jitter, pagination traversal (@nextLink),
    and normalized CostRecord mapping.
    Docs: docs/finops/cost-telemetry.md
    """

    ARM_TOKEN_SCOPE = "https://management.azure.com/.default"
    DEFAULT_API_VERSION = "2023-11-01"

    def __init__(
        self,
        credential=None,
        client_id: Optional[str] = None,
        api_version: Optional[str] = None,
    ):
        self.api_version = api_version or config.COST_QUERY_API_VERSION or self.DEFAULT_API_VERSION
        cid = client_id or config.AZURE_CLIENT_ID
        if credential is not None:
            self._credential = credential
        else:
            if cid:
                self._credential = DefaultAzureCredential(managed_identity_client_id=cid)
            else:
                self._credential = DefaultAzureCredential()

        self._cached_token: Optional[str] = None
        self._token_expires_on: float = 0.0

    def _get_access_token(self, force_refresh: bool = False) -> str:
        """
        Acquire or refresh an OAuth2 Bearer token for Azure Resource Manager.
        """
        now = time.time()
        if not force_refresh and self._cached_token and now < (self._token_expires_on - 300):
            return self._cached_token

        try:
            token_obj = self._credential.get_token(self.ARM_TOKEN_SCOPE)
            self._cached_token = token_obj.token
            self._token_expires_on = float(getattr(token_obj, "expires_on", now + 3600))
            return self._cached_token
        except Exception as ex:
            logger.error("Failed to acquire Azure access token for Cost Management: %s", str(ex))
            raise CostManagementAuthenticationError(f"Azure authentication failed: {str(ex)}") from ex

    @staticmethod
    def build_daily_cost_query_payload(
        start_date: str,
        end_date: str,
        cost_type: str = "ActualCost",
    ) -> Dict[str, Any]:
        """
        Build the standard JSON request payload for daily cost aggregation.
        Docs Section 3.B & 4.A.
        """
        return {
            "type": cost_type,
            "timeframe": "Custom",
            "timePeriod": {
                "from": f"{start_date}T00:00:00Z",
                "to": f"{end_date}T23:59:59Z",
            },
            "dataset": {
                "granularity": "Daily",
                "aggregation": {
                    "totalCost": {
                        "name": "PreTaxCost",
                        "function": "Sum",
                    }
                },
                "grouping": [
                    {"type": "Dimension", "name": "ResourceId"},
                    {"type": "Dimension", "name": "ResourceType"},
                    {"type": "Dimension", "name": "ResourceGroupName"},
                    {"type": "Dimension", "name": "ServiceName"},
                    {"type": "Dimension", "name": "MeterCategory"},
                    {"type": "Dimension", "name": "MeterSubCategory"},
                    {"type": "Dimension", "name": "MeterName"},
                ],
            },
        }

    def query_cost(
        self,
        scope: str,
        query_payload: Dict[str, Any],
        max_pages: int = 10,
    ) -> Dict[str, Any]:
        """
        Execute a POST query against the Cost Management Query API with retry and pagination.
        Canonical URI: POST https://management.azure.com/{scope}/providers/Microsoft.CostManagement/query?api-version=...
        """
        clean_scope = scope.strip().strip("/")
        initial_url = f"https://management.azure.com/{clean_scope}/providers/Microsoft.CostManagement/query?api-version={self.api_version}"

        all_rows: List[List[Any]] = []
        columns: List[Dict[str, Any]] = []
        current_url: Optional[str] = initial_url
        current_payload: Optional[Dict[str, Any]] = query_payload
        page_count = 0

        while current_url and page_count < max_pages:
            page_count += 1
            response_json = self._execute_request_with_retry(
                url=current_url,
                payload=current_payload,
                scope=scope,
            )

            properties = response_json.get("properties", {})
            if not columns:
                columns = properties.get("columns", [])

            rows = properties.get("rows", [])
            all_rows.extend(rows)

            # Check pagination @nextLink
            next_link = (
                properties.get("nextLink")
                or response_json.get("nextLink")
                or response_json.get("@nextLink")
            )
            if next_link:
                logger.info("Cost Management returned pagination link (page %d). Traversing...", page_count)
                current_url = next_link
                # Subsequent pagination requests via nextLink are typically GET or POST without body
                current_payload = None
            else:
                current_url = None

        return {
            "properties": {
                "columns": columns,
                "rows": all_rows,
            }
        }

    def _execute_request_with_retry(
        self,
        url: str,
        payload: Optional[Dict[str, Any]],
        scope: str,
    ) -> Dict[str, Any]:
        """
        Execute single HTTP request with resilience per Section 13.A:
        - 429 Too Many Requests: Exponential backoff with jitter (initial 5s, max 60s, up to 4 retries)
        - 500, 502, 503, 504: Exponential backoff (2s, 4s, 8s, up to 3 retries)
        - Network/Timeout errors: Up to 2 retries (5s delay)
        - 403 Forbidden: CostManagementRbacError (Non-retryable)
        - 401 Unauthorized: Attempt token refresh once, then abort
        - 400 Bad Request: CostManagementBadRequestError (Non-retryable)
        - 404 Not Found: CostManagementNotFoundError (Non-retryable)
        """
        max_rate_limit_retries = 4
        rate_limit_attempts = 0
        max_server_error_retries = 3
        server_error_attempts = 0
        max_network_retries = 2
        network_attempts = 0
        token_refreshed = False

        while True:
            token = self._get_access_token()
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
            body_data = json.dumps(payload).encode("utf-8") if payload is not None else None
            req = urllib.request.Request(
                url=url,
                data=body_data,
                headers=headers,
                method="POST" if body_data is not None else "GET",
            )

            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    resp_bytes = resp.read()
                    return json.loads(resp_bytes.decode("utf-8"))

            except urllib.error.HTTPError as http_err:
                status_code = http_err.code
                error_body = ""
                try:
                    error_body = http_err.read().decode("utf-8")
                except Exception:
                    pass

                # 429 Too Many Requests (Rate Throttling)
                if status_code == 429:
                    rate_limit_attempts += 1
                    if rate_limit_attempts > max_rate_limit_retries:
                        logger.error("Cost Management API rate limit exceeded after %d retries: %s", max_rate_limit_retries, error_body)
                        raise CostManagementRateLimitError(f"Cost Management rate limit exceeded on scope {scope}: {error_body}") from http_err

                    # Parse Retry-After header
                    retry_after_hdr = http_err.headers.get("Retry-After")
                    delay = 5.0 * (2 ** (rate_limit_attempts - 1))
                    if retry_after_hdr and retry_after_hdr.isdigit():
                        delay = float(retry_after_hdr)
                    # Add jitter
                    delay = min(60.0, delay + random.uniform(0.5, 2.0))
                    logger.warning("Cost Management 429 Throttling received. Retrying in %.2fs (attempt %d/%d)", delay, rate_limit_attempts, max_rate_limit_retries)
                    time.sleep(delay)
                    continue

                # 500, 502, 503, 504 Transient Server Errors
                if status_code in (500, 502, 503, 504):
                    server_error_attempts += 1
                    if server_error_attempts > max_server_error_retries:
                        logger.error("Cost Management transient error %d exhausted retries: %s", status_code, error_body)
                        raise CostManagementQueryError(f"Azure Cost Management transient error {status_code}: {error_body}") from http_err

                    delay = 2.0 * (2 ** (server_error_attempts - 1))  # 2s, 4s, 8s
                    logger.warning("Cost Management server error %d. Retrying in %.2fs (attempt %d/%d)", status_code, delay, server_error_attempts, max_server_error_retries)
                    time.sleep(delay)
                    continue

                # 403 Forbidden: Missing RBAC Role (Non-Retryable)
                if status_code == 403:
                    logger.error("Cost Management 403 Forbidden on scope %s: Managed Identity lacks Cost Management Reader. Error: %s", scope, error_body)
                    raise CostManagementRbacError(
                        f"Managed Identity lacks Cost Management Reader role on scope {scope}. "
                        "Ensure role definition 72fafb9e-0641-4937-9268-a42baaa0c913 is assigned."
                    ) from http_err

                # 401 Unauthorized: Expired Token (Retry once with refreshed token)
                if status_code == 401:
                    if not token_refreshed:
                        logger.info("Cost Management returned 401 Unauthorized. Attempting token refresh...")
                        self._get_access_token(force_refresh=True)
                        token_refreshed = True
                        continue
                    logger.error("Cost Management 401 Unauthorized persisted after token refresh: %s", error_body)
                    raise CostManagementAuthenticationError(f"Azure authentication rejected (401): {error_body}") from http_err

                # 400 Bad Request: Invalid Query Syntax (Non-Retryable)
                if status_code == 400:
                    logger.error("Cost Management 400 Bad Request on scope %s: %s", scope, error_body)
                    raise CostManagementBadRequestError(f"Invalid query payload or scope {scope}: {error_body}") from http_err

                # 404 Not Found: Scope does not exist (Non-Retryable)
                if status_code == 404:
                    logger.error("Cost Management 404 Not Found for scope %s: %s", scope, error_body)
                    raise CostManagementNotFoundError(f"Target scope {scope} does not exist: {error_body}") from http_err

                # Any other HTTP error
                logger.error("Cost Management unexpected HTTP error %d: %s", status_code, error_body)
                raise CostManagementQueryError(f"Cost Management query failed with status {status_code}: {error_body}") from http_err

            except urllib.error.URLError as url_err:
                network_attempts += 1
                if network_attempts > max_network_retries:
                    logger.error("Cost Management network failure exhausted retries: %s", str(url_err))
                    raise CostManagementQueryError(f"Network error querying Cost Management: {str(url_err)}") from url_err

                logger.warning("Cost Management network error: %s. Retrying in 5s (attempt %d/%d)", str(url_err), network_attempts, max_network_retries)
                time.sleep(5.0)
                continue

    def normalize_query_response(
        self,
        raw_response: Dict[str, Any],
        default_sub_id: str = "",
        default_rg: str = "",
        cost_type: str = "ActualCost",
        reconciliation_days: int = 3,
    ) -> List[CostRecord]:
        """
        Normalize tabular Azure Cost Management Query API response into CostRecord objects.
        Docs Section 4.A & 4.C.
        """
        props = raw_response.get("properties", {})
        columns = props.get("columns", [])
        rows = props.get("rows", [])

        if not columns or not rows:
            return []

        # Map lowercase column name to row index
        col_map: Dict[str, int] = {}
        for idx, col in enumerate(columns):
            if isinstance(col, dict) and "name" in col:
                col_map[col["name"].strip().lower()] = idx

        # Helper to get value from row by candidate column names
        def get_val(row: List[Any], *col_names: str) -> Any:
            for c in col_names:
                idx = col_map.get(c.lower())
                if idx is not None and idx < len(row):
                    return row[idx]
            return None

        # Determine reference date for provisional flag (within recent 3 days)
        today = datetime.now(timezone.utc).date()
        cutoff_date = (today - timedelta(days=reconciliation_days)).strftime("%Y-%m-%d")

        records: List[CostRecord] = []
        for row in rows:
            raw_cost = get_val(row, "PreTaxCost", "Cost")
            if raw_cost is None:
                continue

            try:
                cost_float = round(float(raw_cost), 4)
            except (ValueError, TypeError):
                cost_float = 0.0

            raw_date = get_val(row, "UsageDate", "BillingMonth", "Date")
            try:
                date_str = parse_usage_date(raw_date)
            except Exception:
                date_str = today.strftime("%Y-%m-%d")

            raw_res_id = get_val(row, "ResourceId")
            raw_res_group = get_val(row, "ResourceGroupName", "ResourceGroup") or default_rg
            raw_service_name = str(get_val(row, "ServiceName") or "UnknownService").strip()
            raw_meter_cat = str(get_val(row, "MeterCategory") or "").strip()
            raw_meter_subcat = get_val(row, "MeterSubCategory")
            raw_meter_name = str(get_val(row, "MeterName") or "StandardMeter").strip()
            raw_quantity = get_val(row, "UsageQuantity", "Quantity")
            try:
                quantity_float = float(raw_quantity) if raw_quantity is not None else 0.0
            except (ValueError, TypeError):
                quantity_float = 0.0

            raw_unit = get_val(row, "UnitOfMeasure", "Unit")
            currency = str(get_val(row, "Currency") or "USD").strip().upper()

            # ARM path metadata parsing
            canonical_id, res_name, res_type, res_group, sub_id = extract_arm_metadata(
                raw_resource_id=str(raw_res_id) if raw_res_id else None,
                default_sub_id=default_sub_id or config.AZURE_SUBSCRIPTION_ID,
                default_rg=str(raw_res_group) if raw_res_group else "",
            )

            # Deterministic cost category
            cost_cat = classify_cost_category(
                resource_type=res_type,
                service_name=raw_service_name,
                meter_category=raw_meter_cat,
            )

            # Deterministic record ID
            record_id = generate_cost_record_id(
                subscription_id=sub_id,
                resource_id=canonical_id,
                meter_name=raw_meter_name,
                usage_date=date_str,
                cost_type=cost_type,
            )

            is_provisional = date_str >= cutoff_date

            record = CostRecord(
                record_id=record_id,
                timestamp=date_str,
                subscription_id=sub_id,
                resource_id=canonical_id,
                resource_group=res_group,
                resource_name=res_name,
                resource_type=res_type,
                service_name=raw_service_name,
                cost_category=cost_cat,
                meter_category=raw_meter_cat,
                meter_subcategory=str(raw_meter_subcat) if raw_meter_subcat else None,
                meter_name=raw_meter_name,
                usage_quantity=quantity_float,
                usage_unit=str(raw_unit) if raw_unit else None,
                actual_cost=cost_float,
                currency=currency,
                cost_type=cost_type,
                is_provisional=is_provisional,
            )
            records.append(record)

        return records

    def get_historical_cost(
        self,
        scope: str,
        lookback_days: int = 14,
        default_sub_id: str = "",
        cost_type: str = "ActualCost",
    ) -> List[CostRecord]:
        """
        Retrieve and normalize historical cost records over closed daily windows [T - lookback_days, T - 1].
        Section 6.B & 14.
        """
        today = datetime.now(timezone.utc).date()
        start_date = (today - timedelta(days=lookback_days)).strftime("%Y-%m-%d")
        end_date = (today - timedelta(days=1)).strftime("%Y-%m-%d")

        query_payload = self.build_daily_cost_query_payload(
            start_date=start_date,
            end_date=end_date,
            cost_type=cost_type,
        )

        response = self.query_cost(scope=scope, query_payload=query_payload)
        return self.normalize_query_response(
            raw_response=response,
            default_sub_id=default_sub_id,
            cost_type=cost_type,
        )

    def validate_rbac(self, scope: str) -> bool:
        """
        Verify that the Managed Identity has Cost Management Reader permissions on the scope.
        Executes a lightweight 1-day query.
        Returns True if successful, False if 403 Forbidden.
        """
        today = datetime.now(timezone.utc).date()
        eval_date = (today - timedelta(days=1)).strftime("%Y-%m-%d")
        test_payload = self.build_daily_cost_query_payload(
            start_date=eval_date,
            end_date=eval_date,
        )
        try:
            self.query_cost(scope=scope, query_payload=test_payload, max_pages=1)
            logger.info("Cost Management Reader RBAC validation succeeded on scope %s", scope)
            return True
        except CostManagementRbacError:
            logger.warning("Cost Management Reader RBAC validation failed on scope %s: 403 Forbidden", scope)
            return False
        except Exception as ex:
            logger.warning("Cost Management validation encountered non-RBAC error on scope %s: %s", scope, str(ex))
            # If error is not 403, might be empty data or network, but RBAC was not denied
            return False
