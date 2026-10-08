import logging
import time
from typing import Optional, Dict, Any, List

from azure.identity import DefaultAzureCredential
from azure.core.exceptions import (
    ResourceNotFoundError,
    ClientAuthenticationError,
    HttpResponseError,
    ResourceExistsError,
)
from config import config

logger = logging.getLogger("cloudpulse.services.azure_network_client")


class AzureNetworkError(Exception):
    """Base exception for Azure Network client errors."""
    pass


class AzureNetworkAuthError(AzureNetworkError):
    """Raised on authentication or permission failure (401/403)."""
    pass


class AzureNetworkNotFoundError(AzureNetworkError):
    """Raised when target NSG or security rule does not exist (404)."""
    pass


class AzureNetworkConflictError(AzureNetworkError):
    """Raised on concurrent write conflict (409)."""
    pass


class AzureNetworkClient:
    """
    Dedicated client for interacting with Azure Network Security Groups and Rules.
    Restricted strictly to the minimal read/write/delete operations required for CloudPulse remediation.
    Uses DefaultAzureCredential (Managed Identity) and azure-mgmt-network.
    """

    def __init__(
        self,
        subscription_id: Optional[str] = None,
        credential=None,
        network_client=None,
    ):
        self.subscription_id = subscription_id or config.AZURE_SUBSCRIPTION_ID

        if credential is not None:
            self._credential = credential
        else:
            if config.AZURE_CLIENT_ID:
                self._credential = DefaultAzureCredential(managed_identity_client_id=config.AZURE_CLIENT_ID)
            else:
                self._credential = DefaultAzureCredential()

        if network_client is not None:
            self._client = network_client
        else:
            try:
                from azure.mgmt.network import NetworkManagementClient
                self._client = NetworkManagementClient(
                    credential=self._credential,
                    subscription_id=self.subscription_id,
                )
            except Exception as e:
                logger.warning("Failed to initialize live NetworkManagementClient: %s", str(e))
                self._client = None

    def get_security_rule(
        self,
        resource_group_name: str,
        network_security_group_name: str,
        security_rule_name: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Read a specific security rule from Azure ARM.
        Returns a normalized dict of rule properties or None if not found.
        """
        if not self._client:
            raise AzureNetworkError("NetworkManagementClient is not initialized")

        try:
            rule_obj = self._client.security_rules.get(
                resource_group_name=resource_group_name,
                network_security_group_name=network_security_group_name,
                security_rule_name=security_rule_name,
            )
            return self._normalize_rule(rule_obj)
        except ResourceNotFoundError:
            return None
        except ClientAuthenticationError as cae:
            logger.error("Authentication failed querying security rule %s: %s", security_rule_name, str(cae))
            raise AzureNetworkAuthError(f"Azure authentication/authorization failed: {str(cae)}") from cae
        except HttpResponseError as hre:
            if hre.status_code == 404:
                return None
            if hre.status_code in (401, 403):
                raise AzureNetworkAuthError(f"Insufficient permissions on NSG {network_security_group_name}: {str(hre)}") from hre
            raise AzureNetworkError(f"Azure API error reading security rule: {str(hre)}") from hre
        except Exception as ex:
            raise AzureNetworkError(f"Unexpected error getting security rule {security_rule_name}: {str(ex)}") from ex

    def list_security_rules(
        self,
        resource_group_name: str,
        network_security_group_name: str,
    ) -> List[Dict[str, Any]]:
        """
        List all security rules attached to an NSG.
        """
        if not self._client:
            raise AzureNetworkError("NetworkManagementClient is not initialized")

        try:
            rules_iter = self._client.security_rules.list(
                resource_group_name=resource_group_name,
                network_security_group_name=network_security_group_name,
            )
            return [self._normalize_rule(r) for r in rules_iter]
        except ResourceNotFoundError:
            raise AzureNetworkNotFoundError(f"NSG '{network_security_group_name}' not found in '{resource_group_name}'")
        except ClientAuthenticationError as cae:
            raise AzureNetworkAuthError(f"Azure authentication failed: {str(cae)}") from cae
        except HttpResponseError as hre:
            if hre.status_code == 404:
                raise AzureNetworkNotFoundError(f"NSG '{network_security_group_name}' not found") from hre
            if hre.status_code in (401, 403):
                raise AzureNetworkAuthError(f"Insufficient permissions: {str(hre)}") from hre
            raise AzureNetworkError(f"Error listing security rules: {str(hre)}") from hre
        except Exception as ex:
            raise AzureNetworkError(f"Unexpected error listing security rules: {str(ex)}") from ex

    def create_or_update_security_rule(
        self,
        resource_group_name: str,
        network_security_group_name: str,
        security_rule_name: str,
        rule_parameters: Dict[str, Any],
        etag: Optional[str] = None,
        max_retries: int = 3,
    ) -> Dict[str, Any]:
        """
        Create or update a security rule.
        When etag is provided, it is attached to rule_parameters['etag'] and passed
        as an HTTP 'If-Match' header for ARM optimistic concurrency control.
        If etag is provided and a 409/412 conflict occurs, AzureNetworkConflictError
        is raised immediately so the caller (RemediationService) can re-read live state
        and revalidate preconditions.
        When etag is not provided (e.g. initial rule creation or legacy calls),
        bounded retries with backoff are performed on transient 409 conflicts.
        """
        if not self._client:
            raise AzureNetworkError("NetworkManagementClient is not initialized")

        extra_kwargs: Dict[str, Any] = {}
        if etag is not None:
            rule_parameters["etag"] = etag
            extra_kwargs["headers"] = {"If-Match": etag}

        payload: Any = rule_parameters
        if isinstance(rule_parameters, dict) and "properties" not in rule_parameters:
            try:
                from azure.mgmt.network.models import SecurityRule
                clean_params = {k: v for k, v in rule_parameters.items() if k not in ("id", "etag")}
                sec_rule = SecurityRule(**clean_params)
                if etag is not None:
                    sec_rule.etag = etag
                payload = sec_rule
            except Exception:
                payload = rule_parameters

        for attempt in range(max_retries):
            try:
                poller = self._client.security_rules.begin_create_or_update(
                    resource_group_name=resource_group_name,
                    network_security_group_name=network_security_group_name,
                    security_rule_name=security_rule_name,
                    security_rule_parameters=payload,
                    **extra_kwargs,
                )
                result = poller.result()
                return self._normalize_rule(result)
            except ClientAuthenticationError as cae:
                raise AzureNetworkAuthError(f"Authorization failed on rule update: {str(cae)}") from cae
            except HttpResponseError as hre:
                if hre.status_code in (401, 403):
                    raise AzureNetworkAuthError(f"Authorization failed: {str(hre)}") from hre
                if hre.status_code == 404:
                    raise AzureNetworkNotFoundError(f"Target NSG not found: {str(hre)}") from hre
                if hre.status_code in (409, 412) or isinstance(hre, ResourceExistsError):
                    if etag is not None:
                        # ETag concurrency constraint violated; fail immediately to let caller re-read and revalidate
                        raise AzureNetworkConflictError(
                            f"Concurrent write conflict on rule '{security_rule_name}': {str(hre)}"
                        ) from hre
                    if attempt + 1 < max_retries:
                        time.sleep(1)
                        continue
                    raise AzureNetworkConflictError(
                        f"Concurrent write conflict on rule '{security_rule_name}': {str(hre)}"
                    ) from hre
                raise AzureNetworkError(f"HTTP error creating/updating security rule: {str(hre)}") from hre
            except Exception as ex:
                raise AzureNetworkError(f"Unexpected error updating security rule: {str(ex)}") from ex

    def delete_security_rule(
        self,
        resource_group_name: str,
        network_security_group_name: str,
        security_rule_name: str,
    ) -> bool:
        """
        Delete a security rule from an NSG. Idempotent: returns True if deleted or already absent.
        """
        if not self._client:
            raise AzureNetworkError("NetworkManagementClient is not initialized")

        try:
            poller = self._client.security_rules.begin_delete(
                resource_group_name=resource_group_name,
                network_security_group_name=network_security_group_name,
                security_rule_name=security_rule_name,
            )
            poller.result()
            return True
        except ResourceNotFoundError:
            return True
        except ClientAuthenticationError as cae:
            raise AzureNetworkAuthError(f"Authorization failed on rule deletion: {str(cae)}") from cae
        except HttpResponseError as hre:
            if hre.status_code == 404:
                return True
            if hre.status_code in (401, 403):
                raise AzureNetworkAuthError(f"Authorization failed: {str(hre)}") from hre
            raise AzureNetworkError(f"Error deleting security rule: {str(hre)}") from hre
        except Exception as ex:
            raise AzureNetworkError(f"Unexpected error deleting security rule: {str(ex)}") from ex

    @staticmethod
    def _normalize_rule(rule_obj: Any) -> Dict[str, Any]:
        """Convert SDK SecurityRule model or dictionary into normalized dict."""
        if isinstance(rule_obj, dict):
            return rule_obj

        def _val(attr_name: str, default: Any = None) -> Any:
            v = getattr(rule_obj, attr_name, default)
            if hasattr(v, "value"):
                return v.value
            return v

        d = {
            "name": getattr(rule_obj, "name", None),
            "id": getattr(rule_obj, "id", None),
            "etag": getattr(rule_obj, "etag", None),
            "priority": getattr(rule_obj, "priority", None),
            "direction": str(_val("direction", "Inbound")),
            "access": str(_val("access", "Allow")),
            "protocol": str(_val("protocol", "*")),
            "source_port_range": getattr(rule_obj, "source_port_range", None),
            "destination_port_range": getattr(rule_obj, "destination_port_range", None),
            "source_address_prefix": getattr(rule_obj, "source_address_prefix", None),
            "destination_address_prefix": getattr(rule_obj, "destination_address_prefix", None),
            "description": getattr(rule_obj, "description", None),
        }
        return {k: v for k, v in d.items() if v is not None}
