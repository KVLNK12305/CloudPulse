import json
import logging
from typing import List, Dict, Any, Optional
import urllib.request
import urllib.error

from azure.core.exceptions import HttpResponseError, ClientAuthenticationError
from azure.identity import DefaultAzureCredential

try:
    from azure.mgmt.resourcegraph import ResourceGraphClient as SdkClient
    from azure.mgmt.resourcegraph.models import QueryRequest
    _HAS_ARG_SDK = True
except ImportError:
    SdkClient = None  # type: ignore
    QueryRequest = None  # type: ignore
    _HAS_ARG_SDK = False

logger = logging.getLogger("cloudpulse.telemetry.resource_graph")


class ResourceGraphQueryError(Exception):
    """Raised when querying Azure Resource Graph fails."""
    pass


class ResourceGraphPermissionError(ResourceGraphQueryError):
    """Raised when Azure permissions are insufficient for Azure Resource Graph queries."""
    pass


class ResourceGraphClient:
    """
    Client for querying Azure Resource Graph for live topological inventory.
    Uses Managed Identity (cloudpulse-identity) or DefaultAzureCredential.
    Supports both azure-mgmt-resourcegraph SDK and direct ARM REST API execution.
    """

    ARG_ENDPOINT = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01"
    ARM_RESOURCE_URI = "https://management.azure.com/.default"

    NETWORK_TOPOLOGY_KQL = """
Resources
| where type in~ (
    "microsoft.network/publicipaddresses",
    "microsoft.network/networkinterfaces",
    "microsoft.network/networksecuritygroups",
    "microsoft.compute/virtualmachines",
    "microsoft.network/virtualnetworks"
)
| project id, name, type, resourceGroup, subscriptionId, location, properties
""".strip()

    def __init__(self, credential=None, client=None):
        """
        Initialize the Azure Resource Graph client.
        Uses DefaultAzureCredential by default (supporting UserAssigned Managed Identity, Azure CLI, etc.).
        """
        if client is not None:
            self._client = client
            self._credential = credential
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

            if _HAS_ARG_SDK and SdkClient is not None:
                try:
                    self._client = SdkClient(self._credential)
                except Exception as ex:
                    logger.debug("azure-mgmt-resourcegraph initialization deferred, using ARM REST API: %s", str(ex))
                    self._client = None
            else:
                self._client = None

    def query(self, kql: str, subscriptions: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Execute a KQL query against Azure Resource Graph.

        Args:
            kql: Kusto Query Language query string for Resource Graph.
            subscriptions: Optional list of subscription IDs to scope the query.

        Returns:
            List of resource record dictionaries.
        """
        if not kql or not kql.strip():
            raise ResourceGraphQueryError("KQL query cannot be empty")

        logger.info("Executing Azure Resource Graph query (subscriptions: %s)", subscriptions)

        # 1. Try SDK if available
        if self._client is not None and QueryRequest is not None:
            try:
                query_request = QueryRequest(
                    query=kql,
                    subscriptions=subscriptions,
                )
                response = self._client.resources(query_request)
                return self._parse_arg_data(response.data)
            except ClientAuthenticationError as auth_err:
                logger.error("Authentication error accessing Azure Resource Graph: %s", auth_err.message)
                raise ResourceGraphPermissionError(
                    f"Authentication failed for Azure Resource Graph: {auth_err.message}. "
                    "Ensure 'Reader' role is assigned on the subscription or resource group scope."
                ) from auth_err
            except HttpResponseError as http_err:
                if http_err.status_code in (401, 403):
                    msg = (
                        f"Authorization failed for Azure Resource Graph ({http_err.status_code}): {http_err.message}. "
                        "The Managed Identity requires 'Reader' role on the target subscription or resource group."
                    )
                    logger.error(msg)
                    raise ResourceGraphPermissionError(msg) from http_err
                logger.error("HTTP error during Resource Graph query: %s", http_err.message)
                raise ResourceGraphQueryError(f"Resource Graph API error ({http_err.status_code}): {http_err.message}") from http_err
            except Exception as e:
                logger.warning("SDK query failed, falling back to REST API: %s", str(e))

        # 2. ARM REST API fallback
        return self._query_rest(kql, subscriptions)

    def _query_rest(self, kql: str, subscriptions: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        try:
            token = self._credential.get_token(self.ARM_RESOURCE_URI).token
        except Exception as auth_err:
            logger.error("Failed to acquire Azure credential token for Resource Graph: %s", str(auth_err))
            raise ResourceGraphPermissionError(
                f"Failed to acquire bearer token: {str(auth_err)}. "
                "Ensure Managed Identity has 'Reader' permissions."
            ) from auth_err

        payload = {"query": kql}
        if subscriptions:
            payload["subscriptions"] = subscriptions

        req = urllib.request.Request(
            self.ARG_ENDPOINT,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = resp.read().decode("utf-8")
                data = json.loads(body)
                return self._parse_arg_data(data.get("data", data))
        except urllib.error.HTTPError as he:
            if he.code in (401, 403):
                err_body = he.read().decode("utf-8", errors="ignore")
                msg = (
                    f"Insufficient permissions for Azure Resource Graph ({he.code}): {err_body}. "
                    "The Managed Identity requires 'Reader' role on the target subscription or resource group."
                )
                logger.error(msg)
                raise ResourceGraphPermissionError(msg) from he
            err_body = he.read().decode("utf-8", errors="ignore")
            raise ResourceGraphQueryError(f"Resource Graph HTTP error {he.code}: {err_body}") from he
        except Exception as ex:
            raise ResourceGraphQueryError(f"Resource Graph query failed: {str(ex)}") from ex

    @staticmethod
    def _parse_arg_data(data: Any) -> List[Dict[str, Any]]:
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            if "rows" in data and "columns" in data:
                cols = [c["name"] if isinstance(c, dict) else str(c) for c in data["columns"]]
                records = []
                for row in data["rows"]:
                    record = {col: val for col, val in zip(cols, row)}
                    records.append(record)
                return records
            if "data" in data and isinstance(data["data"], list):
                return data["data"]
        return []

    def get_network_topology(self, subscriptions: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Query and construct the live network topology graph containing Public IPs,
        NICs, NSGs, Subnets, and Virtual Machines.
        """
        raw_resources = self.query(self.NETWORK_TOPOLOGY_KQL, subscriptions=subscriptions)

        public_ips: Dict[str, Dict[str, Any]] = {}
        nics: Dict[str, Dict[str, Any]] = {}
        nsgs: Dict[str, Dict[str, Any]] = {}
        vms: Dict[str, Dict[str, Any]] = {}
        subnets: Dict[str, Dict[str, Any]] = {}

        for item in raw_resources:
            r_id = str(item.get("id") or "").lower()
            r_type = str(item.get("type") or "").lower()
            props = item.get("properties") or {}

            if r_type == "microsoft.network/publicipaddresses":
                ip_cfg = props.get("ipConfiguration") or {}
                public_ips[r_id] = {
                    "id": item.get("id"),
                    "name": item.get("name"),
                    "ip_address": props.get("ipAddress"),
                    "ip_configuration_id": ip_cfg.get("id"),
                    "resource_group": item.get("resourceGroup"),
                    "subscription_id": item.get("subscriptionId"),
                    "properties": props,
                }

            elif r_type == "microsoft.network/networkinterfaces":
                ip_configs = props.get("ipConfigurations") or []
                vm_ref = props.get("virtualMachine") or {}
                nsg_ref = props.get("networkSecurityGroup") or {}

                formatted_ip_configs = []
                for cfg in ip_configs:
                    cfg_props = cfg.get("properties") or {}
                    pip_ref = cfg_props.get("publicIPAddress") or {}
                    snet_ref = cfg_props.get("subnet") or {}
                    formatted_ip_configs.append({
                        "id": cfg.get("id"),
                        "name": cfg.get("name"),
                        "public_ip_id": pip_ref.get("id"),
                        "subnet_id": snet_ref.get("id"),
                    })

                nics[r_id] = {
                    "id": item.get("id"),
                    "name": item.get("name"),
                    "vm_id": vm_ref.get("id"),
                    "nsg_id": nsg_ref.get("id"),
                    "ip_configurations": formatted_ip_configs,
                    "resource_group": item.get("resourceGroup"),
                    "subscription_id": item.get("subscriptionId"),
                    "properties": props,
                }

            elif r_type == "microsoft.network/networksecuritygroups":
                security_rules = props.get("securityRules") or []
                nsgs[r_id] = {
                    "id": item.get("id"),
                    "name": item.get("name"),
                    "rules": security_rules,
                    "resource_group": item.get("resourceGroup"),
                    "subscription_id": item.get("subscriptionId"),
                    "properties": props,
                }

            elif r_type == "microsoft.compute/virtualmachines":
                net_profile = props.get("networkProfile") or {}
                nic_refs = [nic.get("id") for nic in (net_profile.get("networkInterfaces") or [])]
                vms[r_id] = {
                    "id": item.get("id"),
                    "name": item.get("name"),
                    "nic_ids": nic_refs,
                    "resource_group": item.get("resourceGroup"),
                    "subscription_id": item.get("subscriptionId"),
                    "properties": props,
                }

            elif r_type == "microsoft.network/virtualnetworks":
                snet_list = props.get("subnets") or []
                for snet in snet_list:
                    s_id = str(snet.get("id") or "").lower()
                    s_props = snet.get("properties") or {}
                    s_nsg = s_props.get("networkSecurityGroup") or {}
                    subnets[s_id] = {
                        "id": snet.get("id"),
                        "name": snet.get("name"),
                        "nsg_id": s_nsg.get("id"),
                        "address_prefix": s_props.get("addressPrefix"),
                    }

        logger.info(
            "Constructed network topology: %d Public IPs, %d NICs, %d NSGs, %d VMs, %d Subnets",
            len(public_ips),
            len(nics),
            len(nsgs),
            len(vms),
            len(subnets),
        )

        return {
            "public_ips": public_ips,
            "nics": nics,
            "nsgs": nsgs,
            "vms": vms,
            "subnets": subnets,
            "raw": raw_resources,
        }

    def get_resource_inventory(
        self,
        subscription_id: Optional[str] = None,
        resource_group: Optional[str] = None,
        resource_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Query Azure Resource Graph for live inventory of all provisioned cloud resources.
        Supports filtering by subscription, resource group, and resource type.
        """
        clauses = ["Resources"]
        if subscription_id:
            cleaned_sub = subscription_id.replace("'", "")
            clauses.append(f"| where subscriptionId =~ '{cleaned_sub}'")
        if resource_group:
            cleaned_rg = resource_group.replace("'", "")
            clauses.append(f"| where resourceGroup =~ '{cleaned_rg}'")
        if resource_type:
            cleaned_type = resource_type.replace("'", "")
            clauses.append(f"| where type =~ '{cleaned_type}'")

        clauses.append(
            "| project id, name, type, location, resourceGroup, subscriptionId, sku, tags, provisioningState=properties.provisioningState, kind"
        )
        clauses.append("| order by tolower(name) asc")
        kql = "\n".join(clauses)

        subs = [subscription_id] if subscription_id else None
        return self.query(kql, subscriptions=subs)

