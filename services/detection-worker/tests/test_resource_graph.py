import pytest
from unittest.mock import MagicMock, patch
import urllib.error

from telemetry.resource_graph import (
    ResourceGraphClient,
    ResourceGraphQueryError,
    ResourceGraphPermissionError,
)


def test_resource_graph_init_default():
    mock_cred = MagicMock()
    client = ResourceGraphClient(credential=mock_cred)
    assert client._credential == mock_cred


def test_resource_graph_parse_data_shapes():
    # Shape 1: List of dicts
    data_list = [{"id": "/res/1", "name": "res1"}]
    assert ResourceGraphClient._parse_arg_data(data_list) == data_list

    # Shape 2: Dict with rows and columns
    data_table = {
        "columns": [{"name": "id"}, {"name": "name"}],
        "rows": [["/res/1", "res1"], ["/res/2", "res2"]],
    }
    parsed = ResourceGraphClient._parse_arg_data(data_table)
    assert len(parsed) == 2
    assert parsed[0] == {"id": "/res/1", "name": "res1"}
    assert parsed[1] == {"id": "/res/2", "name": "res2"}

    # Shape 3: Dict with nested data list
    data_nested = {"data": [{"id": "/res/3", "name": "res3"}]}
    assert ResourceGraphClient._parse_arg_data(data_nested) == [{"id": "/res/3", "name": "res3"}]


def test_resource_graph_permission_error_handling():
    mock_cred = MagicMock()
    mock_cred.get_token.return_value.token = "fake-token"
    client = ResourceGraphClient(credential=mock_cred)
    client._client = None  # Force REST API path

    # Simulate HTTP 403 Forbidden
    http_error = urllib.error.HTTPError(
        url=client.ARG_ENDPOINT,
        code=403,
        msg="Forbidden",
        hdrs={},
        fp=MagicMock(read=lambda: b'{"error":{"code":"AuthorizationFailed","message":"The client does not have authorization."}}'),
    )

    with patch("urllib.request.urlopen", side_effect=http_error):
        with pytest.raises(ResourceGraphPermissionError) as exc_info:
            client.query("Resources | project id")

        assert "Reader" in str(exc_info.value)
        assert "403" in str(exc_info.value)


def test_get_network_topology_parsing():
    mock_cred = MagicMock()
    client = ResourceGraphClient(credential=mock_cred)

    mock_resources = [
        {
            "id": "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Network/publicIPAddresses/pip1",
            "name": "pip1",
            "type": "microsoft.network/publicipaddresses",
            "resourceGroup": "rg1",
            "subscriptionId": "sub1",
            "properties": {
                "ipAddress": "20.1.2.3",
                "ipConfiguration": {
                    "id": "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Network/networkInterfaces/nic1/ipConfigurations/ipconfig1"
                },
            },
        },
        {
            "id": "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Network/networkInterfaces/nic1",
            "name": "nic1",
            "type": "microsoft.network/networkinterfaces",
            "resourceGroup": "rg1",
            "subscriptionId": "sub1",
            "properties": {
                "virtualMachine": {"id": "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1"},
                "networkSecurityGroup": {"id": "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Network/networkSecurityGroups/nsg1"},
                "ipConfigurations": [
                    {
                        "id": "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Network/networkInterfaces/nic1/ipConfigurations/ipconfig1",
                        "properties": {
                            "publicIPAddress": {"id": "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Network/publicIPAddresses/pip1"},
                            "subnet": {"id": "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/vnet1/subnets/snet-app"},
                        },
                    }
                ],
            },
        },
        {
            "id": "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Network/networkSecurityGroups/nsg1",
            "name": "nsg1",
            "type": "microsoft.network/networksecuritygroups",
            "resourceGroup": "rg1",
            "subscriptionId": "sub1",
            "properties": {
                "securityRules": [
                    {
                        "name": "Allow-SSH",
                        "properties": {
                            "direction": "Inbound",
                            "access": "Allow",
                            "protocol": "Tcp",
                            "sourceAddressPrefix": "0.0.0.0/0",
                            "destinationPortRange": "22",
                        },
                    }
                ]
            },
        },
    ]

    with patch.object(client, "query", return_value=mock_resources):
        topology = client.get_network_topology()
        assert len(topology["public_ips"]) == 1
        assert len(topology["nics"]) == 1
        assert len(topology["nsgs"]) == 1
        pip = topology["public_ips"][list(topology["public_ips"].keys())[0]]
        assert pip["ip_address"] == "20.1.2.3"
