data "azurerm_client_config" "current" {}

resource "azurerm_virtual_network" "cloudpulse" {
  name                = "cloudpulse-vnet"
  location            = "Central India"
  resource_group_name = azurerm_resource_group.cloudpulse.name
  address_space       = ["10.50.0.0/16"]
}

resource "azurerm_subnet" "edge" {
  name                              = "snet-edge"
  resource_group_name               = azurerm_resource_group.cloudpulse.name
  virtual_network_name              = azurerm_virtual_network.cloudpulse.name
  address_prefixes                  = ["10.50.1.0/24"]
  default_outbound_access_enabled   = false
  private_endpoint_network_policies = "Disabled"
}

resource "azurerm_subnet" "app" {
  name                              = "snet-app"
  resource_group_name               = azurerm_resource_group.cloudpulse.name
  virtual_network_name              = azurerm_virtual_network.cloudpulse.name
  address_prefixes                  = ["10.50.2.0/24"]
  default_outbound_access_enabled   = false
  private_endpoint_network_policies = "Disabled"
}

resource "azurerm_subnet" "worker" {
  name                              = "snet-worker"
  resource_group_name               = azurerm_resource_group.cloudpulse.name
  virtual_network_name              = azurerm_virtual_network.cloudpulse.name
  address_prefixes                  = ["10.50.3.0/24"]
  default_outbound_access_enabled   = false
  private_endpoint_network_policies = "Disabled"
}

resource "azurerm_subnet" "data" {
  name                 = "snet-data"
  resource_group_name  = azurerm_resource_group.cloudpulse.name
  virtual_network_name = azurerm_virtual_network.cloudpulse.name
  address_prefixes     = ["10.50.4.0/24"]

  private_endpoint_network_policies = "Disabled"
  default_outbound_access_enabled   = false

  service_endpoints = [
    "Microsoft.Storage",
  ]

  delegation {
    name = "postgresql-flexible-server"

    service_delegation {
      name = "Microsoft.DBforPostgreSQL/flexibleServers"

      actions = [
        "Microsoft.Network/virtualNetworks/subnets/join/action",
      ]
    }
  }
}

resource "azurerm_subnet_network_security_group_association" "edge" {
  subnet_id                 = azurerm_subnet.edge.id
  network_security_group_id = "/subscriptions/${data.azurerm_client_config.current.subscription_id}/resourceGroups/cloudpulse-rg/providers/Microsoft.Network/networkSecurityGroups/sg-edge"
}

resource "azurerm_subnet_network_security_group_association" "app" {
  subnet_id                 = azurerm_subnet.app.id
  network_security_group_id = "/subscriptions/${data.azurerm_client_config.current.subscription_id}/resourceGroups/cloudpulse-rg/providers/Microsoft.Network/networkSecurityGroups/nsg-app"
}

resource "azurerm_subnet_network_security_group_association" "worker" {
  subnet_id                 = azurerm_subnet.worker.id
  network_security_group_id = "/subscriptions/${data.azurerm_client_config.current.subscription_id}/resourceGroups/cloudpulse-rg/providers/Microsoft.Network/networkSecurityGroups/nsg-worker"
}

resource "azurerm_subnet_network_security_group_association" "data" {
  subnet_id                 = azurerm_subnet.data.id
  network_security_group_id = "/subscriptions/${data.azurerm_client_config.current.subscription_id}/resourceGroups/cloudpulse-rg/providers/Microsoft.Network/networkSecurityGroups/nsg-data"
}
