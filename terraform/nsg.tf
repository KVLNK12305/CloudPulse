resource "azurerm_network_security_group" "edge" {
  name                = "sg-edge"
  location            = "Central India"
  resource_group_name = azurerm_resource_group.cloudpulse.name
}

resource "azurerm_network_security_group" "app" {
  name                = "nsg-app"
  location            = "Central India"
  resource_group_name = azurerm_resource_group.cloudpulse.name
}

resource "azurerm_network_security_group" "worker" {
  name                = "nsg-worker"
  location            = "Central India"
  resource_group_name = azurerm_resource_group.cloudpulse.name
}

resource "azurerm_network_security_group" "data" {
  name                = "nsg-data"
  location            = "Central India"
  resource_group_name = azurerm_resource_group.cloudpulse.name
}

resource "azurerm_network_security_rule" "edge_https" {
  name                        = "Allow-HTTPS-Inbound"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "443"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  description                 = "Allow public HTTPS access to the CloudPulse edge tier"
  resource_group_name         = azurerm_resource_group.cloudpulse.name
  network_security_group_name = azurerm_network_security_group.edge.name
}
