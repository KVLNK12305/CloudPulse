resource "azurerm_container_registry" "cloudpulse" {
  name                = "cloudpulseacr01"
  resource_group_name = azurerm_resource_group.cloudpulse.name
  location            = "Central India"

  sku           = "Basic"
  admin_enabled = false

  tags = {
    Project = "cloudpulse"
    Purpose = "container-images"
  }
}