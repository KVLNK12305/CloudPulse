resource "azurerm_key_vault" "cloudpulse" {
  name                = "cloudpulse-kv01"
  location            = "Central India"
  resource_group_name = azurerm_resource_group.cloudpulse.name
  tenant_id           = data.azurerm_client_config.current.tenant_id

  sku_name = "standard"

  purge_protection_enabled   = true
  soft_delete_retention_days = 7

  public_network_access_enabled = true

  tags = {
    Project = "cloudpulse"
    Purpose = "secrets-management"
  }
}

