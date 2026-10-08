resource "azurerm_user_assigned_identity" "cloudpulse" {
  name                = "cloudpulse-identity"
  location            = "Central India"
  resource_group_name = azurerm_resource_group.cloudpulse.name

  tags = {
    Project = "cloudpulse"
    Purpose = "runtime-identity"
  }
}
resource "azurerm_role_assignment" "cloudpulse_keyvault_secrets_user" {
  scope                = azurerm_key_vault.cloudpulse.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.cloudpulse.principal_id
}

resource "azurerm_role_assignment" "cloudpulse_log_analytics_reader" {
  scope                = azurerm_log_analytics_workspace.cloudpulse.id
  role_definition_name = "Log Analytics Reader"
  principal_id         = azurerm_user_assigned_identity.cloudpulse.principal_id
}
