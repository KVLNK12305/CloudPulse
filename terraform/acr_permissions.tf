resource "azurerm_role_assignment" "cloudpulse_acr_pull" {
  scope                = azurerm_container_registry.cloudpulse.id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_user_assigned_identity.cloudpulse.principal_id
}