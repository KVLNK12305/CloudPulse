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

# Reader on resource group (ARG queries, resource enumeration)
resource "azurerm_role_assignment" "cloudpulse_rg_reader" {
  scope                = azurerm_resource_group.cloudpulse.id
  role_definition_name = "Reader"
  principal_id         = azurerm_user_assigned_identity.cloudpulse.principal_id
}

# Cost Management Reader on subscription (FinOps telemetry)
resource "azurerm_role_assignment" "cloudpulse_cost_reader" {
  scope                = "/subscriptions/${data.azurerm_client_config.current.subscription_id}"
  role_definition_name = "Cost Management Reader"
  principal_id         = azurerm_user_assigned_identity.cloudpulse.principal_id
}

# Custom remediation role (NSG rule CRUD only — least privilege)
resource "azurerm_role_definition" "cloudpulse_remediation_operator" {
  name        = "CloudPulse-Remediation-Operator"
  scope       = azurerm_resource_group.cloudpulse.id
  description = "Least-privilege role for CloudPulse controlled remediation on NSG rules."

  permissions {
    actions = [
      "Microsoft.Network/networkSecurityGroups/read",
      "Microsoft.Network/networkSecurityGroups/securityRules/read",
      "Microsoft.Network/networkSecurityGroups/securityRules/write",
      "Microsoft.Network/networkSecurityGroups/securityRules/delete",
    ]
    not_actions = []
  }

  assignable_scopes = [azurerm_resource_group.cloudpulse.id]
}

resource "azurerm_role_assignment" "cloudpulse_remediation" {
  scope              = azurerm_resource_group.cloudpulse.id
  role_definition_id = azurerm_role_definition.cloudpulse_remediation_operator.role_definition_resource_id
  principal_id       = azurerm_user_assigned_identity.cloudpulse.principal_id
}
