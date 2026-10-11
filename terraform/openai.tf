resource "azurerm_cognitive_account" "cloudpulse_openai" {
  name                = "cloudpulse-openai01"
  location            = "southeastasia"
  resource_group_name = azurerm_resource_group.cloudpulse.name
  kind                = "OpenAI"
  sku_name            = "S0"

  identity {
    type = "SystemAssigned"
  }

  tags = {
    Project = "cloudpulse"
    Purpose = "ai-advisory-triage"
  }
}

resource "azurerm_cognitive_deployment" "cloudpulse_triage" {
  name                 = "cloudpulse-triage"
  cognitive_account_id = azurerm_cognitive_account.cloudpulse_openai.id

  model {
    format  = "OpenAI"
    name    = "gpt-4.1-mini"
    version = "2025-04-14"
  }

  sku {
    name     = "GlobalStandard"
    capacity = 8
  }
}

resource "azurerm_role_assignment" "cloudpulse_openai_user" {
  scope                = azurerm_cognitive_account.cloudpulse_openai.id
  role_definition_name = "Cognitive Services OpenAI User"
  principal_id         = azurerm_user_assigned_identity.cloudpulse.principal_id
}
