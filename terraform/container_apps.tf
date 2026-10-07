resource "azurerm_container_app_environment" "cloudpulse" {
  name                = "cloudpulse-env"
  resource_group_name = azurerm_resource_group.cloudpulse.name
  location            = "Central India"

  log_analytics_workspace_id = azurerm_log_analytics_workspace.cloudpulse.id

  workload_profile {
    name                  = "Consumption"
    workload_profile_type = "Consumption"
    minimum_count         = 0
    maximum_count         = 0
  }

  tags = {
    Project = "cloudpulse"
    Purpose = "container-apps-runtime"
  }
}

resource "azurerm_container_app" "detection_worker" {
  name                         = "cloudpulse-detection-worker"
  container_app_environment_id = azurerm_container_app_environment.cloudpulse.id
  resource_group_name          = azurerm_resource_group.cloudpulse.name
  revision_mode                = "Single"
  workload_profile_name        = "Consumption"

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.cloudpulse.id]
  }

  registry {
    server   = azurerm_container_registry.cloudpulse.login_server
    identity = azurerm_user_assigned_identity.cloudpulse.id
  }

  template {
    container {
      name   = "detection-worker"
      image  = "${azurerm_container_registry.cloudpulse.login_server}/detection-worker:v1"
      cpu    = 0.25
      memory = "0.5Gi"
    }

    min_replicas = 1
    max_replicas = 1
  }

  ingress {
    external_enabled = true
    target_port      = 8080
    transport        = "http"

    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }

  lifecycle {
    ignore_changes = [
      template[0].cooldown_period_in_seconds,
      template[0].polling_interval_in_seconds
    ]
  }

  depends_on = [
    azurerm_role_assignment.cloudpulse_acr_pull
  ]
}