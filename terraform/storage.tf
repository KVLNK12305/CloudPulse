resource "azurerm_storage_account" "cloudpulse" {
  name                     = "cloudpulseraw01"
  resource_group_name      = azurerm_resource_group.cloudpulse.name
  location                 = "Central India"
  account_tier             = "Standard"
  account_replication_type = "LRS"

  min_tls_version = "TLS1_2"

  allow_nested_items_to_be_public = false

  blob_properties {
    versioning_enabled = true
  }

  tags = {
    Project = "cloudpulse"
    Purpose = "raw-telemetry-archive"
  }
}

resource "azurerm_storage_container" "raw_activity" {
  name                  = "raw-activity"
  storage_account_id    = azurerm_storage_account.cloudpulse.id
  container_access_type = "private"
}

resource "azurerm_storage_container" "raw_network" {
  name                  = "raw-network"
  storage_account_id    = azurerm_storage_account.cloudpulse.id
  container_access_type = "private"
}

resource "azurerm_storage_container" "raw_metrics" {
  name                  = "raw-metrics"
  storage_account_id    = azurerm_storage_account.cloudpulse.id
  container_access_type = "private"
}

resource "azurerm_storage_container" "raw_cost" {
  name                  = "raw-cost"
  storage_account_id    = azurerm_storage_account.cloudpulse.id
  container_access_type = "private"
}

resource "azurerm_storage_container" "normalized_network" {
  name                  = "normalized-network"
  storage_account_id    = azurerm_storage_account.cloudpulse.id
  container_access_type = "private"
}

resource "azurerm_storage_container" "normalized_identity" {
  name                  = "normalized-identity"
  storage_account_id    = azurerm_storage_account.cloudpulse.id
  container_access_type = "private"
}

resource "azurerm_storage_container" "normalized_cost" {
  name                  = "normalized-cost"
  storage_account_id    = azurerm_storage_account.cloudpulse.id
  container_access_type = "private"
}

resource "azurerm_storage_container" "incidents" {
  name                  = "incidents"
  storage_account_id    = azurerm_storage_account.cloudpulse.id
  container_access_type = "private"
}
