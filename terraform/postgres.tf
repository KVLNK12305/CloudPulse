resource "azurerm_private_dns_zone" "postgres" {
  name                = "private.postgres.database.azure.com"
  resource_group_name = azurerm_resource_group.cloudpulse.name

  tags = {
    Project = "cloudpulse"
    Purpose = "postgres-private-dns"
  }
}

resource "azurerm_private_dns_zone_virtual_network_link" "postgres" {
  name                  = "cloudpulse-postgres-dns-link"
  resource_group_name   = azurerm_resource_group.cloudpulse.name
  private_dns_zone_name = azurerm_private_dns_zone.postgres.name
  virtual_network_id    = azurerm_virtual_network.cloudpulse.id
}

resource "azurerm_postgresql_flexible_server" "cloudpulse" {
  name                = "cloudpulse-postgres01"
  resource_group_name = azurerm_resource_group.cloudpulse.name
  location            = "Central India"
  version             = "16"
  zone                = "2"
  delegated_subnet_id = azurerm_subnet.data.id
  private_dns_zone_id = azurerm_private_dns_zone.postgres.id

  administrator_login    = "cloudpulseadmin"
  administrator_password = var.postgres_admin_password

  storage_mb   = 32768
  storage_tier = "P4"
  sku_name     = "B_Standard_B1ms"

  backup_retention_days = 7

  public_network_access_enabled = false

  lifecycle {
    ignore_changes = [
      administrator_password
    ]
  }

  tags = {
    Project = "cloudpulse"
    Purpose = "application-database"
  }
}

resource "azurerm_postgresql_flexible_server_database" "cloudpulse" {
  name      = "cloudpulse"
  server_id = azurerm_postgresql_flexible_server.cloudpulse.id
  charset   = "UTF8"
  collation = "en_US.utf8"
}