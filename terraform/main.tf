resource "azurerm_resource_group" "cloudpulse" {
  name     = "cloudpulse-rg"
  location = "South India"

  tags = {
    Project        = "cloudpulse"
    telemetry-test = "cloupulse-law-test"
  }
}
