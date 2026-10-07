terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }

  backend "azurerm" {
    resource_group_name  = "cloudpulse-rg"
    storage_account_name = "cloudpulsetfstate01"
    container_name       = "tfstate"
    key                  = "cloudpulse.tfstate"
  }
}

provider "azurerm" {
  features {}
}
