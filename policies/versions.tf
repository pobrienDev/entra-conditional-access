terraform {
  required_version = ">= 1.9"

  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.9"
    }
  }

  # Remote state in the same locked-down storage account entra-terraform
  # bootstrapped, under its own key. Partial configuration: the account name
  # is supplied at init from the gitignored backend.tfbackend, so it never
  # lands in this public repo.
  #
  #   terraform init -backend-config=backend.tfbackend
  backend "azurerm" {}
}
