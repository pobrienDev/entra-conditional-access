# CA004: require MFA for Azure management.
#
# Targets the "Windows Azure Service Management API" application, which is
# what the Azure portal, Azure CLI and Azure PowerShell all authenticate to.
# CA001 already covers it, so this is a deliberate second layer: an exclusion
# added to CA001 later does not silently expose the management plane.

resource "azuread_conditional_access_policy" "ca004" {
  display_name = "CA004-AllUsers-AzureMgmt-RequireMFA"
  state        = local.report_only

  conditions {
    client_app_types = ["all"]

    applications {
      included_applications = [local.azure_management_app_id]
    }

    users {
      included_users  = ["All"]
      excluded_groups = local.breakglass_exclusions
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["mfa"]
  }
}
