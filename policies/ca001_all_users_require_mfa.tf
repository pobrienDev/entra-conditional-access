# CA001: require MFA for all users on all apps.
#
# The baseline everything else layers on. CA004 looks redundant next to it
# (Azure management is one of "all apps") and that is deliberate: if someone
# later adds an exclusion here, CA004 still protects the management plane.
#
# Starts in report-only. Sign-ins that would have been challenged show as
# "report-only: failure" in the sign-in logs until this is enforced.

resource "azuread_conditional_access_policy" "ca001" {
  display_name = "CA001-AllUsers-AllApps-RequireMFA"
  state        = local.report_only

  conditions {
    client_app_types = ["all"]

    applications {
      included_applications = ["All"]
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
