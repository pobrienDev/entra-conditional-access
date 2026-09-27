# CA007: registering security info requires MFA unless on a trusted network.
#
# An attacker with a stolen password will try to register their own MFA
# method first. This policy targets the "register security info" user action
# rather than an application, and requires MFA everywhere except locations
# marked trusted. A brand-new user with no method yet uses a Temporary Access
# Pass, which satisfies the MFA requirement.

resource "azuread_conditional_access_policy" "ca007" {
  display_name = "CA007-AllUsers-RegisterSecInfo-TrustedOnly"
  state        = local.report_only

  conditions {
    client_app_types = ["all"]

    applications {
      included_user_actions = ["urn:user:registersecurityinfo"]
    }

    locations {
      included_locations = ["All"]
      excluded_locations = ["AllTrusted"]
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

  # Not a reference the provider can infer; makes sure the trusted location
  # exists before a policy that relies on "AllTrusted" is created.
  depends_on = [azuread_named_location.office]
}
