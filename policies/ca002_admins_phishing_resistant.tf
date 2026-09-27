# CA002: phishing-resistant MFA for privileged directory roles.
#
# Targets role TEMPLATE ids (identical in every tenant), not the per-tenant
# role objects, so this file works unchanged in any tenant. Authenticator push
# is not enough here: admins must use a passkey, FIDO2 key, Windows Hello for
# Business or certificate, which cannot be phished by a proxy attack.
#
# Do not enforce this until every admin, including you, has registered a
# phishing-resistant method. Report-only first; check the sign-in logs.

resource "azuread_conditional_access_policy" "ca002" {
  display_name = "CA002-Admins-AllApps-PhishingResistant"
  state        = local.report_only

  conditions {
    client_app_types = ["all"]

    applications {
      included_applications = ["All"]
    }

    users {
      included_roles  = local.privileged_roles
      excluded_groups = local.breakglass_exclusions
    }
  }

  grant_controls {
    operator                          = "OR"
    authentication_strength_policy_id = local.phishing_resistant_strength_id
  }
}
