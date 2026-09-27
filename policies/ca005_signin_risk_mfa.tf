# CA005: medium or high sign-in risk requires MFA, re-evaluated every sign-in.
#
# Sign-in risk is Identity Protection's judgement of a single authentication:
# anonymous IP, impossible travel, unfamiliar sign-in properties, leaked
# credentials in use. Passing MFA remediates the risk for that sign-in. Sign-in
# frequency "every time" stops a previously issued session from carrying a
# risky sign-in through without a fresh challenge.
#
# Needs Entra ID P2. Starts in report-only.

resource "azuread_conditional_access_policy" "ca005" {
  display_name = "CA005-AllUsers-SignInRiskMedHigh-MFA"
  state        = local.report_only

  conditions {
    client_app_types    = ["all"]
    sign_in_risk_levels = ["medium", "high"]

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

  session_controls {
    sign_in_frequency_interval = "everyTime"
  }
}
