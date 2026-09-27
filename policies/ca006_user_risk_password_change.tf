# CA006: high user risk requires MFA AND a password change, every sign-in.
#
# User risk is Identity Protection's judgement that the account itself is
# probably compromised, most often because its credentials turned up in a
# leak. The remediation is a new password, and the operator is AND because a
# password change must be paired with MFA: the password is the very thing
# suspected of being in an attacker's hands, so it cannot be the only proof.
#
# Needs Entra ID P2. Starts in report-only.

resource "azuread_conditional_access_policy" "ca006" {
  display_name = "CA006-AllUsers-UserRiskHigh-PasswordChange"
  state        = local.report_only

  conditions {
    client_app_types = ["all"]
    user_risk_levels = ["high"]

    applications {
      included_applications = ["All"]
    }

    users {
      included_users  = ["All"]
      excluded_groups = local.breakglass_exclusions
    }
  }

  grant_controls {
    operator          = "AND"
    built_in_controls = ["mfa", "passwordChange"]
  }

  session_controls {
    sign_in_frequency_interval = "everyTime"
  }
}
