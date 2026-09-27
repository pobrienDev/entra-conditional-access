# CA003: block legacy authentication for everyone.
#
# Legacy protocols (Exchange ActiveSync, IMAP, POP, SMTP AUTH, older Office
# clients) cannot perform MFA, so CA001's MFA requirement never applies to
# them: an attacker with a stolen password can walk straight in. Blocking is
# the only control that works, which is why this is a separate policy rather
# than a condition on CA001.
#
# Starts in report-only. Legacy sign-ins show up in the sign-in logs as
# "report-only: failure" before anything is actually blocked.

resource "azuread_conditional_access_policy" "ca003" {
  display_name = "CA003-AllUsers-LegacyAuth-Block"
  state        = local.report_only

  conditions {
    # Only legacy clients. Modern browsers and mobile apps are untouched.
    client_app_types = ["exchangeActiveSync", "other"]

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
    built_in_controls = ["block"]
  }
}
