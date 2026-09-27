# Well-known IDs that are identical in every Microsoft Entra tenant. They are
# public Microsoft constants, not tenant data, and are allowlisted for the
# pre-commit GUID check in .githooks/guid-allowlist.

locals {
  # Directory role TEMPLATE ids (not the per-tenant role object ids).
  # CA002 targets these roles with phishing-resistant MFA.
  privileged_roles = [
    "62e90394-69f5-4237-9190-012177145e10", # Global Administrator
    "e8611ab8-c189-46e8-94e1-60213ab1f814", # Privileged Role Administrator
    "194ae4cb-b126-40b2-bd5b-6091b380977d", # Security Administrator
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9", # Conditional Access Administrator
    "fe930be7-5e62-47db-91af-98c3a49a38b1", # User Administrator
  ]

  # Built-in "Phishing-resistant MFA" authentication strength. The azuread 3.x
  # provider expects the full policy path, not the bare GUID.
  phishing_resistant_strength_id = "/policies/authenticationStrengthPolicies/00000000-0000-0000-0000-000000000004"

  # "Windows Azure Service Management API": the portal, CLI and PowerShell.
  # CA004 targets it.
  azure_management_app_id = "797f4846-ba00-4fd7-ba43-dac1f8f63013"

  # Every policy starts here. Changing a policy to "enabled" is a deliberate,
  # reviewed pull request; the guardrails refuse to *create* a policy enabled.
  report_only = "enabledForReportingButNotEnforced"

  # Every policy excludes this group. Enforced by guardrails/check_plan.py,
  # not by memory.
  breakglass_exclusions = [data.azuread_group.breakglass.object_id]
}
