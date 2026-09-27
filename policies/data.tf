# The break-glass group is created by hand in the portal and only READ here.
# Terraform never owns it, so a bad apply can never delete it or change who
# is in it.

data "azuread_group" "breakglass" {
  object_id        = var.breakglass_group_object_id
  security_enabled = true

  lifecycle {
    # Refuse to plan at all if the group is empty or misnamed. An exclusion
    # group with no members excludes nobody, and every policy would then apply
    # to the emergency accounts too.
    postcondition {
      condition     = length(self.members) >= 2
      error_message = "The break-glass group must contain at least two emergency accounts; it currently has ${length(self.members)}. Fix the group in the portal before applying any policy."
    }

    postcondition {
      condition     = self.display_name == "CA-Exclude-BreakGlass"
      error_message = "breakglass_group_object_id points at \"${self.display_name}\", not CA-Exclude-BreakGlass. Check the variable."
    }
  }
}
