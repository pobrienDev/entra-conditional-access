# Trusted named location used by CA007. The ranges live in the gitignored
# terraform.tfvars, never in the repo. Skipped entirely if none are given, in
# which case CA007 still excludes whatever other locations are marked trusted.

resource "azuread_named_location" "office" {
  count = length(var.trusted_ip_ranges) > 0 ? 1 : 0

  display_name = "Trusted-Office"

  ip {
    ip_ranges = var.trusted_ip_ranges
    trusted   = true
  }
}
