# No defaults on the ID variables, on purpose: values live in the gitignored
# terraform.tfvars locally and in GitHub Actions secrets in CI. Nothing
# tenant-specific is ever committed.

variable "tenant_id" {
  description = "Entra ID tenant the policies are deployed to."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$", lower(var.tenant_id)))
    error_message = "tenant_id must be a GUID."
  }
}

variable "breakglass_group_object_id" {
  description = "Object ID of the CA-Exclude-BreakGlass security group. Created by hand and only ever read by Terraform, so no apply can delete it or change its members."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$", lower(var.breakglass_group_object_id)))
    error_message = "breakglass_group_object_id must be a GUID."
  }
}

variable "trusted_ip_ranges" {
  description = "CIDR ranges for the Trusted-Office named location (CA007). Empty list skips creating the named location."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for r in var.trusted_ip_ranges : can(cidrhost(r, 0))])
    error_message = "Every entry in trusted_ip_ranges must be a valid CIDR, e.g. 203.0.113.0/24."
  }
}
