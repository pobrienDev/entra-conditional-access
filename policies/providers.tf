# Pinned to an explicit tenant rather than inheriting whatever `az login`
# session is active. Conditional Access is the tenant's front door; if the CLI
# is logged into the wrong tenant, plan fails instead of targeting it.
#
# In CI the workflow sets ARM_USE_OIDC=true and ARM_CLIENT_ID, and the provider
# exchanges GitHub's OIDC token for a Graph token. No client secret exists.
provider "azuread" {
  tenant_id = var.tenant_id
}
