# Agent Definitions
#
# This folder contains reusable, versioned Agent Definitions (role-based agents).
# Organizations reference agents by URI in their Organization Manifests.
#
# Domain Orgs (routing-only)
# - Domain org manifests under `orgs/domains/` reference `domain_router_lead` as a
#   non-executing org_lead placeholder so Flo Prime can route:
#   Flo Prime -> Domain Org -> Org Lead
