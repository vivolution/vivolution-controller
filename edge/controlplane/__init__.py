"""Deterministic first-tenant CP1 desired-state materializer."""

from .core import (
    DIRECT_ROUTING_CONNECTOR_RESOURCE_ID,
    DIRECT_ROUTING_DEPLOYMENT_MODE,
    DIRECT_ROUTING_LISTENER_RESOURCE_ID,
    DIRECT_ROUTING_MICROSOFT_TARGETS,
    DIRECT_ROUTING_PBX_TO_TEAMS_ROUTE_ID,
    DIRECT_ROUTING_PROFILE_KIND,
    DIRECT_ROUTING_TEAMS_TO_PBX_ROUTE_ID,
    ControlPlaneError,
    FirstTenantProfile,
    MaterializedRelease,
    generate_private_seed,
    materialize_first_tenant,
)

__all__ = [
    "ControlPlaneError",
    "DIRECT_ROUTING_CONNECTOR_RESOURCE_ID",
    "DIRECT_ROUTING_DEPLOYMENT_MODE",
    "DIRECT_ROUTING_LISTENER_RESOURCE_ID",
    "DIRECT_ROUTING_MICROSOFT_TARGETS",
    "DIRECT_ROUTING_PBX_TO_TEAMS_ROUTE_ID",
    "DIRECT_ROUTING_PROFILE_KIND",
    "DIRECT_ROUTING_TEAMS_TO_PBX_ROUTE_ID",
    "FirstTenantProfile",
    "MaterializedRelease",
    "generate_private_seed",
    "materialize_first_tenant",
]
