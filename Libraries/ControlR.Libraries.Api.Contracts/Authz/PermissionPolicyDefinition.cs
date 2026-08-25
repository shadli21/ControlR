namespace ControlR.Libraries.Api.Contracts.Authz;

public sealed record PermissionPolicyDefinition(
  string PermissionName,
  PermissionScopeKind ResourceScopeKind = PermissionScopeKind.Tenant);
