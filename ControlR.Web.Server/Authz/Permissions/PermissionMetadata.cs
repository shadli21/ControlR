namespace ControlR.Web.Server.Authz.Permissions;

public sealed record PermissionMetadata(
  string Name,
  string DisplayName,
  string Description,
  PermissionScopeKind[] AllowedScopeKinds,
  bool SelfRemovable = true);
