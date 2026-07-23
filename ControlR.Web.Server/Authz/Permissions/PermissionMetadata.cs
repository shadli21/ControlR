using ControlR.Web.Server.Data.Enums;

namespace ControlR.Web.Server.Authz.Permissions;

public sealed record PermissionMetadata(
  string Name,
  string DisplayName,
  string Description,
  PermissionScopeKind[] DefaultScopeKinds,
  bool IsAssignable);
