using System.Collections.Immutable;

namespace ControlR.Web.Server.Authz.Permissions;

public sealed record PermissionMetadata(
  string Name,
  string DisplayName,
  string Description,
  ImmutableArray<PermissionScopeKind> AllowedScopeKinds,
  bool SelfRemovable = true);
