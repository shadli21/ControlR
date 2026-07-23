using ControlR.Web.Server.Data.Enums;

namespace ControlR.Web.Server.Authz.Permissions;

public sealed record ResourceDescriptor(
  PermissionScopeKind Kind,
  Guid? Id = null,
  Guid? TenantId = null);
