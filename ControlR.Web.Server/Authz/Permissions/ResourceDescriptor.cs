namespace ControlR.Web.Server.Authz.Permissions;

public sealed record ResourceDescriptor(
  PermissionScopeKind Kind,
  Guid? Id = null,
  Guid? TenantId = null,
  Guid? CustomerId = null,
  IReadOnlyCollection<Guid>? DeviceGroupIds = null);
