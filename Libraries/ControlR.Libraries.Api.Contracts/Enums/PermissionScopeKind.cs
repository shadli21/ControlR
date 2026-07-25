namespace ControlR.Libraries.Api.Contracts.Enums;

/// <summary>
/// The kind of resource a permission assignment is scoped to.
/// </summary>
public enum PermissionScopeKind
{
  Server,
  Tenant,
  CustomerTenant,
  DeviceGroup,
  Device,
  UserGroup,
  User,
  PersonalAccessToken,
  ServiceAccount
}
