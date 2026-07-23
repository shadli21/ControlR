namespace ControlR.Web.Server.Data.Enums;

/// <summary>
/// The kind of resource a permission assignment is scoped to. Stored as a human-readable
/// string in the database via EF conversion so that raw DB inspection is readable.
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
