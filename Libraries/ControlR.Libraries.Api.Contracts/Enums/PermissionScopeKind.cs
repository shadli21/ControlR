namespace ControlR.Libraries.Api.Contracts.Enums;

/// <summary>
/// The kind of resource a permission assignment is scoped to.
/// </summary>
public enum PermissionScopeKind
{
  /// <summary>
  /// Sentinel default so an omitted scope kind never silently resolves to a real (and
  /// privileged) scope. No catalog permission allows this kind, so requests that omit the
  /// scope kind are rejected at validation.
  /// </summary>
  Unknown = 0,
  Server = 1,
  Tenant = 2,
  CustomerTenant = 3,
  DeviceGroup = 4,
  Device = 5,
  UserGroup = 6
}
