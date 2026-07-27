namespace ControlR.Web.Client.Authz;

/// <summary>
/// Single source of truth mapping each permission-based policy to the permission name it
/// requires. The server registers these policies against the permission evaluator; the
/// Blazor client registers them as permission-claim checks (the client cannot run the
/// server-side evaluator). The server emits the user's effective permissions as claims of
/// type <see cref="PermissionClaimType"/> so the client-side checks succeed.
/// </summary>
public static class PermissionPolicies
{
  public const string PermissionClaimType = "controlr:permission";

  public static IReadOnlyDictionary<string, string> PolicyToPermission { get; } =
    new Dictionary<string, string>
    {
      [PolicyNames.RequireCustomersRead] = PermissionNames.TenantCustomersRead,
      [PolicyNames.RequireCustomersWrite] = PermissionNames.TenantCustomersWrite,
      [PolicyNames.RequireDeviceGroupAssignDevices] = PermissionNames.DeviceGroupAssignDevices,
      [PolicyNames.RequireDeviceGroupsRead] = PermissionNames.TenantDeviceGroupsRead,
      [PolicyNames.RequireDeviceGroupsWrite] = PermissionNames.TenantDeviceGroupsWrite,
      [PolicyNames.RequirePermissionAssignmentsRead] = PermissionNames.TenantPermissionsRead,
      [PolicyNames.RequirePermissionAssignmentsWrite] = PermissionNames.TenantPermissionsWrite,
      [PolicyNames.RequireServerServiceAccountsRead] = PermissionNames.ServerServiceAccountsRead,
      [PolicyNames.RequireServerServiceAccountsRotateCredentials] = PermissionNames.ServerServiceAccountsRotateCredentials,
      [PolicyNames.RequireServerServiceAccountsWrite] = PermissionNames.ServerServiceAccountsWrite,
      [PolicyNames.RequireServiceAccountRead] = PermissionNames.ServiceAccountRead,
      [PolicyNames.RequireServiceAccountRotateCredentials] = PermissionNames.ServiceAccountRotateCredentials,
      [PolicyNames.RequireServiceAccountWrite] = PermissionNames.ServiceAccountWrite,
      [PolicyNames.RequireUserGroupAssignUsers] = PermissionNames.UserGroupAssignUsers,
      [PolicyNames.RequireUserGroupsRead] = PermissionNames.TenantUserGroupsRead,
      [PolicyNames.RequireUserGroupsWrite] = PermissionNames.TenantUserGroupsWrite,
    };
}
