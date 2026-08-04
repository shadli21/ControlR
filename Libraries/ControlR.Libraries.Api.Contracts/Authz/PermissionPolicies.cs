namespace ControlR.Libraries.Api.Contracts.Authz;

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
      [PolicyNames.RequireAgentInstall] = PermissionNames.AgentInstall,
      [PolicyNames.RequireCustomersRead] = PermissionNames.TenantCustomersRead,
      [PolicyNames.RequireCustomersWrite] = PermissionNames.TenantCustomersWrite,
      [PolicyNames.RequireDeviceGroupAssignDevices] = PermissionNames.DeviceGroupAssignDevices,
      [PolicyNames.RequireDeviceGroupsRead] = PermissionNames.TenantDeviceGroupsRead,
      [PolicyNames.RequireDeviceGroupsWrite] = PermissionNames.TenantDeviceGroupsWrite,
      [PolicyNames.RequireInstallerKeyRead] = PermissionNames.InstallerKeyRead,
      [PolicyNames.RequireInstallerKeyWrite] = PermissionNames.InstallerKeyWrite,
      [PolicyNames.RequirePermissionAssignmentsRead] = PermissionNames.TenantPermissionsRead,
      [PolicyNames.RequirePermissionAssignmentsWrite] = PermissionNames.TenantPermissionsWrite,
      [PolicyNames.RequirePersonalAccessTokensOthersRead] = PermissionNames.PersonalAccessTokenOthersRead,
      [PolicyNames.RequirePersonalAccessTokensOthersWrite] = PermissionNames.PersonalAccessTokenOthersWrite,
      [PolicyNames.RequireServerAdmin] = PermissionNames.ServerAdmin,
      [PolicyNames.RequireServerAlertsWrite] = PermissionNames.ServerAlertsWrite,
      [PolicyNames.RequireServerServiceAccountsRead] = PermissionNames.ServerServiceAccountsRead,
      [PolicyNames.RequireServerServiceAccountsRotateCredentials] = PermissionNames.ServerServiceAccountsRotateCredentials,
      [PolicyNames.RequireServerServiceAccountsWrite] = PermissionNames.ServerServiceAccountsWrite,
      [PolicyNames.RequireServerTelemetryRead] = PermissionNames.ServerTelemetryRead,
      [PolicyNames.RequireServiceAccountRead] = PermissionNames.ServiceAccountRead,
      [PolicyNames.RequireServiceAccountRotateCredentials] = PermissionNames.ServiceAccountRotateCredentials,
      [PolicyNames.RequireServiceAccountWrite] = PermissionNames.ServiceAccountWrite,
      [PolicyNames.RequireTagsWrite] = PermissionNames.TenantTagsWrite,
      [PolicyNames.RequireTenantSettingsRead] = PermissionNames.TenantSettingsRead,
      [PolicyNames.RequireTenantSettingsWrite] = PermissionNames.TenantSettingsWrite,
      [PolicyNames.RequireTenantUsersDelete] = PermissionNames.TenantUsersDelete,
      [PolicyNames.RequireTenantUsersWrite] = PermissionNames.TenantUsersWrite,
      [PolicyNames.RequireUserGroupAssignUsers] = PermissionNames.UserGroupAssignUsers,
      [PolicyNames.RequireUserGroupsRead] = PermissionNames.TenantUserGroupsRead,
      [PolicyNames.RequireUserGroupsWrite] = PermissionNames.TenantUserGroupsWrite,
      [PolicyNames.RequireUsersRead] = PermissionNames.TenantUsersRead,
    };
}
