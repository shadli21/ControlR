namespace ControlR.Libraries.Api.Contracts.Authz;

/// <summary>
/// Maps each permission-based policy to its permission and authorization resource scope. The
/// server registers these against the permission evaluator; the Blazor client uses the permission
/// name for claim checks because it cannot run the server-side evaluator.
/// </summary>
public static class PermissionPolicies
{
  public const string PermissionClaimType = "controlr:permission";

  public static IReadOnlyDictionary<string, PermissionPolicyDefinition> Definitions { get; } =
    new Dictionary<string, PermissionPolicyDefinition>
    {
      [PolicyNames.RequireAgentInstall] = new(PermissionNames.AgentInstall),
      [PolicyNames.RequireAuthorizationLogsRead] = new(PermissionNames.TenantAuthorizationLogsRead),
      [PolicyNames.RequireCustomersRead] = new(PermissionNames.TenantCustomersRead),
      [PolicyNames.RequireCustomersWrite] = new(PermissionNames.TenantCustomersWrite),
      [PolicyNames.RequireDeviceGroupAssignDevices] = new(PermissionNames.DeviceGroupAssignDevices, PermissionScopeKind.DeviceGroup),
      [PolicyNames.RequireDeviceGroupsRead] = new(PermissionNames.TenantDeviceGroupsRead),
      [PolicyNames.RequireDeviceGroupsWrite] = new(PermissionNames.TenantDeviceGroupsWrite),
      [PolicyNames.RequireInstallerKeyRead] = new(PermissionNames.InstallerKeyRead),
      [PolicyNames.RequireInstallerKeyWrite] = new(PermissionNames.InstallerKeyWrite),
      [PolicyNames.RequirePermissionAssignmentsRead] = new(PermissionNames.TenantPermissionsRead),
      [PolicyNames.RequirePermissionAssignmentsWrite] = new(PermissionNames.TenantPermissionsWrite),
      [PolicyNames.RequirePersonalAccessTokensOthersRead] = new(PermissionNames.PersonalAccessTokenOthersRead),
      [PolicyNames.RequirePersonalAccessTokensOthersWrite] = new(PermissionNames.PersonalAccessTokenOthersWrite),
      [PolicyNames.RequireServerAdmin] = new(PermissionNames.ServerAdmin),
      [PolicyNames.RequireServerAlertsWrite] = new(PermissionNames.ServerAlertsWrite),
      [PolicyNames.RequireServerAuthorizationLogsRead] = new(PermissionNames.ServerAuthorizationLogsRead),
      [PolicyNames.RequireServerPermissionsRead] = new(PermissionNames.ServerPermissionsRead),
      [PolicyNames.RequireServerPermissionsWrite] = new(PermissionNames.ServerPermissionsWrite),
      [PolicyNames.RequireServerTenantsRead] = new(PermissionNames.ServerTenantsRead),
      [PolicyNames.RequireServerServiceAccountsRead] = new(PermissionNames.ServerServiceAccountsRead),
      [PolicyNames.RequireServerServiceAccountsRotateCredentials] = new(PermissionNames.ServerServiceAccountsRotateCredentials),
      [PolicyNames.RequireServerServiceAccountsWrite] = new(PermissionNames.ServerServiceAccountsWrite),
      [PolicyNames.RequireServerTelemetryRead] = new(PermissionNames.ServerTelemetryRead),
      [PolicyNames.RequireServiceAccountRead] = new(PermissionNames.ServiceAccountRead),
      [PolicyNames.RequireServiceAccountRotateCredentials] = new(PermissionNames.ServiceAccountRotateCredentials),
      [PolicyNames.RequireServiceAccountWrite] = new(PermissionNames.ServiceAccountWrite),
      [PolicyNames.RequireTagsWrite] = new(PermissionNames.TenantTagsWrite),
      [PolicyNames.RequireTenantSettingsRead] = new(PermissionNames.TenantSettingsRead),
      [PolicyNames.RequireTenantSettingsWrite] = new(PermissionNames.TenantSettingsWrite),
      [PolicyNames.RequireTenantUsersDelete] = new(PermissionNames.TenantUsersDelete),
      [PolicyNames.RequireTenantUsersWrite] = new(PermissionNames.TenantUsersWrite),
      [PolicyNames.RequireUserGroupAssignUsers] = new(PermissionNames.UserGroupAssignUsers, PermissionScopeKind.UserGroup),
      [PolicyNames.RequireUserGroupsRead] = new(PermissionNames.TenantUserGroupsRead),
      [PolicyNames.RequireUserGroupsWrite] = new(PermissionNames.TenantUserGroupsWrite),
      [PolicyNames.RequireUsersRead] = new(PermissionNames.TenantUsersRead),
    };

  public static IReadOnlyDictionary<string, string> PolicyToPermission { get; } =
    Definitions.ToDictionary(x => x.Key, x => x.Value.PermissionName);
}
