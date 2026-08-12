namespace ControlR.Libraries.Api.Contracts.Authz;

/// <summary>
/// Well-known policy names for permission-based authorization policies. Shared by the
/// server (which registers and enforces them) and the Blazor client (which resolves them
/// to permission-claim checks). Used in <c>[Authorize(Policy = "...")]</c> attributes.
/// </summary>
public static class PolicyNames
{
  public const string RequireAgentInstall = "RequireAgentInstall";
  public const string RequireAuthorizationLogsRead = "RequireAuthorizationLogsRead";
  public const string RequireCustomersRead = "RequireCustomersRead";
  public const string RequireCustomersWrite = "RequireCustomersWrite";
  public const string RequireDeviceGroupAssignDevices = "RequireDeviceGroupAssignDevices";
  public const string RequireDeviceGroupsRead = "RequireDeviceGroupsRead";
  public const string RequireDeviceGroupsWrite = "RequireDeviceGroupsWrite";
  public const string RequireInstallerKeyRead = "RequireInstallerKeyRead";
  public const string RequireInstallerKeyWrite = "RequireInstallerKeyWrite";
  public const string RequirePermissionAssignmentsRead = "RequirePermissionAssignmentsRead";
  public const string RequirePermissionAssignmentsWrite = "RequirePermissionAssignmentsWrite";
  public const string RequirePersonalAccessTokensOthersRead = "RequirePersonalAccessTokensOthersRead";
  public const string RequirePersonalAccessTokensOthersWrite = "RequirePersonalAccessTokensOthersWrite";
  public const string RequireServerAdmin = "RequireServerAdmin";
  public const string RequireServerAlertsWrite = "RequireServerAlertsWrite";
  public const string RequireServerAuthorizationLogsRead = "RequireServerAuthorizationLogsRead";
  public const string RequireServerPermissionsRead = "RequireServerPermissionsRead";
  public const string RequireServerPermissionsWrite = "RequireServerPermissionsWrite";
  public const string RequireServerServiceAccountsRead = "RequireServerServiceAccountsRead";
  public const string RequireServerServiceAccountsRotateCredentials = "RequireServerServiceAccountsRotateCredentials";
  public const string RequireServerServiceAccountsWrite = "RequireServerServiceAccountsWrite";
  public const string RequireServerTelemetryRead = "RequireServerTelemetryRead";
  public const string RequireServerTenantsRead = "RequireServerTenantsRead";
  public const string RequireServiceAccountRead = "RequireServiceAccountRead";
  public const string RequireServiceAccountRotateCredentials = "RequireServiceAccountRotateCredentials";
  public const string RequireServiceAccountWrite = "RequireServiceAccountWrite";
  public const string RequireTagsWrite = "RequireTagsWrite";
  public const string RequireTenantSettingsRead = "RequireTenantSettingsRead";
  public const string RequireTenantSettingsWrite = "RequireTenantSettingsWrite";
  public const string RequireTenantUsersDelete = "RequireTenantUsersDelete";
  public const string RequireTenantUsersWrite = "RequireTenantUsersWrite";
  public const string RequireUserGroupAssignUsers = "RequireUserGroupAssignUsers";
  public const string RequireUserGroupsRead = "RequireUserGroupsRead";
  public const string RequireUserGroupsWrite = "RequireUserGroupsWrite";
  public const string RequireUsersRead = "RequireUsersRead";
}
