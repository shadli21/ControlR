using System.Collections.Frozen;

namespace ControlR.Libraries.Api.Contracts.Authz;

/// <summary>
/// Maps each permission-based policy to its permission and authorization resource scope. The
/// server registers these against the permission evaluator. The Blazor client uses the permission
/// name for claim checks because it cannot run the server-side evaluator.
/// </summary>
public static class PermissionPolicies
{
  /// <summary>
  /// Claim type for server-evaluated client policy grants. A claim of this type whose value
  /// is a <see cref="PolicyNames"/> entry means the server evaluated that policy against its
  /// canonical (tenant/server) resource while producing the current auth snapshot and the
  /// decision was allowed. A permission name may be resource-scoped, whereas a client policy
  /// grant answers one exact resource-independent client presentation question.
  /// </summary>
  public const string ClientPolicyClaimType = "controlr:client-policy";

  private static IReadOnlyDictionary<string, PermissionPolicyDefinition>? _clientDefinitions;

  /// <summary>
  /// The subset of <see cref="Definitions"/> that is projected to the client as
  /// <see cref="ClientPolicyClaimType"/> grants. Only policies whose canonical resource kind
  /// is <see cref="PermissionScopeKind.Tenant"/> or <see cref="PermissionScopeKind.Server"/>
  /// may be projected; resource-specific access is never represented as a global claim. This
  /// is kept as an explicit curated list so projection is a deliberate edit.
  /// </summary>
  public static IReadOnlyDictionary<string, PermissionPolicyDefinition> ClientDefinitions
  {
    get
    {
      return _clientDefinitions ??= Definitions
        .Where(entry => entry.Value.ProjectToClient)
        .ToFrozenDictionary(entry => entry.Key, entry => entry.Value, StringComparer.Ordinal);
    }
  }
  public static IReadOnlyDictionary<string, PermissionPolicyDefinition> Definitions { get; } =
    new Dictionary<string, PermissionPolicyDefinition>
    {
      [PolicyNames.RequireAgentInstall] = new(PermissionNames.AgentInstall, PermissionScopeKind.Tenant, ProjectToClient: true),
      [PolicyNames.RequireAuthorizationLogsRead] = new(PermissionNames.TenantAuthorizationLogsRead, PermissionScopeKind.Tenant, ProjectToClient: true),
      [PolicyNames.RequireCustomersRead] = new(PermissionNames.TenantCustomersRead, PermissionScopeKind.Tenant, ProjectToClient: true),
      [PolicyNames.RequireCustomersWrite] = new(PermissionNames.TenantCustomersWrite, PermissionScopeKind.Tenant, ProjectToClient: true),
      [PolicyNames.RequireDeviceGroupAssignDevices] = new(PermissionNames.DeviceGroupAssignDevices, PermissionScopeKind.DeviceGroup),
      [PolicyNames.RequireDeviceGroupsRead] = new(PermissionNames.TenantDeviceGroupsRead, PermissionScopeKind.Tenant, ProjectToClient: true),
      [PolicyNames.RequireDeviceGroupsWrite] = new(PermissionNames.TenantDeviceGroupsWrite, PermissionScopeKind.Tenant),
      [PolicyNames.RequireInstallerKeyRead] = new(PermissionNames.InstallerKeyRead, PermissionScopeKind.Tenant, ProjectToClient: true),
      [PolicyNames.RequireInstallerKeyWrite] = new(PermissionNames.InstallerKeyWrite, PermissionScopeKind.Tenant),
      [PolicyNames.RequirePermissionAssignmentsRead] = new(PermissionNames.TenantPermissionsRead, PermissionScopeKind.Tenant, ProjectToClient: true),
      [PolicyNames.RequirePermissionAssignmentsWrite] = new(PermissionNames.TenantPermissionsWrite, PermissionScopeKind.Tenant, ProjectToClient: true),
      [PolicyNames.RequirePersonalAccessTokensOthersRead] = new(PermissionNames.PersonalAccessTokenOthersRead, PermissionScopeKind.Tenant),
      [PolicyNames.RequirePersonalAccessTokensOthersWrite] = new(PermissionNames.PersonalAccessTokenOthersWrite, PermissionScopeKind.Tenant),
      [PolicyNames.RequireServerAdmin] = new(PermissionNames.ServerAdmin, PermissionScopeKind.Server, ProjectToClient: true),
      [PolicyNames.RequireServerAlertsWrite] = new(PermissionNames.ServerAlertsWrite, PermissionScopeKind.Server),
      [PolicyNames.RequireServerAuthorizationLogsRead] = new(PermissionNames.ServerAuthorizationLogsRead, PermissionScopeKind.Server, ProjectToClient: true),
      [PolicyNames.RequireServerPermissionsRead] = new(PermissionNames.ServerPermissionsRead, PermissionScopeKind.Server),
      [PolicyNames.RequireServerPermissionsWrite] = new(PermissionNames.ServerPermissionsWrite, PermissionScopeKind.Server, ProjectToClient: true),
      [PolicyNames.RequireServerTenantsRead] = new(PermissionNames.ServerTenantsRead, PermissionScopeKind.Server),
      [PolicyNames.RequireServerServiceAccountsRead] = new(PermissionNames.ServerServiceAccountsRead, PermissionScopeKind.Server, ProjectToClient: true),
      [PolicyNames.RequireServerServiceAccountsRotateCredentials] = new(PermissionNames.ServerServiceAccountsRotateCredentials, PermissionScopeKind.Server, ProjectToClient: true),
      [PolicyNames.RequireServerServiceAccountsWrite] = new(PermissionNames.ServerServiceAccountsWrite, PermissionScopeKind.Server),
      [PolicyNames.RequireServerTelemetryRead] = new(PermissionNames.ServerTelemetryRead, PermissionScopeKind.Server, ProjectToClient: true),
      [PolicyNames.RequireServiceAccountRead] = new(PermissionNames.ServiceAccountRead, PermissionScopeKind.Tenant, ProjectToClient: true),
      [PolicyNames.RequireServiceAccountRotateCredentials] = new(PermissionNames.ServiceAccountRotateCredentials, PermissionScopeKind.Tenant, ProjectToClient: true),
      [PolicyNames.RequireServiceAccountWrite] = new(PermissionNames.ServiceAccountWrite, PermissionScopeKind.Tenant),
      [PolicyNames.RequireTagsWrite] = new(PermissionNames.TenantTagsWrite, PermissionScopeKind.Tenant, ProjectToClient: true),
      [PolicyNames.RequireTenantSettingsRead] = new(PermissionNames.TenantSettingsRead, PermissionScopeKind.Tenant, ProjectToClient: true),
      [PolicyNames.RequireTenantSettingsWrite] = new(PermissionNames.TenantSettingsWrite, PermissionScopeKind.Tenant, ProjectToClient: true),
      [PolicyNames.RequireTenantUsersDelete] = new(PermissionNames.TenantUsersDelete, PermissionScopeKind.Tenant),
      [PolicyNames.RequireTenantUsersWrite] = new(PermissionNames.TenantUsersWrite, PermissionScopeKind.Tenant, ProjectToClient: true),
      [PolicyNames.RequireUserGroupAssignUsers] = new(PermissionNames.UserGroupAssignUsers, PermissionScopeKind.UserGroup),
      [PolicyNames.RequireUserGroupsRead] = new(PermissionNames.TenantUserGroupsRead, PermissionScopeKind.Tenant, ProjectToClient: true),
      [PolicyNames.RequireUserGroupsWrite] = new(PermissionNames.TenantUserGroupsWrite, PermissionScopeKind.Tenant),
      [PolicyNames.RequireUsersRead] = new(PermissionNames.TenantUsersRead, PermissionScopeKind.Tenant, ProjectToClient: true),
    };
  public static IReadOnlyDictionary<string, string> PolicyToPermission { get; } =
    Definitions.ToDictionary(x => x.Key, x => x.Value.PermissionName);
}
