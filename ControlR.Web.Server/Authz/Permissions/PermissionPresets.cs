using ControlR.Web.Server.Services.Authorization;

namespace ControlR.Web.Server.Authz.Permissions;

/// <summary>
/// Named permission presets: curated permission sets used to seed principals (the first/bootstrap
/// user, test users, and the role-to-permission backfill). These are the assignable templates that
/// replaced the legacy role bundles; roles no longer participate in authorization, but the curated
/// sets remain the canonical groupings of related permissions.
/// </summary>
public static class PermissionPresets
{
  public const string AgentInstaller = "Agent Installer";
  public const string DeviceSuperUser = "Device Superuser";
  public const string InstallerKeyManager = "Installer Key Manager";
  public const string ServerAdministrator = "Server Administrator";
  public const string ServiceAccountManager = "Service Account Manager";
  public const string TenantAdministrator = "Tenant Administrator";

  public static IReadOnlyDictionary<string, IReadOnlyList<string>> All { get; } = BuildPresets();

  public static IReadOnlyList<string> GetPermissions(string presetName) =>
    All.TryGetValue(presetName, out var permissions) ? permissions : [];

  /// <summary>
  /// Seeds permission assignments for every permission in the given presets. Each permission is
  /// scoped to its <b>broadest legal scope</b> from the catalog (Server &gt; Tenant &gt;
  /// CustomerTenant/DeviceGroup &gt; Device). Server-wide permissions get ScopeKind.Server with
  /// no ScopeId or OwningTenantId; everything else lands at Tenant scope targeting the given
  /// tenant, matching the PermissionEvaluator's ScopeMatches requirements.
  /// </summary>
  public static async Task SeedAssignments(
    AppDb appDb,
    Guid userId,
    Guid tenantId,
    IEnumerable<string> presetNames,
    CancellationToken cancellationToken = default)
  {
    var seeded = new HashSet<string>();
    foreach (var presetName in presetNames)
    {
      var permissions = GetPermissions(presetName);
      if (permissions.Count == 0)
      {
        continue;
      }

      foreach (var permission in permissions)
      {
        if (!seeded.Add(permission))
        {
          continue;
        }

        var scopeKind = PermissionCatalog.GetBroadestLegalScope(permission) ?? PermissionScopeKind.Tenant;
        var scopeId = scopeKind == PermissionScopeKind.Server ? (Guid?)null : tenantId;

        appDb.PermissionAssignments.Add(PermissionAssignment.CreateGrant(
          PermissionPrincipalKind.User,
          userId,
          permission,
          scopeKind,
          scopeId,
          tenantId,
          AuthorizationChangeLogActorTypes.System,
          userId.ToString()));
      }
    }

    await appDb.SaveChangesAsync(cancellationToken);
  }

  private static Dictionary<string, IReadOnlyList<string>> BuildPresets()
  {
    return new Dictionary<string, IReadOnlyList<string>>
    {
      [ServerAdministrator] =
      [
        PermissionNames.ServerAdmin,
        PermissionNames.ServerAlertsRead,
        PermissionNames.ServerAlertsWrite,
        PermissionNames.ServerAuthorizationLogsRead,
        PermissionNames.ServerTenantsRead,
        PermissionNames.ServerTelemetryRead,
        PermissionNames.ServerServiceAccountsRead,
        PermissionNames.ServerServiceAccountsWrite,
        PermissionNames.ServerServiceAccountsRotateCredentials,
        PermissionNames.ServerPermissionsRead,
        PermissionNames.ServerPermissionsWrite,
        PermissionNames.TenantPermissionsRead,
        PermissionNames.TenantAuthorizationLogsRead,
      ],

      [TenantAdministrator] =
      [
        PermissionNames.TenantRead,
        PermissionNames.TenantSettingsRead,
        PermissionNames.TenantSettingsWrite,
        PermissionNames.TenantUsersRead,
        PermissionNames.TenantUsersWrite,
        PermissionNames.TenantUsersDelete,
        PermissionNames.TenantUserGroupsRead,
        PermissionNames.TenantUserGroupsWrite,
        PermissionNames.UserGroupAssignUsers,
        PermissionNames.TenantDeviceGroupsRead,
        PermissionNames.TenantDeviceGroupsWrite,
        PermissionNames.DeviceGroupAssignDevices,
        PermissionNames.TenantCustomersRead,
        PermissionNames.TenantCustomersWrite,
        PermissionNames.TenantTagsWrite,
        PermissionNames.TenantPermissionsRead,
        PermissionNames.TenantAuthorizationLogsRead,
        PermissionNames.TenantPermissionsWrite,
        PermissionNames.TenantPermissionsDeny,
        PermissionNames.PersonalAccessTokenSelfRead,
        PermissionNames.PersonalAccessTokenSelfWrite,
        PermissionNames.PersonalAccessTokenOthersRead,
        PermissionNames.PersonalAccessTokenOthersWrite,
        PermissionNames.ServiceAccountRead,
        PermissionNames.ServiceAccountWrite,
        PermissionNames.ServiceAccountRotateCredentials,
        PermissionNames.InstallerKeyRead,
        PermissionNames.InstallerKeyWrite,
        PermissionNames.InstallerKeyManageAll,
        PermissionNames.AgentInstall,
      ],

      [DeviceSuperUser] =
      [
        PermissionNames.DeviceRead,
        PermissionNames.DeviceDelete,
        PermissionNames.DeviceAliasWrite,
        PermissionNames.DeviceTagsRead,
        PermissionNames.DeviceTagsWrite,
        PermissionNames.DeviceDesktopPreviewRead,
        PermissionNames.DeviceLogsRead,
        PermissionNames.DeviceRemoteControlConnect,
        PermissionNames.DeviceRemoteControlInteract,
        PermissionNames.DeviceRemoteControlBlockInput,
        PermissionNames.DeviceRemoteControlElevatedDesktop,
        PermissionNames.DeviceCtrlAltDelSend,
        PermissionNames.DeviceClipboardRead,
        PermissionNames.DeviceClipboardWrite,
        PermissionNames.DeviceChatSend,
        PermissionNames.DeviceFileSystemRead,
        PermissionNames.DeviceFileSystemWrite,
        PermissionNames.DeviceFileSystemDelete,
        PermissionNames.DeviceFileSystemTransferUpload,
        PermissionNames.DeviceFileSystemTransferDownload,
        PermissionNames.DeviceTerminalUse,
        PermissionNames.DeviceLogonTokenCreate,
        PermissionNames.DeviceWakeSend,
        PermissionNames.DevicePowerManage,
        PermissionNames.DeviceAgentUpdate,
      ],

      [AgentInstaller] =
      [
        PermissionNames.AgentInstall,
      ],

      [InstallerKeyManager] =
      [
        PermissionNames.InstallerKeyRead,
        PermissionNames.InstallerKeyWrite,
        PermissionNames.AgentInstall,
      ],

      [ServiceAccountManager] =
      [
        PermissionNames.ServiceAccountRead,
        PermissionNames.ServiceAccountWrite,
        PermissionNames.ServiceAccountRotateCredentials,
      ],
    };
  }
}
