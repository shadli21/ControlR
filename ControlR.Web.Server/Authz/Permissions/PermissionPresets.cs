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
  public const string TenantAdministrator = "Tenant Administrator";

  private static readonly HashSet<string> _serverScopedPresets = [ServerAdministrator, InstallerKeyManager];

  public static IReadOnlyDictionary<string, IReadOnlyList<string>> All { get; } = BuildPresets();

  public static IReadOnlyList<string> GetPermissions(string presetName) =>
    All.TryGetValue(presetName, out var permissions) ? permissions : [];

  public static PermissionScopeKind GetPresetScopeKind(string presetName) =>
    _serverScopedPresets.Contains(presetName) ? PermissionScopeKind.Server : PermissionScopeKind.Tenant;

  /// <summary>
  /// Seeds permission assignments for every permission in the given presets. Server-level
  /// presets (Server Administrator, Installer Key Manager) get ScopeKind.Server with no
  /// ScopeId or OwningTenantId; tenant-level presets get ScopeKind.Tenant scoped to the
  /// user's tenant, matching the PermissionEvaluator's ScopeMatches requirements.
  /// </summary>
  public static async Task SeedAssignmentsAsync(
    AppDb appDb,
    Guid userId,
    Guid tenantId,
    IEnumerable<string> presetNames,
    CancellationToken cancellationToken = default)
  {
    foreach (var presetName in presetNames)
    {
      var permissions = GetPermissions(presetName);
      if (permissions.Count == 0)
      {
        continue;
      }

      var scopeKind = GetPresetScopeKind(presetName);
      var scopeId = scopeKind == PermissionScopeKind.Server ? (Guid?)null : tenantId;
      var owningTenantId = scopeKind == PermissionScopeKind.Server ? (Guid?)null : tenantId;

      foreach (var permission in permissions)
      {
        appDb.PermissionAssignments.Add(new PermissionAssignment
        {
          PrincipalKind = PermissionPrincipalKind.User,
          PrincipalId = userId,
          PermissionName = permission,
          Effect = PermissionEffect.Allow,
          ScopeKind = scopeKind,
          ScopeId = scopeId,
          IsEnabled = true,
          OwningTenantId = owningTenantId,
          CreatedByPrincipalType = "system",
          CreatedByPrincipalId = userId.ToString()
        });
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
        PermissionNames.ServerTelemetryRead,
        PermissionNames.ServerServiceAccountsRead,
        PermissionNames.ServerServiceAccountsWrite,
        PermissionNames.ServerServiceAccountsRotateCredentials,
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
    };
  }
}
