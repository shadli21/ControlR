using ControlR.Web.Server.Authz.Permissions;

namespace ControlR.Web.Server.Services.Authorization;

/// <summary>
/// Resolves the set of permission names granted by a collection of role names.
/// Roles are demoted to static permission bundles in the permission rework; this
/// resolver maps role claims to their seeded permission sets for the evaluator.
/// </summary>
public interface IRoleBundleResolver
{
  /// <summary>
  /// Returns the union of permission names granted by the given role names.
  /// </summary>
  IReadOnlySet<string> ResolvePermissions(IEnumerable<string> roleNames);
}

/// <summary>
/// Interim role-to-permission bridge. Maps each built-in role to its equivalent
/// permission set so the evaluator can treat role claims as allow rules during
/// the PR-sequencing period. Deleted in PR 13 (Final Cleanup).
/// </summary>
public class RoleBundleResolver : IRoleBundleResolver
{
  private static readonly Dictionary<string, HashSet<string>> _roleBundles = BuildRoleBundles();

  public IReadOnlySet<string> ResolvePermissions(IEnumerable<string> roleNames)
  {
    var result = new HashSet<string>();
    foreach (var roleName in roleNames)
    {
      if (_roleBundles.TryGetValue(roleName, out var permissions))
      {
        result.UnionWith(permissions);
      }
    }
    return result;
  }

  private static Dictionary<string, HashSet<string>> BuildRoleBundles()
  {
    return new Dictionary<string, HashSet<string>>
    {
      [RoleNames.ServerAdministrator] =
      [
        PermissionNames.ServerAdmin,
        PermissionNames.ServerAlertsRead,
        PermissionNames.ServerAlertsWrite,
        PermissionNames.ServerDashboardRead,
        PermissionNames.ServerServiceAccountsRead,
        PermissionNames.ServerServiceAccountsWrite,
        PermissionNames.ServerServiceAccountsRotateCredentials,
      ],

      [RoleNames.TenantAdministrator] =
      [
        PermissionNames.TenantRead,
        PermissionNames.TenantSettingsRead,
        PermissionNames.TenantSettingsWrite,
        PermissionNames.TenantUsersRead,
        PermissionNames.TenantUsersWrite,
        PermissionNames.TenantUsersDelete,
        PermissionNames.TenantRolesRead,
        PermissionNames.TenantRolesAssign,
        PermissionNames.TenantUserGroupsRead,
        PermissionNames.TenantUserGroupsWrite,
        PermissionNames.UserGroupAssignUsers,
        PermissionNames.TenantDeviceGroupsRead,
        PermissionNames.TenantDeviceGroupsWrite,
        PermissionNames.DeviceGroupAssignDevices,
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
        PermissionNames.AgentInstall,
      ],

      [RoleNames.DeviceSuperUser] =
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

      [RoleNames.AgentInstaller] =
      [
        PermissionNames.AgentInstall,
      ],

      [RoleNames.InstallerKeyManager] =
      [
        PermissionNames.InstallerKeyRead,
        PermissionNames.InstallerKeyWrite,
        PermissionNames.AgentInstall,
      ],
    };
  }
}
