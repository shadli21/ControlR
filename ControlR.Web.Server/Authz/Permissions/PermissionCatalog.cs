using ControlR.Web.Server.Data.Enums;

namespace ControlR.Web.Server.Authz.Permissions;

public static class PermissionCatalog
{
  private static readonly Dictionary<string, PermissionMetadata> _permissions = BuildCatalog();

  public static IReadOnlyDictionary<string, PermissionMetadata> All => _permissions;

  public static bool Exists(string permissionName) => _permissions.ContainsKey(permissionName);

  public static PermissionMetadata? Get(string permissionName) =>
    _permissions.GetValueOrDefault(permissionName);

  private static Dictionary<string, PermissionMetadata> BuildCatalog()
  {
    var catalog = new Dictionary<string, PermissionMetadata>();

    void Add(string name, string displayName, string description, PermissionScopeKind[] scopeKinds, bool isAssignable = true)
    {
      catalog[name] = new PermissionMetadata(name, displayName, description, scopeKinds, isAssignable);
    }

    var server = new[] { PermissionScopeKind.Server };
    var tenant = new[] { PermissionScopeKind.Tenant };
    var device = new[] { PermissionScopeKind.Device };
    var deviceAndGroup = new[] { PermissionScopeKind.Device, PermissionScopeKind.DeviceGroup };

    Add(PermissionNames.ServerAdmin, "Server Admin", "Full administrative access to server-wide settings and operations.", server);
    Add(PermissionNames.ServerAlertsRead, "Read Server Alerts", "View server alerts and notifications.", server);
    Add(PermissionNames.ServerAlertsWrite, "Manage Server Alerts", "Create, update, and dismiss server alerts.", server);
    Add(PermissionNames.ServerDashboardRead, "Read Server Dashboard", "View the Aspire dashboard (logs and metrics).", server);
    Add(PermissionNames.ServerServiceAccountsRead, "Read Server Service Accounts", "View server-scoped service accounts and credentials.", server);
    Add(PermissionNames.ServerServiceAccountsWrite, "Manage Server Service Accounts", "Create and delete server-scoped service accounts.", server);
    Add(PermissionNames.ServerServiceAccountsRotateCredentials, "Rotate Server Service Account Credentials", "Create and revoke credentials for server-scoped service accounts.", server);

    Add(PermissionNames.TenantRead, "Read Tenant", "View tenant details and settings.", tenant);
    Add(PermissionNames.TenantSettingsRead, "Read Tenant Settings", "View tenant configuration.", tenant);
    Add(PermissionNames.TenantSettingsWrite, "Manage Tenant Settings", "Modify tenant configuration.", tenant);
    Add(PermissionNames.TenantUsersRead, "Read Tenant Users", "View users within the tenant.", tenant);
    Add(PermissionNames.TenantUsersWrite, "Manage Tenant Users", "Create and update users within the tenant.", tenant);
    Add(PermissionNames.TenantUsersDelete, "Delete Tenant Users", "Remove users from the tenant.", tenant);
    Add(PermissionNames.TenantRolesRead, "Read Tenant Roles", "View role assignments within the tenant.", tenant);
    Add(PermissionNames.TenantRolesAssign, "Assign Tenant Roles", "Assign and remove roles for users within the tenant.", tenant);
    Add(PermissionNames.TenantUserGroupsRead, "Read User Groups", "View user groups within the tenant.", tenant);
    Add(PermissionNames.TenantUserGroupsWrite, "Manage User Groups", "Create, update, and delete user groups within the tenant.", tenant);
    Add(PermissionNames.TenantDeviceGroupsRead, "Read Device Groups", "View device groups within the tenant.", tenant);
    Add(PermissionNames.TenantDeviceGroupsWrite, "Manage Device Groups", "Create, update, and delete device groups within the tenant.", tenant);
    Add(PermissionNames.TenantPermissionsRead, "Read Permissions", "View permission assignments within the tenant.", tenant);
    Add(PermissionNames.TenantPermissionsWrite, "Manage Permissions", "Create and update allow permission assignments within the tenant.", tenant);
    Add(PermissionNames.TenantPermissionsDeny, "Manage Deny Permissions", "Create and update deny permission assignments within the tenant.", tenant);

    Add(PermissionNames.DeviceRead, "Read Device", "View device details and status.", deviceAndGroup);
    Add(PermissionNames.DeviceDelete, "Delete Device", "Remove a device from the system.", deviceAndGroup);
    Add(PermissionNames.DeviceAliasWrite, "Update Device Alias", "Change the display alias for a device.", deviceAndGroup);
    Add(PermissionNames.DeviceTagsRead, "Read Device Tags", "View tags assigned to a device.", deviceAndGroup);
    Add(PermissionNames.DeviceTagsWrite, "Manage Device Tags", "Add and remove tags on a device.", deviceAndGroup);
    Add(PermissionNames.DeviceDesktopPreviewRead, "View Desktop Preview", "View the desktop preview thumbnail for a device.", deviceAndGroup);
    Add(PermissionNames.DeviceLogsRead, "Read Device Logs", "View remote log files from a device.", deviceAndGroup);

    Add(PermissionNames.DeviceRemoteControlConnect, "Connect Remote Control", "Initiate a remote control session to a device.", deviceAndGroup);
    Add(PermissionNames.DeviceRemoteControlInteract, "Interact Remote Control", "Send input during a remote control session.", deviceAndGroup);
    Add(PermissionNames.DeviceRemoteControlBlockInput, "Block Remote Input", "Block the remote user's keyboard and mouse during a remote control session.", deviceAndGroup);
    Add(PermissionNames.DeviceRemoteControlElevatedDesktop, "Elevated Desktop Access", "Access the elevated (system) desktop during remote control.", deviceAndGroup);
    Add(PermissionNames.DeviceCtrlAltDelSend, "Send Ctrl+Alt+Del", "Send Ctrl+Alt+Del to a remote device.", deviceAndGroup);
    Add(PermissionNames.DeviceClipboardRead, "Read Device Clipboard", "Read the clipboard contents from a remote device.", device);
    Add(PermissionNames.DeviceClipboardWrite, "Write Device Clipboard", "Write to the clipboard on a remote device.", device);
    Add(PermissionNames.DeviceChatSend, "Chat with Device", "Send chat messages to a remote device user.", deviceAndGroup);

    Add(PermissionNames.DeviceFileSystemRead, "Read Device File System", "Browse and read files on a remote device.", deviceAndGroup);
    Add(PermissionNames.DeviceFileSystemWrite, "Write Device File System", "Create and modify files on a remote device.", deviceAndGroup);
    Add(PermissionNames.DeviceFileSystemDelete, "Delete Device Files", "Delete files on a remote device.", deviceAndGroup);
    Add(PermissionNames.DeviceFileSystemTransferUpload, "Upload Files to Device", "Upload files to a remote device.", deviceAndGroup);
    Add(PermissionNames.DeviceFileSystemTransferDownload, "Download Files from Device", "Download files from a remote device.", deviceAndGroup);

    Add(PermissionNames.DeviceTerminalUse, "Use Remote Terminal", "Open a terminal session and execute commands on a remote device.", deviceAndGroup);
    Add(PermissionNames.DeviceLogonTokenCreate, "Create Logon Token", "Create a single-use logon token for a device.", device);
    Add(PermissionNames.DeviceWakeSend, "Send Wake Command", "Send a wake-on-LAN command to a device.", deviceAndGroup);
    Add(PermissionNames.DevicePowerManage, "Manage Device Power", "Shutdown or restart a remote device.", deviceAndGroup);
    Add(PermissionNames.DeviceAgentUpdate, "Update Device Agent", "Trigger an agent update on a remote device.", deviceAndGroup);

    Add(PermissionNames.PersonalAccessTokenSelfRead, "Read Own PATs", "View your own personal access tokens.", tenant);
    Add(PermissionNames.PersonalAccessTokenSelfWrite, "Manage Own PATs", "Create and delete your own personal access tokens.", tenant);
    Add(PermissionNames.PersonalAccessTokenOthersRead, "Read Others' PATs", "View personal access tokens belonging to other users in the tenant.", tenant);
    Add(PermissionNames.PersonalAccessTokenOthersWrite, "Manage Others' PATs", "Create and delete personal access tokens for other users in the tenant.", tenant);
    Add(PermissionNames.ServiceAccountRead, "Read Service Accounts", "View tenant-scoped service accounts and credentials.", tenant);
    Add(PermissionNames.ServiceAccountWrite, "Manage Service Accounts", "Create and delete tenant-scoped service accounts.", tenant);
    Add(PermissionNames.ServiceAccountRotateCredentials, "Rotate Service Account Credentials", "Create and revoke credentials for tenant-scoped service accounts.", tenant);

    Add(PermissionNames.InstallerKeyRead, "Read Installer Keys", "View agent installer keys.", tenant);
    Add(PermissionNames.InstallerKeyWrite, "Manage Installer Keys", "Create and delete agent installer keys.", tenant);
    Add(PermissionNames.AgentInstall, "Install Agent", "Generate agent installation commands and scripts.", tenant);

    Add(PermissionNames.CustomerTenantRead, "Read Customer Tenant", "View customer tenant details.", [PermissionScopeKind.CustomerTenant], isAssignable: false);
    Add(PermissionNames.CustomerTenantWrite, "Manage Customer Tenant", "Create and update customer tenants.", [PermissionScopeKind.CustomerTenant], isAssignable: false);
    Add(PermissionNames.DeviceGroupAssignDevices, "Assign Devices to Group", "Add and remove devices from a device group.", [PermissionScopeKind.DeviceGroup], isAssignable: false);
    Add(PermissionNames.UserGroupAssignUsers, "Assign Users to Group", "Add and remove users from a user group.", [PermissionScopeKind.UserGroup], isAssignable: false);

    return catalog;
  }
}
