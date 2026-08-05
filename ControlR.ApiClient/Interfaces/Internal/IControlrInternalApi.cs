namespace ControlR.ApiClient.Interfaces.Internal;

public interface IControlrInternalApi
{
  IAuthApi Auth { get; }
  IAuthorizationChangeLogsApi AuthorizationChangeLogs { get; }
  ICustomersApi Customers { get; }
  IDesktopPreviewApi DesktopPreview { get; }
  IDeviceFileSystemApi DeviceFileSystem { get; }
  IDeviceGroupsApi DeviceGroups { get; }
  IDevicesApi Devices { get; }
  IDeviceTagsApi DeviceTags { get; }
  IEffectivePermissionsApi EffectivePermissions { get; }
  IEffectiveUserPreferencesApi EffectiveUserPreferences { get; }
  IInstallerKeysApi InstallerKeys { get; }
  IInvitesApi Invites { get; }
  ILogonTokensApi LogonTokens { get; }
  IPermissionAssignmentsApi PermissionAssignments { get; }
  IPersonalAccessTokensApi PersonalAccessTokens { get; }
  IPublicServerSettingsApi PublicServerSettings { get; }
  IServerAlertApi ServerAlert { get; }
  IServerLogsApi ServerLogs { get; }
  IServerServiceAccountsApi ServerServiceAccounts { get; }
  IServerStatsApi ServerStats { get; }
  IServiceAccountsApi ServiceAccounts { get; }
  ITagsApi Tags { get; }
  ITenantsApi Tenants { get; }
  ITenantSettingsApi TenantSettings { get; }
  ITestEmailApi TestEmail { get; }
  IUserGroupsApi UserGroups { get; }
  IUserPreferencesApi UserPreferences { get; }
  IUsersApi Users { get; }
  IUserServerSettingsApi UserServerSettings { get; }
  IUserStorageApi UserStorage { get; }
  IVersionApi Version { get; }
}