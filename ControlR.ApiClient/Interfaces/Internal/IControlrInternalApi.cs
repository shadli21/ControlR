namespace ControlR.ApiClient.Interfaces.Internal;

public interface IControlrInternalApi
{
  IAuthApi Auth { get; }
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
  IPersonalAccessTokensApi PersonalAccessTokens { get; }
  IPermissionAssignmentsApi PermissionAssignments { get; }
  IPublicServerSettingsApi PublicServerSettings { get; }
  IRolesApi Roles { get; }
  IServerAlertApi ServerAlert { get; }
  IServerLogsApi ServerLogs { get; }
  IServerStatsApi ServerStats { get; }
  IServiceAccountsApi ServiceAccounts { get; }
  ITagsApi Tags { get; }
  ITenantSettingsApi TenantSettings { get; }
  ITestEmailApi TestEmail { get; }
  IUserGroupsApi UserGroups { get; }
  IUserPreferencesApi UserPreferences { get; }
  IUserRolesApi UserRoles { get; }
  IUsersApi Users { get; }
  IUserServerSettingsApi UserServerSettings { get; }
  IUserStorageApi UserStorage { get; }
  IUserTagsApi UserTags { get; }
  IVersionApi Version { get; }
}