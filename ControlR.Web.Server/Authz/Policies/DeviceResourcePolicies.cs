namespace ControlR.Web.Server.Authz.Policies;

/// <summary>
/// Resource-based authorization policies scoped to a specific device. Each policy requires a
/// single device permission evaluated against the target device (passed as the authorization
/// resource via <c>AuthorizeAsync(user, device, DeviceResourcePolicies.X)</c>).
/// </summary>
public static class DeviceResourcePolicies
{
  public const string AliasWrite = "DeviceAliasWrite";
  public const string Delete = "DeviceDelete";
  public const string DesktopPreviewRead = "DeviceDesktopPreviewRead";
  public const string FileSystemDelete = "DeviceFileSystemDelete";
  public const string FileSystemRead = "DeviceFileSystemRead";
  public const string FileSystemTransferDownload = "DeviceFileSystemTransferDownload";
  public const string FileSystemTransferUpload = "DeviceFileSystemTransferUpload";
  public const string FileSystemWrite = "DeviceFileSystemWrite";
  public const string LogonTokenCreate = "DeviceLogonTokenCreate";
  public const string LogsRead = "DeviceLogsRead";
  public const string Read = "DeviceRead";
  public const string TagsRead = "DeviceTagsRead";
  public const string TagsWrite = "DeviceTagsWrite";
  public const string TerminalUse = "DeviceTerminalUse";

  public static IReadOnlyDictionary<string, string> PolicyToPermission { get; } =
    new Dictionary<string, string>
    {
      [Read] = PermissionNames.DeviceRead,
      [Delete] = PermissionNames.DeviceDelete,
      [AliasWrite] = PermissionNames.DeviceAliasWrite,
      [DesktopPreviewRead] = PermissionNames.DeviceDesktopPreviewRead,
      [TerminalUse] = PermissionNames.DeviceTerminalUse,
      [LogonTokenCreate] = PermissionNames.DeviceLogonTokenCreate,
      [LogsRead] = PermissionNames.DeviceLogsRead,
      [TagsRead] = PermissionNames.DeviceTagsRead,
      [TagsWrite] = PermissionNames.DeviceTagsWrite,
      [FileSystemRead] = PermissionNames.DeviceFileSystemRead,
      [FileSystemWrite] = PermissionNames.DeviceFileSystemWrite,
      [FileSystemDelete] = PermissionNames.DeviceFileSystemDelete,
      [FileSystemTransferDownload] = PermissionNames.DeviceFileSystemTransferDownload,
      [FileSystemTransferUpload] = PermissionNames.DeviceFileSystemTransferUpload,
    };
}
