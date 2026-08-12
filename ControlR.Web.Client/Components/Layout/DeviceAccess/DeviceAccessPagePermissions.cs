namespace ControlR.Web.Client.Components.Layout.DeviceAccess;

internal static class DeviceAccessPagePermissions
{
  public static bool CanAccess(DeviceAccessPermissionsDto? permissions, string path)
  {
    if (permissions is null)
    {
      return false;
    }

    return path switch
    {
      ClientRoutes.DeviceAccess => permissions.CanViewOverview,
      ClientRoutes.DeviceAccessRemoteControl => permissions.CanUseRemoteControl,
      ClientRoutes.DeviceAccessTerminal => permissions.CanUseTerminal,
      ClientRoutes.DeviceAccessChat => permissions.CanUseChat,
      ClientRoutes.DeviceAccessFileSystem => permissions.CanReadFileSystem,
      ClientRoutes.DeviceAccessRemoteLogs => permissions.CanReadLogs,
      ClientRoutes.DeviceAccessVncRelay => permissions.CanUseVncRelay,
      _ => false
    };
  }

  public static string? FirstAllowedRoute(DeviceAccessPermissionsDto? permissions)
  {
    if (permissions is null)
    {
      return null;
    }

    var routes = new (string Route, bool Allowed)[]
    {
      (ClientRoutes.DeviceAccess, permissions.CanViewOverview),
      (ClientRoutes.DeviceAccessRemoteControl, permissions.CanUseRemoteControl),
      (ClientRoutes.DeviceAccessTerminal, permissions.CanUseTerminal),
      (ClientRoutes.DeviceAccessChat, permissions.CanUseChat),
      (ClientRoutes.DeviceAccessFileSystem, permissions.CanReadFileSystem),
      (ClientRoutes.DeviceAccessRemoteLogs, permissions.CanReadLogs),
      (ClientRoutes.DeviceAccessVncRelay, permissions.CanUseVncRelay)
    };

    return routes.FirstOrDefault(x => x.Allowed).Route;
  }
}