namespace ControlR.Web.Server.Hubs;

public static class HubGroupNames
{
  public const string ServerAdministrators = "server-administrators";

  public static string DeviceHeartbeat(Guid deviceId) => $"device:{deviceId}:heartbeat";

  // Legacy role/tag-based group builders. Retained until Chunks 42/43/43b migrate all callers
  // (AgentHub, ViewerHub, DeviceTagsController) to the content-based topic builders above; the
  // legacy methods are deleted in Chunk 43b once zero callers remain.
  public static string GetDeviceGroupName(Guid deviceId, Guid tenantId)
  {
    return $"tenant-{tenantId}-device-{deviceId}";
  }

  public static string GetTagGroupName(Guid tagId, Guid tenantId)
  {
    return $"tenant-{tenantId}-tag-{tagId}";
  }

  public static string GetTenantDevicesGroupName(Guid tenantId)
  {
    return $"tenant-{tenantId}-devices";
  }

  public static string GetUserRoleGroupName(string roleName, Guid tenantId)
  {
    return $"tenant-{tenantId}-user-role-{roleName}";
  }

  public static string ServerAlerts() => "server:alerts";

  public static string ServerTelemetry() => "server:telemetry";
}
