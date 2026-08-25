namespace ControlR.Web.Server.Hubs;

public static class HubGroupNames
{
  public static string DeviceHeartbeat(Guid deviceId) => $"device:{deviceId}:heartbeat";

  public static string ServerAlerts() => "server:alerts";

  public static string ServerTelemetry() => "server:telemetry";
}
