using System.Text.Json.Serialization;

namespace ControlR.Libraries.Api.Contracts.Dtos.ServerApi.V1;

/// <summary>
/// REST-facing desktop session type. Kept separate from the hub's
/// <see cref="Devices.DesktopSessionType"/> so the REST API can serialize it as
/// a string while the SignalR hub stays numeric for backwards compatibility.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum DesktopSessionTypeDto
{
  Console = 0,
  Rdp = 1
}
