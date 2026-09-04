using ControlR.Libraries.Api.Contracts.Dtos.Devices;

namespace ControlR.Libraries.Api.Contracts.Dtos.ServerApi.V1;

public record DesktopSessionResponseDto(
  bool AreRemoteControlPermissionsGranted,
  string DesktopName,
  string Name,
  int ProcessId,
  int SystemSessionId,
  DesktopSessionTypeDto Type,
  string Username)
{
  public static DesktopSessionResponseDto From(DesktopSession session)
  {
    return new(
      session.AreRemoteControlPermissionsGranted,
      session.DesktopName,
      session.Name,
      session.ProcessId,
      session.SystemSessionId,
      (DesktopSessionTypeDto)session.Type,
      session.Username);
  }
}
