using ControlR.Libraries.Shared.Dtos.Devices;

namespace ControlR.Libraries.Shared.Dtos.HubDtos;

[MessagePackObject(keyAsPropertyName: true)]
public record InvokeCtrlAltDelRequestDto(
  int TargetDesktopProcessId, 
  string InvokerUserName, 
  DesktopSessionType DesktopSessionType);
