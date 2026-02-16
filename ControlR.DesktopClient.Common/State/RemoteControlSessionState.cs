using ControlR.Libraries.Shared.Services.StateManagement;
using Microsoft.Extensions.Logging;

namespace ControlR.DesktopClient.Common.State;

internal interface IRemoteControlSessionState : IStateBase
{
  bool CaptureCursor { get; set; }
  int ImageQuality { get; set; }
}

internal class RemoteControlSessionState(ILogger<RemoteControlSessionState> logger)
  : ObservableState(logger), IRemoteControlSessionState
{
  public bool CaptureCursor
  {
    get => Get<bool>();
    set => Set(value);
  }
  public int ImageQuality
  {
    get => Get(defaultValue: 75);
    set => Set(value);
  }
}