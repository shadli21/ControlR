using ControlR.Libraries.Shared.Services.StateManagement;

namespace ControlR.Libraries.Viewer.Common.State;

public interface IDeviceState : IStateBase
{
  DeviceResponseDto CurrentDevice { get; set; }
  bool IsDeviceLoaded { get; }
  DeviceResponseDto? TryGetCurrentDevice();
}

public class DeviceState(ILogger<DeviceState> logger) : ObservableState(logger), IDeviceState
{
  public DeviceResponseDto CurrentDevice
  {
    get => Get<DeviceResponseDto?>() ?? throw new InvalidOperationException("CurrentDevice is not set.");
    set => Set(value);
  }

  public bool IsDeviceLoaded => Get<DeviceResponseDto>(propertyName: nameof(CurrentDevice)) != null;

  public DeviceResponseDto? TryGetCurrentDevice() => Get<DeviceResponseDto?>(propertyName: nameof(CurrentDevice));
}