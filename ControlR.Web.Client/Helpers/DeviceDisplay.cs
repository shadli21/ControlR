namespace ControlR.Web.Client.Helpers;

public static class DeviceDisplay
{
  public static string GetCustomerDisplay(DeviceResponseDto device) =>
    string.IsNullOrWhiteSpace(device.CustomerName) ? "(none)" : device.CustomerName;

  public static string GetDisplayName(DeviceResponseDto device)
  {
    var customer = GetCustomerDisplay(device);
    var alias = string.IsNullOrWhiteSpace(device.Alias) ? "" : $"  |  Alias: {device.Alias}";
    return $"{device.Name}  (Customer: {customer}{alias}  |  Device ID: {device.Id.ToString()[..8]}...)";
  }
}
