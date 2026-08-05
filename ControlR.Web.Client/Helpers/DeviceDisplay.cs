namespace ControlR.Web.Client.Helpers;

public static class DeviceDisplay
{
  public static string GetAliasDisplay(DeviceResponseDto device) =>
    string.IsNullOrWhiteSpace(device.Alias) ? "—" : device.Alias;

  public static string GetCustomerDisplay(DeviceResponseDto device) =>
    string.IsNullOrWhiteSpace(device.CustomerName) ? "—" : device.CustomerName;

  public static string GetFullDisplayName(DeviceResponseDto device) =>
    $"{device.Name}  (Customer: {GetCustomerDisplay(device)}  |  Alias: {GetAliasDisplay(device)}  |  Device ID: {GetIdDisplay(device)})";

  public static string GetIdDisplay(DeviceResponseDto device) =>
    device.Id.ToString()[..8] + "...";}
