namespace ControlR.Web.Client.Helpers;

public static class DeviceDisplay
{
  private const string Unassigned = "—";

  public static string GetCustomerDisplay(DeviceResponseDto device)
  {
    return string.IsNullOrWhiteSpace(device.CustomerName) ? Unassigned : device.CustomerName;
  }

  public static string GetDisplayName(DeviceResponseDto device)
  {
    var segments = new List<string>
    {
      $"Name: {device.Name}"
    };

    if (!string.IsNullOrWhiteSpace(device.Alias))
    {
      segments.Add($"Alias: {device.Alias}");
    }

    segments.Add($"Customer: {GetCustomerDisplay(device)}");

    return string.Join(" | ", segments);
  }
}
