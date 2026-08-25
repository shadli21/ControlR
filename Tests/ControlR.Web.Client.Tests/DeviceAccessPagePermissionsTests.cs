using System.Reflection;
using ControlR.Web.Client.Components.Layout.DeviceAccess;

namespace ControlR.Web.Client.Tests;

public class DeviceAccessPagePermissionsTests
{
  [Fact]
  public void AllDeviceAccessRoutes_AreRepresentedInAllRoutes()
  {
    var deviceAccessRouteValues = typeof(ClientRoutes)
      .GetFields(BindingFlags.Public | BindingFlags.Static | BindingFlags.FlattenHierarchy)
      .Where(f => f.IsLiteral && f.FieldType == typeof(string) && f.Name.StartsWith("DeviceAccess"))
      .Select(f => (string)f.GetValue(null)!)
      .ToArray();

    var allRoutesSet = DeviceAccessPagePermissions.AllRoutes.ToHashSet();

    var missing = deviceAccessRouteValues
      .Where(route => !allRoutesSet.Contains(route))
      .ToArray();

    Assert.True(
      missing.Length == 0,
      $"The following DeviceAccess routes are missing from AllRoutes: {string.Join(", ", missing)}");
  }
}
