using System.Reflection;

namespace ControlR.Web.Server.Tests;

public class PermissionPresetsCoverageTests
{
  [Fact]
  public void AllPermissionNames_AreCoveredByAtLeastOnePreset()
  {
    var permissionNameFields = typeof(PermissionNames)
      .GetFields(BindingFlags.Public | BindingFlags.Static | BindingFlags.FlattenHierarchy)
      .Where(f => f.IsLiteral && f.FieldType == typeof(string))
      .Select(f => (string)f.GetValue(null)!)
      .ToArray();

    var allPresetPermissions = PermissionPresets.All.Values
      .SelectMany(x => x)
      .ToHashSet();

    var uncovered = permissionNameFields
      .Where(name => !allPresetPermissions.Contains(name))
      .ToArray();

    Assert.True(
      uncovered.Length == 0,
      $"The following permissions are not in any preset: {string.Join(", ", uncovered)}");
  }
}
