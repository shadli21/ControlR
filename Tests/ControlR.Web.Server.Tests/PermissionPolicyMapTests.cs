using ControlR.Web.Client.Authz;
using ControlR.Web.Server.Authz.Policies;
using ControlR.Web.Server.Authz.Permissions;
using System.Reflection;

namespace ControlR.Web.Server.Tests;

public class PermissionPolicyMapTests
{
  [Fact]
  public void DeviceResourcePolicies_AllConstantsAreMapped()
  {
    var policyNames = GetPublicStringConstants(typeof(DeviceResourcePolicies));
    var missing = policyNames
      .Where(policyName => !DeviceResourcePolicies.PolicyToPermission.ContainsKey(policyName))
      .ToArray();

    Assert.True(
      missing.Length == 0,
      $"DeviceResourcePolicies constants missing from PolicyToPermission: {string.Join(", ", missing)}");
  }

  [Fact]
  public void PermissionNames_AllConstantsExistInCatalog()
  {
    var permissionNames = GetPublicStringConstants(typeof(PermissionNames));
    var missing = permissionNames
      .Where(permissionName => !PermissionCatalog.Exists(permissionName))
      .ToArray();

    Assert.True(
      missing.Length == 0,
      $"PermissionNames constants missing from PermissionCatalog: {string.Join(", ", missing)}");
  }

  [Fact]
  public void PolicyNames_AllConstantsAreMapped()
  {
    var policyNames = GetPublicStringConstants(typeof(PolicyNames));
    var missing = policyNames
      .Where(policyName => !PermissionPolicies.PolicyToPermission.ContainsKey(policyName))
      .ToArray();

    Assert.True(
      missing.Length == 0,
      $"PolicyNames constants missing from PermissionPolicies.PolicyToPermission: {string.Join(", ", missing)}");
  }

  [Fact]
  public void PolicyToPermission_Values_AreKnownCatalogPermissions()
  {
    foreach (var (policyName, permissionName) in PermissionPolicies.PolicyToPermission)
    {
      Assert.True(
        PermissionCatalog.Exists(permissionName),
        $"Policy '{policyName}' maps to permission '{permissionName}', which is not in the PermissionCatalog.");
    }

    foreach (var (policyName, permissionName) in DeviceResourcePolicies.PolicyToPermission)
    {
      Assert.True(
        PermissionCatalog.Exists(permissionName),
        $"Device policy '{policyName}' maps to permission '{permissionName}', which is not in the PermissionCatalog.");
    }
  }

  private static IReadOnlyList<string> GetPublicStringConstants(Type type) =>
    type
      .GetFields(BindingFlags.Public | BindingFlags.Static)
      .Where(field => field.IsLiteral && field.FieldType == typeof(string))
      .Select(field => (string)field.GetRawConstantValue()!)
      .ToArray();
}
