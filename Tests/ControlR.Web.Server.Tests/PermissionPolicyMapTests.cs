using ControlR.Web.Client.Authz;
using ControlR.Web.Server.Authz.Permissions;

namespace ControlR.Web.Server.Tests;

public class PermissionPolicyMapTests
{
  [Fact]
  public void PolicyToPermission_Values_AreKnownCatalogPermissions()
  {
    foreach (var (policyName, permissionName) in PermissionPolicies.PolicyToPermission)
    {
      Assert.True(
        PermissionCatalog.Exists(permissionName),
        $"Policy '{policyName}' maps to permission '{permissionName}', which is not in the PermissionCatalog.");
    }
  }
}
