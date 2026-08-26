using System.Security.Claims;
using ControlR.Libraries.Api.Contracts.Authz;
using ControlR.Web.Client.Extensions;

namespace ControlR.Web.Client.Tests;

public class ClientPolicyGrantTests
{
  [Fact]
  public void HasClientPolicy_MatchesGrantedPolicy()
  {
    var principal = new ClaimsPrincipal(new ClaimsIdentity(
    [
      new Claim(PermissionPolicies.ClientPolicyClaimType, PolicyNames.RequireCustomersWrite)
    ], "test"));

    Assert.True(principal.HasClientPolicy(PolicyNames.RequireCustomersWrite));
  }

  [Fact]
  public void HasClientPolicy_OnePolicyDoesNotSatisfyAnotherBackedBySamePermission()
  {
    // Two policies can share a permission; a grant for one must not satisfy the other unless
    // both policy claims were emitted.
    var principal = new ClaimsPrincipal(new ClaimsIdentity(
    [
      new Claim(PermissionPolicies.ClientPolicyClaimType, PolicyNames.RequireCustomersRead)
    ], "test"));

    Assert.True(principal.HasClientPolicy(PolicyNames.RequireCustomersRead));
    Assert.False(principal.HasClientPolicy(PolicyNames.RequireCustomersWrite));
  }

  [Fact]
  public void HasClientPolicy_PermissionNameValueDoesNotSatisfyPolicyGrant()
  {
    // A raw permission-name value under the client-policy claim type must not satisfy a policy
    // grant. Only exact policy names are emitted by the server.
    var principal = new ClaimsPrincipal(new ClaimsIdentity(
    [
      new Claim(PermissionPolicies.ClientPolicyClaimType, "TenantCustomersWrite")
    ], "test"));

    Assert.False(principal.HasClientPolicy(PolicyNames.RequireCustomersWrite));
  }

  [Fact]
  public void HasClientPolicy_ResourcePermissionNameDoesNotMatch()
  {
    // Resource-scoped permission names are never emitted as global client-policy claims.
    var principal = new ClaimsPrincipal(new ClaimsIdentity(
    [
      new Claim(PermissionPolicies.ClientPolicyClaimType, PermissionNames.DeviceTagsWrite)
    ], "test"));

    Assert.False(principal.HasClientPolicy(PolicyNames.RequireTagsWrite));
  }

  [Fact]
  public void HasClientPolicy_UnauthenticatedReturnsFalse()
  {
    var principal = new ClaimsPrincipal(new ClaimsIdentity());

    Assert.False(principal.HasClientPolicy(PolicyNames.RequireCustomersWrite));
  }
}
