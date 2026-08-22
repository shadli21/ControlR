using System.Security.Claims;
using ControlR.Web.Server.Authn;
using ControlR.Web.Server.Authz.Permissions;

namespace ControlR.Web.Server.Tests;

public class PrincipalDescriptorBuilderTests
{
  [Fact]
  public void FromClaims_ServerServiceAccountWithoutTenantClaim_ReturnsDescriptor()
  {
    var principal = new ClaimsPrincipal(new ClaimsIdentity(
    [
      new Claim(PrincipalClaimTypes.PrincipalType, PrincipalClaimValues.ServerServiceAccount),
      new Claim(PrincipalClaimTypes.PrincipalId, Guid.NewGuid().ToString())
    ], "TestAuth"));

    var descriptor = PrincipalDescriptorBuilder.FromClaims(principal);

    Assert.NotNull(descriptor);
    Assert.Null(descriptor.TenantId);
    Assert.Equal(PrincipalType.ServerServiceAccount, descriptor.PrincipalType);
  }

  [Fact]
  public void FromClaims_UserWithMalformedTenantClaim_ReturnsNull()
  {
    var principal = new ClaimsPrincipal(new ClaimsIdentity(
    [
      new Claim(PrincipalClaimTypes.PrincipalType, PrincipalClaimValues.User),
      new Claim(PrincipalClaimTypes.PrincipalId, Guid.NewGuid().ToString()),
      new Claim(UserClaimTypes.TenantId, "not-a-guid")
    ], "TestAuth"));

    Assert.Null(PrincipalDescriptorBuilder.FromClaims(principal));
  }

  [Fact]
  public void FromClaims_UserWithoutTenantClaim_ReturnsNull()
  {
    var principal = new ClaimsPrincipal(new ClaimsIdentity(
    [
      new Claim(PrincipalClaimTypes.PrincipalType, PrincipalClaimValues.User),
      new Claim(PrincipalClaimTypes.PrincipalId, Guid.NewGuid().ToString())
    ], "TestAuth"));

    Assert.Null(PrincipalDescriptorBuilder.FromClaims(principal));
  }
}
