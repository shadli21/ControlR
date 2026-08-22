using System.Security.Claims;
using ControlR.Web.Server.Authn;
using ControlR.Web.Server.Authz.Permissions;

namespace ControlR.Web.Server.Tests;

public class PrincipalDescriptorBuilderTests
{
  [Fact]
  public void FromClaims_DesktopSessionRestrictionClaims_ParsesAllowedIds()
  {
    var principal = new ClaimsPrincipal(new ClaimsIdentity(
    [
      new Claim(PrincipalClaimTypes.PrincipalType, PrincipalClaimValues.User),
      new Claim(PrincipalClaimTypes.PrincipalId, Guid.NewGuid().ToString()),
      new Claim(UserClaimTypes.TenantId, Guid.NewGuid().ToString()),
      new Claim(UserClaimTypes.AuthenticationMethod, PrincipalClaimValues.LogonTokenMethod),
      new Claim(UserClaimTypes.AllowedDesktopSessionId, "1"),
      new Claim(UserClaimTypes.AllowedDesktopSessionId, "2"),
      new Claim(UserClaimTypes.DesktopSessionRestriction, bool.TrueString)
    ], "TestAuth"));

    var descriptor = PrincipalDescriptorBuilder.FromClaims(principal);

    Assert.NotNull(descriptor);
    Assert.NotNull(descriptor.AllowedDesktopSessionIds);
    Assert.Equal(new HashSet<int> { 1, 2 }, descriptor.AllowedDesktopSessionIds);
    Assert.True(descriptor.HasDesktopSessionRestriction);
  }

  [Fact]
  public void FromClaims_DesktopSessionRestrictionClaim_WithoutIds_IsNotRestricted()
  {
    // Restriction flag present with no allowed ids -> empty set normalized to null.
    var principal = new ClaimsPrincipal(new ClaimsIdentity(
    [
      new Claim(PrincipalClaimTypes.PrincipalType, PrincipalClaimValues.User),
      new Claim(PrincipalClaimTypes.PrincipalId, Guid.NewGuid().ToString()),
      new Claim(UserClaimTypes.TenantId, Guid.NewGuid().ToString()),
      new Claim(UserClaimTypes.AuthenticationMethod, PrincipalClaimValues.LogonTokenMethod),
      new Claim(UserClaimTypes.DesktopSessionRestriction, bool.TrueString)
    ], "TestAuth"));

    var descriptor = PrincipalDescriptorBuilder.FromClaims(principal);

    Assert.NotNull(descriptor);
    Assert.Null(descriptor.AllowedDesktopSessionIds);
    Assert.True(descriptor.HasDesktopSessionRestriction);
  }

  [Fact]
  public void FromClaims_MalformedPrincipalId_ReturnsNull()
  {
    var principal = new ClaimsPrincipal(new ClaimsIdentity(
    [
      new Claim(PrincipalClaimTypes.PrincipalType, PrincipalClaimValues.User),
      new Claim(PrincipalClaimTypes.PrincipalId, "not-a-guid"),
      new Claim(UserClaimTypes.TenantId, Guid.NewGuid().ToString())
    ], "TestAuth"));

    Assert.Null(PrincipalDescriptorBuilder.FromClaims(principal));
  }

  [Fact]
  public void FromClaims_MissingCanonicalClaims_ReturnsNull()
  {
    // No principal type or principal id claim at all.
    var principal = new ClaimsPrincipal(new ClaimsIdentity(
    [
      new Claim(UserClaimTypes.TenantId, Guid.NewGuid().ToString())
    ], "TestAuth"));

    Assert.Null(PrincipalDescriptorBuilder.FromClaims(principal));
  }

  [Fact]
  public void FromClaims_NonCanonicalDesktopSessionRestrictionValue_IsNotRestricted()
  {
    // Restriction claim must carry the exact boolean string; anything else is ignored.
    var principal = new ClaimsPrincipal(new ClaimsIdentity(
    [
      new Claim(PrincipalClaimTypes.PrincipalType, PrincipalClaimValues.User),
      new Claim(PrincipalClaimTypes.PrincipalId, Guid.NewGuid().ToString()),
      new Claim(UserClaimTypes.TenantId, Guid.NewGuid().ToString()),
      new Claim(UserClaimTypes.AllowedDesktopSessionId, "1"),
      new Claim(UserClaimTypes.DesktopSessionRestriction, "TRUE")
    ], "TestAuth"));

    var descriptor = PrincipalDescriptorBuilder.FromClaims(principal);

    Assert.NotNull(descriptor);
    Assert.False(descriptor.HasDesktopSessionRestriction);
  }

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
