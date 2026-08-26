using ControlR.Web.Server.Authn;
using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Services.Authorization.Capabilities;

namespace ControlR.Web.Server.Tests;

public class DesktopSessionAccessAuthorizerTests
{
  private readonly DesktopSessionAccessAuthorizer _authorizer = new();

  [Fact]
  public void NonLogonToken_IsUnrestricted()
  {
    var principal = new PrincipalDescriptor(PrincipalType.User, Guid.NewGuid(), Guid.NewGuid(), "cookie");

    Assert.True(_authorizer.CanUse(principal, Guid.NewGuid(), 23));
  }

  [Fact]
  public void RestrictedLogonTokenWithNoParsedIds_FailsClosed()
  {
    var deviceId = Guid.NewGuid();
    var principal = CreateLogonTokenPrincipal(deviceId, null, hasRestriction: true);

    Assert.False(_authorizer.CanUse(principal, deviceId, 23));
  }

  [Fact]
  public void RestrictedLogonToken_AllowsOnlyListedSession()
  {
    var deviceId = Guid.NewGuid();
    var principal = CreateLogonTokenPrincipal(deviceId, new HashSet<int> { 23, 24 }, hasRestriction: true);

    Assert.True(_authorizer.CanUse(principal, deviceId, 23));
    Assert.True(_authorizer.CanUse(principal, deviceId, 24));
    Assert.False(_authorizer.CanUse(principal, deviceId, 25));
  }

  [Fact]
  public void UnrestrictedLogonToken_AllowsSessionsOnBoundDevice()
  {
    var deviceId = Guid.NewGuid();
    var principal = CreateLogonTokenPrincipal(deviceId);

    Assert.True(_authorizer.CanUse(principal, deviceId, 23));
    Assert.False(_authorizer.CanUse(principal, Guid.NewGuid(), 23));
  }

  private static PrincipalDescriptor CreateLogonTokenPrincipal(
    Guid deviceId,
    IReadOnlySet<int>? allowedSessionIds = null,
    bool hasRestriction = false) =>
    new(
      PrincipalType.User,
      Guid.NewGuid(),
      Guid.NewGuid(),
      PrincipalClaimValues.LogonTokenMethod,
      Guid.NewGuid(),
      CredentialType.LogonToken,
      deviceId,
      allowedSessionIds,
      hasRestriction);
}
