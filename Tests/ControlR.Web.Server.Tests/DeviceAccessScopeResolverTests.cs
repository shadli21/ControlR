using System.Security.Claims;
using ControlR.Web.Server.Authn;
using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Services.Authorization.PermissionRules;
using ControlR.Web.Server.Services.DeviceManagement;
using Moq;

namespace ControlR.Web.Server.Tests;

/// <summary>
/// Focused tests for the fail-closed guard in <see cref="DeviceAccessScopeResolver"/>.
/// When the authentication method is logon-token but the DeviceSessionScope claim is absent or
/// invalid, Resolve must return <see cref="DeviceAccessScope.None()"/> instead of falling through
/// to full device.read rule resolution.
/// </summary>
public class DeviceAccessScopeResolverTests
{
  [Fact]
  public async Task Resolve_LogonTokenWithInvalidScope_FailsClosedToNone()
  {
    var ruleResolver = new Mock<IPermissionRuleResolver>();
    var resolver = new DeviceAccessScopeResolver(ruleResolver.Object);
    var principal = CreateLogonTokenPrincipal("not-a-guid");

    var scope = await resolver.Resolve(principal, TestContext.Current.CancellationToken);

    Assert.Equal(DeviceAccessScopeKind.None, scope.Kind);
    ruleResolver.Verify(
      x => x.Resolve(It.IsAny<PrincipalDescriptor>(), It.IsAny<CancellationToken>()),
      Times.Never);
  }

  [Fact]
  public async Task Resolve_LogonTokenWithMissingScope_FailsClosedToNone()
  {
    var ruleResolver = new Mock<IPermissionRuleResolver>();
    var resolver = new DeviceAccessScopeResolver(ruleResolver.Object);
    var principal = CreateLogonTokenPrincipal(deviceSessionScopeValue: null);

    var scope = await resolver.Resolve(principal, TestContext.Current.CancellationToken);

    Assert.Equal(DeviceAccessScopeKind.None, scope.Kind);
    ruleResolver.Verify(
      x => x.Resolve(It.IsAny<PrincipalDescriptor>(), It.IsAny<CancellationToken>()),
      Times.Never);
  }

  [Fact]
  public async Task Resolve_LogonTokenWithValidScope_ReturnsSingleDevice()
  {
    var ruleResolver = new Mock<IPermissionRuleResolver>();
    var resolver = new DeviceAccessScopeResolver(ruleResolver.Object);
    var deviceId = Guid.NewGuid();
    var principal = CreateLogonTokenPrincipal(deviceId.ToString());

    var scope = await resolver.Resolve(principal, TestContext.Current.CancellationToken);

    Assert.Equal(DeviceAccessScopeKind.SingleDevice, scope.Kind);
    Assert.Equal(deviceId, scope.DeviceId);
    // The rule resolver must never be consulted on the logon-token path.
    ruleResolver.Verify(
      x => x.Resolve(It.IsAny<PrincipalDescriptor>(), It.IsAny<CancellationToken>()),
      Times.Never);
  }

  private static ClaimsPrincipal CreateLogonTokenPrincipal(string? deviceSessionScopeValue)
  {
    var claims = new List<Claim>
    {
      new(UserClaimTypes.AuthenticationMethod, PrincipalClaimValues.LogonTokenMethod),
      new(PrincipalClaimTypes.PrincipalType, PrincipalClaimValues.User),
      new(PrincipalClaimTypes.PrincipalId, Guid.NewGuid().ToString())
    };

    if (deviceSessionScopeValue is not null)
    {
      claims.Add(new Claim(UserClaimTypes.DeviceSessionScope, deviceSessionScopeValue));
    }

    return new ClaimsPrincipal(new ClaimsIdentity(claims, "TestAuth"));
  }
}
