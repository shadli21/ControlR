using System.Security.Claims;
using ControlR.Web.Server.Authn;
using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Services.Authorization;
using ControlR.Web.Server.Services.Authorization.PermissionRules;
using ControlR.Web.Server.Services.DeviceManagement;
using Moq;

namespace ControlR.Web.Server.Tests;

public class DeviceAccessScopeResolverTests
{
  [Fact]
  public async Task Resolve_LogonTokenWithInvalidScope_FailsClosedToNone()
  {
    var contextLoader = CreateEmptyContextLoader();
    var resolver = new DeviceAccessScopeResolver(contextLoader.Object);
    var principal = CreateLogonTokenPrincipal("not-a-guid");

    var scope = await resolver.Resolve(principal, TestContext.Current.CancellationToken);

    Assert.False(scope.IncludesServerWide);
    Assert.Empty(scope.IncludedDeviceIds);
  }

  [Fact]
  public async Task Resolve_LogonTokenWithMissingScope_FailsClosedToNone()
  {
    var contextLoader = CreateEmptyContextLoader();
    var resolver = new DeviceAccessScopeResolver(contextLoader.Object);
    var principal = CreateLogonTokenPrincipal(deviceSessionScopeValue: null);

    var scope = await resolver.Resolve(principal, TestContext.Current.CancellationToken);

    Assert.Empty(scope.IncludedDeviceIds);
  }

  [Fact]
  public async Task Resolve_LogonTokenWithValidReadGrant_ReturnsSingleDevice()
  {
    var deviceId = Guid.NewGuid();
    var contextLoader = new Mock<IPermissionEvaluationContextLoader>();
    contextLoader
      .Setup(loader => loader.Load(It.IsAny<PrincipalDescriptor>(), It.IsAny<CancellationToken>()))
      .ReturnsAsync((PrincipalDescriptor principal, CancellationToken _) =>
        new PermissionEvaluationContext(
          principal,
          false,
          [],
          [new PermissionRule(
            PermissionNames.DeviceRead,
            PermissionEffect.Allow,
            PermissionScopeKind.Device,
            deviceId,
            principal.TenantId,
            RuleSource.LogonTokenGrant,
            SourcePriority.CredentialLogonToken)],
          false));
    var resolver = new DeviceAccessScopeResolver(contextLoader.Object);
    var principal = CreateLogonTokenPrincipal(deviceId.ToString());

    var scope = await resolver.Resolve(principal, TestContext.Current.CancellationToken);

    Assert.Equal([deviceId], scope.IncludedDeviceIds);
  }

  private static Mock<IPermissionEvaluationContextLoader> CreateEmptyContextLoader()
  {
    var contextLoader = new Mock<IPermissionEvaluationContextLoader>();
    contextLoader
      .Setup(loader => loader.Load(It.IsAny<PrincipalDescriptor>(), It.IsAny<CancellationToken>()))
      .ReturnsAsync((PrincipalDescriptor principal, CancellationToken _) =>
        new PermissionEvaluationContext(principal, false, [], [], false));
    return contextLoader;
  }

  private static ClaimsPrincipal CreateLogonTokenPrincipal(string? deviceSessionScopeValue)
  {
    var claims = new List<Claim>
    {
      new(UserClaimTypes.AuthenticationMethod, PrincipalClaimValues.LogonTokenMethod),
      new(PrincipalClaimTypes.PrincipalType, PrincipalClaimValues.User),
      new(PrincipalClaimTypes.PrincipalId, Guid.NewGuid().ToString()),
      new(PrincipalClaimTypes.CredentialId, Guid.NewGuid().ToString()),
      new(PrincipalClaimTypes.CredentialType, CredentialType.LogonToken.ToString())
    };

    if (deviceSessionScopeValue is not null)
    {
      claims.Add(new Claim(UserClaimTypes.DeviceSessionScope, deviceSessionScopeValue));
    }

    return new ClaimsPrincipal(new ClaimsIdentity(claims, "TestAuth"));
  }
}
