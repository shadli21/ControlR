using System.Text.Encodings.Web;
using ControlR.Web.Server.Authn;
using ControlR.Web.Server.Data.Entities;
using ControlR.Web.Server.Services.LogonTokens;
using ControlR.Web.Server.Tests.Helpers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace ControlR.Web.Server.Tests;

public class LogonTokenAuthenticationHandlerTests(ITestOutputHelper testOutput)
{
  private readonly ITestOutputHelper _testOutputHelper = testOutput;

  [Fact]
  public async Task HandleAuthenticateAsync_LockedOutUser_ReturnsFail()
  {
    // Arrange
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutputHelper);
    using var scope = testApp.CreateScope();
    var services = scope.ServiceProvider;

    var tenant = await services.CreateTestTenant();
    var user = await services.CreateTestUser(tenant.Id);
    var device = await services.CreateTestDevice(tenant.Id);

    // Create a logon token for the user
    var logonTokenProvider = services.GetRequiredService<ILogonTokenProvider>();
    var tokenResult = await logonTokenProvider.CreateToken(
      device.Id, tenant.Id, user.Id,
      cancellationToken: TestContext.Current.CancellationToken);
    Assert.True(tokenResult.IsSuccess);
    var token = tokenResult.Value!.Token;

    // Lock the user out (re-fetch via UserManager so EF tracks the instance correctly)
    var userManager = services.GetRequiredService<UserManager<AppUser>>();
    var trackedUser = await userManager.FindByIdAsync(user.Id.ToString());
    Assert.NotNull(trackedUser);
    await userManager.SetLockoutEnabledAsync(trackedUser, true);
    await userManager.SetLockoutEndDateAsync(trackedUser, DateTimeOffset.UtcNow.AddHours(1));

    var context = CreateHttpContext(services, token, device.Id);
    var handler = await CreateHandler(services, context);

    // Act
    var result = await handler.AuthenticateAsync();

    // Assert
    Assert.False(result.Succeeded);
    Assert.NotNull(result.Failure);
    Assert.Equal("User account is locked", result.Failure.Message);
  }

  [Fact]
  public async Task HandleAuthenticateAsync_ValidToken_EmitsLogonTokenMethodClaim()
  {
    // Arrange — pins the canonical claim set emitted by the logon-token handler.
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutputHelper);
    using var scope = testApp.CreateScope();
    var services = scope.ServiceProvider;

    var tenant = await services.CreateTestTenant();
    var user = await services.CreateTestUser(tenant.Id);
    var device = await services.CreateTestDevice(tenant.Id);

    var logonTokenProvider = services.GetRequiredService<ILogonTokenProvider>();
    var tokenResult = await logonTokenProvider.CreateToken(
      device.Id, tenant.Id, user.Id,
      cancellationToken: TestContext.Current.CancellationToken);
    Assert.True(tokenResult.IsSuccess);
    var token = tokenResult.Value!.Token;

    var context = CreateHttpContext(services, token, device.Id);
    var handler = await CreateHandler(services, context);

    // Act
    var result = await handler.AuthenticateAsync();

    // Assert
    Assert.True(result.Succeeded);
    Assert.NotNull(result.Principal);
    Assert.NotNull(result.Principal.Identity);
    Assert.True(result.Principal.Identity.IsAuthenticated);
    Assert.Equal(
      LogonTokenAuthenticationSchemeOptions.DefaultScheme,
      result.Principal.Identity.AuthenticationType);

    var tenantClaim = result.Principal.FindFirst(UserClaimTypes.TenantId);
    Assert.NotNull(tenantClaim);
    Assert.Equal(tenant.Id.ToString(), tenantClaim.Value);

    var authMethodClaim = result.Principal.FindFirst(UserClaimTypes.AuthenticationMethod);
    Assert.NotNull(authMethodClaim);
    Assert.Equal(PrincipalClaimValues.LogonTokenMethod, authMethodClaim.Value);

    var deviceSessionScopeClaim = result.Principal.FindFirst(UserClaimTypes.DeviceSessionScope);
    Assert.NotNull(deviceSessionScopeClaim);
    Assert.Equal(device.Id.ToString(), deviceSessionScopeClaim.Value);

    var principalTypeClaim = result.Principal.FindFirst(PrincipalClaimTypes.PrincipalType);
    Assert.NotNull(principalTypeClaim);
    Assert.Equal(PrincipalClaimValues.User, principalTypeClaim.Value);
  }

  private static DefaultHttpContext CreateHttpContext(IServiceProvider services, string token, Guid deviceId)
  {
    var context = new DefaultHttpContext
    {
      Request =
      {
        QueryString = new QueryString($"?logonToken={Uri.EscapeDataString(token)}&deviceId={deviceId}"),
      },
      RequestServices = services,
    };
    return context;
  }

  private async Task<LogonTokenAuthenticationHandler> CreateHandler(
    IServiceProvider services,
    HttpContext context)
  {
    var options = services.GetRequiredService<IOptionsMonitor<LogonTokenAuthenticationSchemeOptions>>();
    var loggerFactory = services.GetRequiredService<ILoggerFactory>();
    var userManager = services.GetRequiredService<UserManager<AppUser>>();
    var timeProvider = services.GetRequiredService<TimeProvider>();
    var logonTokenProvider = services.GetRequiredService<ILogonTokenProvider>();

    var scheme = new AuthenticationScheme(
      LogonTokenAuthenticationSchemeOptions.DefaultScheme,
      LogonTokenAuthenticationSchemeOptions.DefaultScheme,
      typeof(LogonTokenAuthenticationHandler));

    var handler = new LogonTokenAuthenticationHandler(
      UrlEncoder.Default,
      userManager,
      timeProvider,
      options,
      loggerFactory,
      logonTokenProvider);

    await handler.InitializeAsync(scheme, context);

    return handler;
  }
}
