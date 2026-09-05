using System.Net;
using System.Net.Http.Json;
using ControlR.Web.Server.Authn;
using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Services;
using ControlR.Web.Server.Tests.Helpers;
using Microsoft.Extensions.DependencyInjection;

namespace ControlR.Web.Server.Tests;

public class LogonTokenDeviceScopeTests(ITestOutputHelper testOutput)
{
  private readonly ITestOutputHelper _testOutput = testOutput;

  [Fact]
  public async Task LogonTokenSession_CannotManagePersonalAccessTokens()
  {
    // The logon token's application cookie must not reach the self-PAT endpoints. The token's
    // grants are device-scoped, so the tenant-scoped self PAT permissions can never be held
    // through it. Without that boundary a scoped device session could mint an InheritOwner
    // PAT and inherit the owner's full effective permissions.
    using var testApp = await TestWebServerBuilder.CreateTestServer(_testOutput);
    using var httpClient = testApp.Factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

    var deviceId = Guid.NewGuid();

    // The test user is the instance's first user, so it becomes a server administrator with
    // full tenant rights. The logon token derived from it must still be device-scoped.
    var user = await testApp.TestServer.Services.CreateTestUser();
    await testApp.TestServer.Services.CreateTestDevice(user.TenantId, deviceId);

    var patManager = testApp.TestServer.Services.GetRequiredService<IPersonalAccessTokenManager>();
    var patCreate = await patManager.CreateToken(
      new InternalDtos.CreatePersonalAccessTokenRequestDto("Escalation Test PAT", PersonalAccessTokenPermissionMode.InheritOwner),
      user.Id,
      new PrincipalDescriptor(PrincipalType.User, user.Id, user.TenantId, "test"));
    Assert.True(patCreate.IsSuccess, patCreate.Reason);

    httpClient.DefaultRequestHeaders.Add(PersonalAccessTokenAuthenticationSchemeOptions.DefaultHeaderName, patCreate.Value.PlainTextToken);
    var logonTokenResponse = await httpClient.PostAsJsonAsync(
      HttpConstants.Internal.LogonTokensEndpoint,
      new InternalDtos.LogonTokenRequestDto(deviceId, ExpirationMinutes: 5),
      TestContext.Current.CancellationToken);
    logonTokenResponse.EnsureSuccessStatusCode();
    var logonTokenResult = await logonTokenResponse.Content.ReadFromJsonAsync<InternalDtos.LogonTokenResponseDto>(TestContext.Current.CancellationToken);
    Assert.NotNull(logonTokenResult);

    // Consume the logon token to establish the cookie session.
    var firstAccess = await httpClient.GetAsync(logonTokenResult.DeviceAccessUrl, TestContext.Current.CancellationToken);
    Assert.True(
      firstAccess.IsSuccessStatusCode ||
      firstAccess.StatusCode == HttpStatusCode.Redirect ||
      firstAccess.StatusCode == HttpStatusCode.Found,
      $"Expected logon token consumption to succeed, got {firstAccess.StatusCode}");

    // Drop the PAT header so subsequent requests authenticate with the logon-token cookie only.
    httpClient.DefaultRequestHeaders.Remove(PersonalAccessTokenAuthenticationSchemeOptions.DefaultHeaderName);

    var listResponse = await httpClient.GetAsync(HttpConstants.Internal.PersonalAccessTokensEndpoint, TestContext.Current.CancellationToken);
    Assert.Equal(HttpStatusCode.Forbidden, listResponse.StatusCode);

    var createResponse = await httpClient.PostAsJsonAsync(
      HttpConstants.Internal.PersonalAccessTokensEndpoint,
      new InternalDtos.CreatePersonalAccessTokenRequestDto("Escalated PAT", PersonalAccessTokenPermissionMode.InheritOwner),
      TestContext.Current.CancellationToken);
    Assert.Equal(HttpStatusCode.Forbidden, createResponse.StatusCode);
  }

  [Fact]
  public async Task LogonTokenSession_ShouldBeRestrictedToSingleDevice()
  {
    using var testApp = await TestWebServerBuilder.CreateTestServer(_testOutput);
    using var httpClient = testApp.Factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

    var primaryDeviceId = Guid.NewGuid();
    var otherDeviceId = Guid.NewGuid();

    // Setup tenant + devices + user
    var user = await testApp.TestServer.Services.CreateTestUser();
    await testApp.TestServer.Services.CreateTestDevice(user.TenantId, primaryDeviceId);
    await testApp.TestServer.Services.CreateTestDevice(user.TenantId, otherDeviceId);

    // Create PAT
    var patManager = testApp.TestServer.Services.GetRequiredService<IPersonalAccessTokenManager>();
    var patCreate = await patManager.CreateToken(new InternalDtos.CreatePersonalAccessTokenRequestDto("ScopeTest PAT", PersonalAccessTokenPermissionMode.InheritOwner), user.Id, new PrincipalDescriptor(PrincipalType.User, user.Id, user.TenantId, "test"));
    Assert.True(patCreate.IsSuccess, patCreate.Reason);
    var pat = patCreate.Value.PlainTextToken;

    // Request logon token for primary device
    httpClient.DefaultRequestHeaders.Add(PersonalAccessTokenAuthenticationSchemeOptions.DefaultHeaderName, pat);
    var logonTokenRequest = new InternalDtos.LogonTokenRequestDto(primaryDeviceId, ExpirationMinutes: 5);
    var logonTokenResponse = await httpClient.PostAsJsonAsync(HttpConstants.Internal.LogonTokensEndpoint, logonTokenRequest, cancellationToken: TestContext.Current.CancellationToken);
    logonTokenResponse.EnsureSuccessStatusCode();
    var logonTokenResult = await logonTokenResponse.Content.ReadFromJsonAsync<InternalDtos.LogonTokenResponseDto>(TestContext.Current.CancellationToken);
    Assert.NotNull(logonTokenResult);

    // Consume logon token (first access) to establish cookie session
    var firstAccess = await httpClient.GetAsync(logonTokenResult.DeviceAccessUrl, TestContext.Current.CancellationToken);
    Assert.True(firstAccess.IsSuccessStatusCode || firstAccess.StatusCode == HttpStatusCode.Redirect || firstAccess.StatusCode == HttpStatusCode.Found);

    // Remove PAT header so that subsequent API requests use the established cookie session
    httpClient.DefaultRequestHeaders.Remove(PersonalAccessTokenAuthenticationSchemeOptions.DefaultHeaderName);

    // Attempt to access primary device API (should succeed)
    var primaryDeviceApi = await httpClient.GetAsync($"{HttpConstants.Internal.DevicesEndpoint}/{primaryDeviceId}", TestContext.Current.CancellationToken);
    Assert.True(primaryDeviceApi.IsSuccessStatusCode, $"Expected success for primary device, got {primaryDeviceApi.StatusCode}");

    // Attempt to access other device API (should be hidden as not found due to DeviceSessionScope restriction)
    var otherDeviceApi = await httpClient.GetAsync($"{HttpConstants.Internal.DevicesEndpoint}/{otherDeviceId}", TestContext.Current.CancellationToken);
    Assert.True(
      otherDeviceApi.StatusCode == HttpStatusCode.NotFound ||
      otherDeviceApi.StatusCode == HttpStatusCode.Forbidden ||
      otherDeviceApi.StatusCode == HttpStatusCode.Unauthorized,
      $"Expected NotFound/Forbidden/Unauthorized for other device, got {otherDeviceApi.StatusCode}");
  }
}
