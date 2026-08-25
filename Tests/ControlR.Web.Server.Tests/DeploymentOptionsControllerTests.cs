using System.Net;
using System.Net.Http.Json;
using ControlR.Web.Server.Authn;
using ControlR.Web.Server.Services;
using ControlR.Web.Server.Tests.Helpers;
using Microsoft.Extensions.DependencyInjection;

namespace ControlR.Web.Server.Tests;

public class DeploymentOptionsControllerTests(ITestOutputHelper testOutput)
{
  private readonly ITestOutputHelper _testOutput = testOutput;

  [Fact]
  public async Task AgentInstaller_CanCreateInstallerKeyWithoutTenantAdminReads()
  {
    using var testServer = await TestWebServerBuilder.CreateTestServer(_testOutput);
    var tenant = await testServer.Services.CreateTestTenant();
    await testServer.Services.CreateTestUser(
      tenant.Id,
      email: $"seed-{Guid.NewGuid():N}@t.local");
    var installer = await testServer.Services.CreateTestUser(
      tenant.Id,
      $"installer-{Guid.NewGuid():N}@t.local",
      PermissionPresets.AgentInstaller);
    using var httpClient = await CreatePatClient(testServer, installer.Id);

    var createKeyResponse = await httpClient.PostAsJsonAsync(
      HttpConstants.Internal.InstallerKeysEndpoint,
      new InternalDtos.CreateInstallerKeyRequestDto(InstallerKeyType.Persistent),
      TestContext.Current.CancellationToken);
    var customersResponse = await httpClient.GetAsync(
      HttpConstants.Internal.CustomersEndpoint,
      TestContext.Current.CancellationToken);
    var tenantSettingsResponse = await httpClient.GetAsync(
      HttpConstants.Internal.TenantSettingsEndpoint,
      TestContext.Current.CancellationToken);

    Assert.Equal(HttpStatusCode.OK, createKeyResponse.StatusCode);
    Assert.Equal(HttpStatusCode.Forbidden, customersResponse.StatusCode);
    Assert.Equal(HttpStatusCode.Forbidden, tenantSettingsResponse.StatusCode);
  }

  [Fact]
  public async Task Get_WithAgentInstallerPreset_ReturnsConfiguredDeploymentSettings()
  {
    using var testServer = await TestWebServerBuilder.CreateTestServer(_testOutput);
    var tenant = await testServer.Services.CreateTestTenant();
    await testServer.Services.CreateTestUser(
      tenant.Id,
      email: $"seed-{Guid.NewGuid():N}@t.local");
    var installer = await testServer.Services.CreateTestUser(
      tenant.Id,
      $"installer-{Guid.NewGuid():N}@t.local",
      PermissionPresets.AgentInstaller);
    using (var scope = testServer.Services.CreateScope())
    {
      var settingsManager = scope.ServiceProvider.GetRequiredService<Services.Settings.ITenantSettingsManager>();
      var result = await settingsManager.SetSettings(
        tenant.Id,
        new InternalDtos.TenantSettingsDto(true, "deployment-instance", null),
        TestContext.Current.CancellationToken);
      Assert.True(result.IsSuccess);
    }

    using var httpClient = await CreatePatClient(testServer, installer.Id);

    var response = await httpClient.GetAsync(
      HttpConstants.Internal.DeploymentOptionsEndpoint,
      TestContext.Current.CancellationToken);
    var options = await response.Content.ReadFromJsonAsync<InternalDtos.DeploymentOptionsDto>(
      TestContext.Current.CancellationToken);

    Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    Assert.NotNull(options);
    Assert.True(options.AppendInstanceId);
    Assert.Equal("deployment-instance", options.InstanceId);
  }

  [Fact]
  public async Task Get_WithoutAgentInstall_ReturnsForbidden()
  {
    using var testServer = await TestWebServerBuilder.CreateTestServer(_testOutput);
    var tenant = await testServer.Services.CreateTestTenant();
    await testServer.Services.CreateTestUser(
      tenant.Id,
      email: $"seed-{Guid.NewGuid():N}@t.local");
    var user = await testServer.Services.CreateTestUser(
      tenant.Id,
      $"plain-{Guid.NewGuid():N}@t.local");
    using var httpClient = await CreatePatClient(testServer, user.Id);

    var response = await httpClient.GetAsync(
      HttpConstants.Internal.DeploymentOptionsEndpoint,
      TestContext.Current.CancellationToken);

    Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
  }

  private static async Task<HttpClient> CreatePatClient(
    TestWebServer testServer,
    Guid userId)
  {
    var patManager = testServer.Services.GetRequiredService<IPersonalAccessTokenManager>();
    var patResult = await patManager.CreateToken(
      new InternalDtos.CreatePersonalAccessTokenRequestDto("Deployment Options Test PAT"),
      userId);
    Assert.True(patResult.IsSuccess);

    var client = testServer.Factory.CreateClient();
    client.DefaultRequestHeaders.Add(
      PersonalAccessTokenAuthenticationSchemeOptions.DefaultHeaderName,
      patResult.Value.PlainTextToken);
    return client;
  }
}
