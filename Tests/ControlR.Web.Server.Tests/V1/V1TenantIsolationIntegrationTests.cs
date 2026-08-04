using System.Net;
using System.Net.Http.Json;
using ControlR.Libraries.Api.Contracts.Dtos.ServerApi.V1;
using ControlR.Web.Server.Authn;
using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Data;
using ControlR.Web.Server.Services;
using ControlR.Web.Server.Services.ServiceAccounts;
using ControlR.Web.Server.Tests.Helpers;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace ControlR.Web.Server.Tests.V1;

/// <summary>
/// HTTP-level tenant-isolation tests for the V1 surface. Each test exercises a
/// tenant-scoped principal (user, PAT, logon-token, tenant-SA) attempting to
/// access or mutate resources in *another* tenant. Every code path must return
/// 400 / 403 / 404 without leaking data, and never 200.
/// </summary>
public class V1TenantIsolationIntegrationTests(ITestOutputHelper testOutput)
{
  [Fact]
  public async Task Devices_DeleteDevice_PatInTenantA_DeviceIdInTenantB_ReturnsForbidden()
  {
    using var testServer = await TestWebServerBuilder.CreateTestServer(testOutput);
    using var httpClient = testServer.Factory.CreateClient();

    var tenantA = await testServer.Services.CreateTestTenant("Tenant A");
    var tenantB = await testServer.Services.CreateTestTenant("Tenant B");
    var userA = await testServer.Services.CreateTestUser(
      tenantA.Id,
      "del-tenant-a@t.local",
      PermissionPresets.DeviceSuperUser);
    var deviceB = await testServer.Services.CreateTestDevice(tenantB.Id);

    var patManager = testServer.Services.GetRequiredService<IPersonalAccessTokenManager>();
    var patResult = await patManager.CreateToken(
      new InternalDtos.CreatePersonalAccessTokenRequestDto("Tenant A PAT"),
      userA.Id);
    Assert.True(patResult.IsSuccess);
    httpClient.DefaultRequestHeaders.Add(
      PersonalAccessTokenAuthenticationSchemeOptions.DefaultHeaderName,
      patResult.Value.PlainTextToken);

    var response = await httpClient.DeleteAsync(
      $"{HttpConstants.V1.DevicesEndpoint}/{deviceB.Id}",
      TestContext.Current.CancellationToken);

    Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);

    using var scope = testServer.Services.CreateScope();
    await using var db = scope.ServiceProvider.GetRequiredService<AppDb>();
    var deviceStillExists = await db.Devices
      .IgnoreQueryFilters()
      .AnyAsync(x => x.Id == deviceB.Id, TestContext.Current.CancellationToken);

    Assert.True(deviceStillExists, "The cross-tenant device was deleted despite the Forbidden response.");
  }

  [Fact]
  public async Task Devices_GetSingleDevice_PatInTenantA_AskingForDeviceInTenantB_ReturnsForbidden()
  {
    using var testServer = await TestWebServerBuilder.CreateTestServer(testOutput);
    using var httpClient = testServer.Factory.CreateClient();

    var tenantA = await testServer.Services.CreateTestTenant("Tenant A");
    var tenantB = await testServer.Services.CreateTestTenant("Tenant B");
    var userA = await testServer.Services.CreateTestUser(
      tenantA.Id,
      "dev-tenant-a@t.local",
      PermissionPresets.DeviceSuperUser);
    var deviceB = await testServer.Services.CreateTestDevice(tenantB.Id);

    var patManager = testServer.Services.GetRequiredService<IPersonalAccessTokenManager>();
    var patResult = await patManager.CreateToken(
      new InternalDtos.CreatePersonalAccessTokenRequestDto("Tenant A PAT"),
      userA.Id);
    Assert.True(patResult.IsSuccess);
    httpClient.DefaultRequestHeaders.Add(
      PersonalAccessTokenAuthenticationSchemeOptions.DefaultHeaderName,
      patResult.Value.PlainTextToken);

    var response = await httpClient.GetAsync(
      $"{HttpConstants.V1.DevicesEndpoint}/{deviceB.Id}",
      TestContext.Current.CancellationToken);

    Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);

    var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
    Assert.DoesNotContain(deviceB.Id.ToString(), body);
  }

  [Fact]
  public async Task Devices_Stream_PatInTenantA_DoesNotLeakDevicesFromTenantB()
  {
    using var testServer = await TestWebServerBuilder.CreateTestServer(testOutput);
    using var httpClient = testServer.Factory.CreateClient();

    var tenantA = await testServer.Services.CreateTestTenant("Tenant A");
    var tenantB = await testServer.Services.CreateTestTenant("Tenant B");
    var userA = await testServer.Services.CreateTestUser(
      tenantA.Id,
      "stream-tenant-a@t.local",
      PermissionPresets.DeviceSuperUser);

    var deviceA = await testServer.Services.CreateTestDevice(tenantA.Id);
    var deviceB = await testServer.Services.CreateTestDevice(tenantB.Id);

    var patManager = testServer.Services.GetRequiredService<IPersonalAccessTokenManager>();
    var patResult = await patManager.CreateToken(
      new InternalDtos.CreatePersonalAccessTokenRequestDto("Tenant A PAT"),
      userA.Id);
    Assert.True(patResult.IsSuccess);
    httpClient.DefaultRequestHeaders.Add(
      PersonalAccessTokenAuthenticationSchemeOptions.DefaultHeaderName,
      patResult.Value.PlainTextToken);

    var response = await httpClient.GetAsync(
      HttpConstants.V1.DevicesEndpoint,
      HttpCompletionOption.ResponseHeadersRead,
      TestContext.Current.CancellationToken);

    Assert.Equal(HttpStatusCode.OK, response.StatusCode);

    var stream = response.Content.ReadFromJsonAsAsyncEnumerable<DeviceResponseDto>(
      TestContext.Current.CancellationToken);
    var seenIds = new HashSet<Guid>();
    await foreach (var dto in stream)
    {
      seenIds.Add(dto!.Id);
    }

    Assert.Contains(deviceA.Id, seenIds);
    Assert.DoesNotContain(deviceB.Id, seenIds);
  }

  [Fact]
  public async Task Devices_Stream_ViaServerServiceAccount_SeesBothTenants()
  {
    using var testServer = await TestWebServerBuilder.CreateTestServer(testOutput);
    using var httpClient = testServer.Factory.CreateClient();

    var saManager = testServer.Services.GetRequiredService<IServiceAccountManager>();
    var saResult = await saManager.CreateForServer(
      "V1 SA - Stream Both",
      null,
      TestContext.Current.CancellationToken);
    Assert.True(saResult.IsSuccess);
    httpClient.DefaultRequestHeaders.Add(
      ServiceAccountCredentialAuthenticationSchemeOptions.DefaultHeaderName,
      saResult.Value.PlainTextSecretKey);

    var tenantA = await testServer.Services.CreateTestTenant("Tenant A");
    var tenantB = await testServer.Services.CreateTestTenant("Tenant B");
    var deviceA = await testServer.Services.CreateTestDevice(tenantA.Id);
    var deviceB = await testServer.Services.CreateTestDevice(tenantB.Id);

    var response = await httpClient.GetAsync(
      HttpConstants.V1.DevicesEndpoint,
      HttpCompletionOption.ResponseHeadersRead,
      TestContext.Current.CancellationToken);
    Assert.Equal(HttpStatusCode.OK, response.StatusCode);

    var stream = response.Content.ReadFromJsonAsAsyncEnumerable<DeviceResponseDto>(
      TestContext.Current.CancellationToken);
    var seenIds = new HashSet<Guid>();
    await foreach (var dto in stream)
    {
      seenIds.Add(dto!.Id);
    }

    Assert.Contains(deviceA.Id, seenIds);
    Assert.Contains(deviceB.Id, seenIds);
  }

  [Fact]
  public async Task InstallerKey_Create_ViaServerServiceAccount_PostingAnyTenant_ReturnsOk()
  {
    using var testServer = await TestWebServerBuilder.CreateTestServer(testOutput);
    using var httpClient = testServer.Factory.CreateClient();

    var saManager = testServer.Services.GetRequiredService<IServiceAccountManager>();
    var saResult = await saManager.CreateForServer(
      "V1 Tenant Isolation - SA",
      null,
      TestContext.Current.CancellationToken);
    Assert.True(saResult.IsSuccess);
    httpClient.DefaultRequestHeaders.Add(
      ServiceAccountCredentialAuthenticationSchemeOptions.DefaultHeaderName,
      saResult.Value.PlainTextSecretKey);

    var tenantOther = await testServer.Services.CreateTestTenant("Any Tenant");

    var response = await httpClient.PostAsJsonAsync(
      HttpConstants.V1.InstallerKeysEndpoint,
      new CreateInstallerKeyRequestDto(
        TenantId: tenantOther.Id,
        KeyType: InstallerKeyType.Persistent),
      TestContext.Current.CancellationToken);

    Assert.Equal(HttpStatusCode.OK, response.StatusCode);
  }

  [Fact]
  public async Task InstallerKey_Create_ViaUserPatInTenantA_PostingTenantA_ReturnsOk()
  {
    using var testServer = await TestWebServerBuilder.CreateTestServer(testOutput);
    using var httpClient = testServer.Factory.CreateClient();

    var tenantA = await testServer.Services.CreateTestTenant("Tenant A");
    var userA = await testServer.Services.CreateTestUser(
      tenantA.Id,
      "ik-tenant-a-ok@t.local",
      PermissionPresets.InstallerKeyManager);

    var patManager = testServer.Services.GetRequiredService<IPersonalAccessTokenManager>();
    var patResult = await patManager.CreateToken(
      new InternalDtos.CreatePersonalAccessTokenRequestDto("Tenant A PAT"),
      userA.Id);
    Assert.True(patResult.IsSuccess);
    httpClient.DefaultRequestHeaders.Add(
      PersonalAccessTokenAuthenticationSchemeOptions.DefaultHeaderName,
      patResult.Value.PlainTextToken);

    var response = await httpClient.PostAsJsonAsync(
      HttpConstants.V1.InstallerKeysEndpoint,
      new CreateInstallerKeyRequestDto(
        TenantId: tenantA.Id,
        KeyType: InstallerKeyType.Persistent),
      TestContext.Current.CancellationToken);

    Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    var created = await response.Content.ReadFromJsonAsync<CreateInstallerKeyResponseDto>(
      TestContext.Current.CancellationToken);
    Assert.NotNull(created);
    Assert.Equal(userA.Id, created.CreatorId);
  }

  [Fact]
  public async Task InstallerKey_Create_ViaUserPatInTenantA_PostingTenantB_ReturnsForbidden()
  {
    using var testServer = await TestWebServerBuilder.CreateTestServer(testOutput);
    using var httpClient = testServer.Factory.CreateClient();

    var tenantA = await testServer.Services.CreateTestTenant("Tenant A");
    var tenantB = await testServer.Services.CreateTestTenant("Tenant B");
    var userA = await testServer.Services.CreateTestUser(
      tenantA.Id,
      "ik-tenant-a@t.local",
      PermissionPresets.InstallerKeyManager);

    var patManager = testServer.Services.GetRequiredService<IPersonalAccessTokenManager>();
    var patResult = await patManager.CreateToken(
      new InternalDtos.CreatePersonalAccessTokenRequestDto("Tenant A PAT"),
      userA.Id);
    Assert.True(patResult.IsSuccess);
    httpClient.DefaultRequestHeaders.Add(
      PersonalAccessTokenAuthenticationSchemeOptions.DefaultHeaderName,
      patResult.Value.PlainTextToken);

    var response = await httpClient.PostAsJsonAsync(
      HttpConstants.V1.InstallerKeysEndpoint,
      new CreateInstallerKeyRequestDto(
        TenantId: tenantB.Id,
        KeyType: InstallerKeyType.Persistent),
      TestContext.Current.CancellationToken);

    Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
  }

  [Fact]
  public async Task LogonToken_CreateForUser_PatInTenantA_DeviceInTenantA_ReturnsOk()
  {
    using var testServer = await TestWebServerBuilder.CreateTestServer(testOutput);
    using var httpClient = testServer.Factory.CreateClient();

    var tenantA = await testServer.Services.CreateTestTenant("Tenant A");
    var userA = await testServer.Services.CreateTestUser(
      tenantA.Id,
      "lt-tenant-a-ok@t.local",
      PermissionPresets.DeviceSuperUser);
    var deviceA = await testServer.Services.CreateTestDevice(tenantA.Id);

    var patManager = testServer.Services.GetRequiredService<IPersonalAccessTokenManager>();
    var patResult = await patManager.CreateToken(
      new InternalDtos.CreatePersonalAccessTokenRequestDto("Tenant A PAT"),
      userA.Id);
    Assert.True(patResult.IsSuccess);
    httpClient.DefaultRequestHeaders.Add(
      PersonalAccessTokenAuthenticationSchemeOptions.DefaultHeaderName,
      patResult.Value.PlainTextToken);

    var response = await httpClient.PostAsJsonAsync(
      $"{HttpConstants.V1.LogonTokensEndpoint}/user",
      new CreateLogonTokenForUserRequestDto(
        DeviceId: deviceA.Id,
        TenantId: tenantA.Id,
        UserId: userA.Id,
        ExpirationMinutes: 15),
      TestContext.Current.CancellationToken);

    Assert.Equal(HttpStatusCode.OK, response.StatusCode);
  }

  [Fact]
  public async Task LogonToken_CreateForUser_PatInTenantA_DeviceInTenantB_ReturnsBadRequest()
  {
    using var testServer = await TestWebServerBuilder.CreateTestServer(testOutput);
    using var httpClient = testServer.Factory.CreateClient();

    var tenantA = await testServer.Services.CreateTestTenant("Tenant A");
    var tenantB = await testServer.Services.CreateTestTenant("Tenant B");
    var userA = await testServer.Services.CreateTestUser(
      tenantA.Id,
      "lt-tenant-a@t.local",
      PermissionPresets.DeviceSuperUser);
    var deviceB = await testServer.Services.CreateTestDevice(tenantB.Id);

    var patManager = testServer.Services.GetRequiredService<IPersonalAccessTokenManager>();
    var patResult = await patManager.CreateToken(
      new InternalDtos.CreatePersonalAccessTokenRequestDto("Tenant A PAT"),
      userA.Id);
    Assert.True(patResult.IsSuccess);
    httpClient.DefaultRequestHeaders.Add(
      PersonalAccessTokenAuthenticationSchemeOptions.DefaultHeaderName,
      patResult.Value.PlainTextToken);

    var response = await httpClient.PostAsJsonAsync(
      $"{HttpConstants.V1.LogonTokensEndpoint}/user",
      new CreateLogonTokenForUserRequestDto(
        DeviceId: deviceB.Id,
        TenantId: tenantB.Id,
        UserId: userA.Id,
        ExpirationMinutes: 15),
      TestContext.Current.CancellationToken);

    Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
  }
}
