using System.Net;
using System.Net.Http.Json;
using ControlR.Web.Server.Authn;
using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Data;
using ControlR.Web.Server.Data.Entities;
using ControlR.Web.Server.Services;
using ControlR.Web.Server.Tests.Helpers;
using Microsoft.Extensions.DependencyInjection;

namespace ControlR.Web.Server.Tests;

public class LogonTokenScopeDenyOverrideTests(ITestOutputHelper testOutput)
{
  private readonly ITestOutputHelper _testOutput = testOutput;

  [Fact]
  public async Task CreateLogonToken_NonDeviceScope_ReturnsBadRequest()
  {
    using var testServer = await TestWebServerBuilder.CreateTestServer(_testOutput);
    using var httpClient = testServer.Factory.CreateClient();

    var tenant = await testServer.Services.CreateTestTenant();
    await testServer.Services.CreateTestUser(tenant.Id, email: $"seed-{Guid.NewGuid():N}@t.local");
    var user = await testServer.Services.CreateTestUser(
      tenant.Id, $"nondevice-{Guid.NewGuid():N}@t.local", PermissionPresets.DeviceSuperUser);
    var device = await testServer.Services.CreateTestDevice(tenant.Id);

    var patManager = testServer.Services.GetRequiredService<IPersonalAccessTokenManager>();
    var patResult = await patManager.CreateToken(
      new InternalDtos.CreatePersonalAccessTokenRequestDto("Non-Device Scope Test PAT"), user.Id);
    Assert.True(patResult.IsSuccess, $"PAT creation failed: {patResult.Reason}");

    httpClient.DefaultRequestHeaders.Add(
      PersonalAccessTokenAuthenticationSchemeOptions.DefaultHeaderName,
      patResult.Value.PlainTextToken);

    var request = new InternalDtos.LogonTokenRequestDto(
      device.Id,
      ExpirationMinutes: 15,
      Scopes: [new InternalDtos.CredentialScopeDto(PermissionNames.DeviceRead, PermissionScopeKind.Tenant, tenant.Id)]);

    var response = await httpClient.PostAsJsonAsync(
      HttpConstants.Internal.LogonTokensEndpoint, request, TestContext.Current.CancellationToken);

    Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
  }

  [Fact]
  public async Task CreateLogonToken_ScopeGrantingDeniedPermission_ReturnsBadRequest()
  {
    using var testServer = await TestWebServerBuilder.CreateTestServer(_testOutput);
    using var httpClient = testServer.Factory.CreateClient();

    var tenant = await testServer.Services.CreateTestTenant();
    await testServer.Services.CreateTestUser(tenant.Id, email: $"seed-{Guid.NewGuid():N}@t.local");
    var user = await testServer.Services.CreateTestUser(
      tenant.Id, $"denied-{Guid.NewGuid():N}@t.local", PermissionPresets.DeviceSuperUser);
    var device = await testServer.Services.CreateTestDevice(tenant.Id);

    using (var scope = testServer.Services.CreateScope())
    {
      await using var db = scope.ServiceProvider.GetRequiredService<AppDb>();
      db.PermissionAssignments.Add(new PermissionAssignment
      {
        PrincipalKind = PermissionPrincipalKind.User,
        PrincipalId = user.Id,
        PermissionName = PermissionNames.DeviceRead,
        Effect = PermissionEffect.Deny,
        ScopeKind = PermissionScopeKind.Tenant,
        ScopeId = tenant.Id,
        IsEnabled = true,
        OwningTenantId = tenant.Id,
        CreatedByPrincipalType = "user",
        CreatedByPrincipalId = user.Id.ToString()
      });
      await db.SaveChangesAsync(TestContext.Current.CancellationToken);
    }

    var patManager = testServer.Services.GetRequiredService<IPersonalAccessTokenManager>();
    var patResult = await patManager.CreateToken(
      new InternalDtos.CreatePersonalAccessTokenRequestDto("Deny Override Test PAT"), user.Id);
    Assert.True(patResult.IsSuccess, $"PAT creation failed: {patResult.Reason}");

    httpClient.DefaultRequestHeaders.Add(
      PersonalAccessTokenAuthenticationSchemeOptions.DefaultHeaderName,
      patResult.Value.PlainTextToken);

    var request = new InternalDtos.LogonTokenRequestDto(
      device.Id,
      ExpirationMinutes: 15,
      Scopes: [new InternalDtos.CredentialScopeDto(PermissionNames.DeviceRead, PermissionScopeKind.Device, device.Id)]);

    var response = await httpClient.PostAsJsonAsync(
      HttpConstants.Internal.LogonTokensEndpoint, request, TestContext.Current.CancellationToken);

    Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
  }

  [Fact]
  public async Task CreateLogonToken_ScopeOnDeviceInsideCreatorGroup_ReturnsOk()
  {
    using var testServer = await TestWebServerBuilder.CreateTestServer(_testOutput);
    using var httpClient = testServer.Factory.CreateClient();

    var tenant = await testServer.Services.CreateTestTenant();
    await testServer.Services.CreateTestUser(tenant.Id, email: $"seed-{Guid.NewGuid():N}@t.local");
    var user = await testServer.Services.CreateTestUser(tenant.Id, $"scoped-ok-{Guid.NewGuid():N}@t.local");
    var deviceInGroup = await testServer.Services.CreateTestDevice(tenant.Id);
    var groupId = Guid.NewGuid();

    using (var scope = testServer.Services.CreateScope())
    {
      await using var db = scope.ServiceProvider.GetRequiredService<AppDb>();
      db.DeviceGroups.Add(new DeviceGroup { Id = groupId, Name = $"group-{groupId:N}", TenantId = tenant.Id });
      db.DeviceGroupMembers.Add(new DeviceGroupMember { DeviceId = deviceInGroup.Id, DeviceGroupId = groupId });
      await db.SaveChangesAsync(TestContext.Current.CancellationToken);
    }

    await SeedAssignment(testServer, new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.User,
      PrincipalId = user.Id,
      PermissionName = PermissionNames.DeviceLogonTokenCreate,
      Effect = PermissionEffect.Allow,
      ScopeKind = PermissionScopeKind.Tenant,
      ScopeId = tenant.Id,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });

    await SeedAssignment(testServer, new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.User,
      PrincipalId = user.Id,
      PermissionName = PermissionNames.DeviceRead,
      Effect = PermissionEffect.Allow,
      ScopeKind = PermissionScopeKind.DeviceGroup,
      ScopeId = groupId,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });

    var patManager = testServer.Services.GetRequiredService<IPersonalAccessTokenManager>();
    var patResult = await patManager.CreateToken(
      new InternalDtos.CreatePersonalAccessTokenRequestDto("Scope Coverage Test PAT"), user.Id);
    Assert.True(patResult.IsSuccess, $"PAT creation failed: {patResult.Reason}");

    httpClient.DefaultRequestHeaders.Add(
      PersonalAccessTokenAuthenticationSchemeOptions.DefaultHeaderName,
      patResult.Value.PlainTextToken);

    var request = new InternalDtos.LogonTokenRequestDto(
      deviceInGroup.Id,
      ExpirationMinutes: 15,
      Scopes: [new InternalDtos.CredentialScopeDto(PermissionNames.DeviceRead, PermissionScopeKind.Device, deviceInGroup.Id)]);

    var response = await httpClient.PostAsJsonAsync(
      HttpConstants.Internal.LogonTokensEndpoint, request, TestContext.Current.CancellationToken);

    Assert.Equal(HttpStatusCode.OK, response.StatusCode);
  }

  [Fact]
  public async Task CreateLogonToken_ScopeOnDeviceOutsideCreatorGroup_ReturnsBadRequest()
  {
    using var testServer = await TestWebServerBuilder.CreateTestServer(_testOutput);
    using var httpClient = testServer.Factory.CreateClient();

    var tenant = await testServer.Services.CreateTestTenant();
    await testServer.Services.CreateTestUser(tenant.Id, email: $"seed-{Guid.NewGuid():N}@t.local");
    var user = await testServer.Services.CreateTestUser(tenant.Id, $"scoped-{Guid.NewGuid():N}@t.local");
    var deviceInGroup = await testServer.Services.CreateTestDevice(tenant.Id);
    var deviceOutsideGroup = await testServer.Services.CreateTestDevice(tenant.Id);
    var groupId = Guid.NewGuid();

    using (var scope = testServer.Services.CreateScope())
    {
      await using var db = scope.ServiceProvider.GetRequiredService<AppDb>();
      db.DeviceGroups.Add(new DeviceGroup { Id = groupId, Name = $"group-{groupId:N}", TenantId = tenant.Id });
      db.DeviceGroupMembers.Add(new DeviceGroupMember { DeviceId = deviceInGroup.Id, DeviceGroupId = groupId });
      await db.SaveChangesAsync(TestContext.Current.CancellationToken);
    }

    await SeedAssignment(testServer, new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.User,
      PrincipalId = user.Id,
      PermissionName = PermissionNames.DeviceLogonTokenCreate,
      Effect = PermissionEffect.Allow,
      ScopeKind = PermissionScopeKind.Tenant,
      ScopeId = tenant.Id,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });

    await SeedAssignment(testServer, new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.User,
      PrincipalId = user.Id,
      PermissionName = PermissionNames.DeviceRead,
      Effect = PermissionEffect.Allow,
      ScopeKind = PermissionScopeKind.DeviceGroup,
      ScopeId = groupId,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });

    var patManager = testServer.Services.GetRequiredService<IPersonalAccessTokenManager>();
    var patResult = await patManager.CreateToken(
      new InternalDtos.CreatePersonalAccessTokenRequestDto("Scope Coverage Test PAT"), user.Id);
    Assert.True(patResult.IsSuccess, $"PAT creation failed: {patResult.Reason}");

    httpClient.DefaultRequestHeaders.Add(
      PersonalAccessTokenAuthenticationSchemeOptions.DefaultHeaderName,
      patResult.Value.PlainTextToken);

    var request = new InternalDtos.LogonTokenRequestDto(
      deviceInGroup.Id,
      ExpirationMinutes: 15,
      Scopes: [new InternalDtos.CredentialScopeDto(PermissionNames.DeviceRead, PermissionScopeKind.Device, deviceOutsideGroup.Id)]);

    var response = await httpClient.PostAsJsonAsync(
      HttpConstants.Internal.LogonTokensEndpoint, request, TestContext.Current.CancellationToken);

    Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
  }

  private static async Task SeedAssignment(TestWebServer testServer, PermissionAssignment assignment)
  {
    using var scope = testServer.Services.CreateScope();
    await using var db = scope.ServiceProvider.GetRequiredService<AppDb>();
    db.PermissionAssignments.Add(assignment);
    await db.SaveChangesAsync(TestContext.Current.CancellationToken);
  }
}
