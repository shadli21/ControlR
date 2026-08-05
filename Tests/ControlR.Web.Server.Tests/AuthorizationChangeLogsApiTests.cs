using System.Net;
using System.Net.Http.Json;
using ControlR.Web.Server.Authn;
using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Data.Entities;
using ControlR.Web.Server.Services;
using ControlR.Web.Server.Services.PermissionAssignments;
using ControlR.Web.Server.Tests.Helpers;
using Microsoft.Extensions.DependencyInjection;

namespace ControlR.Web.Server.Tests;

/// <summary>
/// Authorization change log endpoint audience scoping: server administrators see all
/// tenants, tenant readers see only their own tenant, and other principals are forbidden.
/// </summary>
public class AuthorizationChangeLogsApiTests(ITestOutputHelper testOutput)
{
  private readonly ITestOutputHelper _testOutput = testOutput;

  [Fact]
  public async Task Get_AsServerAdmin_ReturnsEntriesFromAllTenants()
  {
    using var testServer = await TestWebServerBuilder.CreateTestServer(_testOutput);
    var (tenantA, tenantB, serverAdmin, _) = await SetupTenantsWithEntries(testServer);

    using var httpClient = await CreatePatClient(testServer, serverAdmin.Id);

    var response = await httpClient.GetAsync(
      HttpConstants.Internal.AuthorizationChangeLogsEndpoint, TestContext.Current.CancellationToken);
    Assert.Equal(HttpStatusCode.OK, response.StatusCode);

    var result = await response.Content.ReadFromJsonAsync<InternalDtos.AuthorizationChangeLogSearchResponseDto>(
      TestContext.Current.CancellationToken);
    Assert.NotNull(result);
    Assert.Contains(result.Items, x => x.OwningTenantId == tenantA.Id);
    Assert.Contains(result.Items, x => x.OwningTenantId == tenantB.Id);
  }

  [Fact]
  public async Task Get_AsTenantReader_ReturnsOnlyOwnTenantEntries()
  {
    using var testServer = await TestWebServerBuilder.CreateTestServer(_testOutput);
    var (tenantA, tenantB, _, tenantAdminA) = await SetupTenantsWithEntries(testServer);

    using var httpClient = await CreatePatClient(testServer, tenantAdminA.Id);

    var response = await httpClient.GetAsync(
      HttpConstants.Internal.AuthorizationChangeLogsEndpoint, TestContext.Current.CancellationToken);
    Assert.Equal(HttpStatusCode.OK, response.StatusCode);

    var result = await response.Content.ReadFromJsonAsync<InternalDtos.AuthorizationChangeLogSearchResponseDto>(
      TestContext.Current.CancellationToken);
    Assert.NotNull(result);
    Assert.NotEmpty(result.Items);
    Assert.All(result.Items, x => Assert.Equal(tenantA.Id, x.OwningTenantId));

    var crossTenantResponse = await httpClient.GetAsync(
      $"{HttpConstants.Internal.AuthorizationChangeLogsEndpoint}?tenantId={tenantB.Id}",
      TestContext.Current.CancellationToken);
    Assert.Equal(HttpStatusCode.Forbidden, crossTenantResponse.StatusCode);
  }

  [Fact]
  public async Task Get_AsUnauthorizedUser_ReturnsForbidden()
  {
    using var testServer = await TestWebServerBuilder.CreateTestServer(_testOutput);
    var tenant = await testServer.Services.CreateTestTenant();
    await testServer.Services.CreateTestUser(tenant.Id, email: $"seed-{Guid.NewGuid():N}@t.local");
    var plainUser = await testServer.Services.CreateTestUser(tenant.Id, $"plain-{Guid.NewGuid():N}@t.local");

    using var httpClient = await CreatePatClient(testServer, plainUser.Id);

    var response = await httpClient.GetAsync(
      HttpConstants.Internal.AuthorizationChangeLogsEndpoint, TestContext.Current.CancellationToken);
    Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
  }

  private async Task<HttpClient> CreatePatClient(TestWebServer testServer, Guid userId)
  {
    var patManager = testServer.Services.GetRequiredService<IPersonalAccessTokenManager>();
    var patResult = await patManager.CreateToken(
      new InternalDtos.CreatePersonalAccessTokenRequestDto("Audit Log Test PAT"), userId);
    Assert.True(patResult.IsSuccess);

    var client = testServer.Factory.CreateClient();
    client.DefaultRequestHeaders.Add(
      PersonalAccessTokenAuthenticationSchemeOptions.DefaultHeaderName,
      patResult.Value.PlainTextToken);
    return client;
  }

  private async Task<(Tenant TenantA, Tenant TenantB, AppUser ServerAdmin, AppUser TenantAdminA)> SetupTenantsWithEntries(
    TestWebServer testServer)
  {
    var tenantA = await testServer.Services.CreateTestTenant("Tenant A");
    var tenantB = await testServer.Services.CreateTestTenant("Tenant B");
    await testServer.Services.CreateTestUser(tenantA.Id, email: $"seed-{Guid.NewGuid():N}@t.local");

    var serverAdmin = await testServer.Services.CreateTestUser(tenantA.Id, $"server-admin-{Guid.NewGuid():N}@t.local");
    var tenantAdminA = await testServer.Services.CreateTestUser(
      tenantA.Id, $"tenant-admin-{Guid.NewGuid():N}@t.local", PermissionPresets.TenantAdministrator);
    var targetA = await testServer.Services.CreateTestUser(tenantA.Id, $"target-a-{Guid.NewGuid():N}@t.local");
    var targetB = await testServer.Services.CreateTestUser(tenantB.Id, $"target-b-{Guid.NewGuid():N}@t.local");

    using (var scope = testServer.Services.CreateScope())
    {
      await using var db = scope.ServiceProvider.GetRequiredService<ControlR.Web.Server.Data.AppDb>();
      db.PermissionAssignments.Add(PermissionAssignment.CreateGrant(
        PermissionPrincipalKind.User,
        serverAdmin.Id,
        PermissionNames.ServerAdmin,
        PermissionScopeKind.Server,
        null,
        tenantA.Id,
        "test",
        serverAdmin.Id.ToString()));
      await db.SaveChangesAsync(TestContext.Current.CancellationToken);
    }

    using (var scope = testServer.Services.CreateScope())
    {
      var manager = scope.ServiceProvider.GetRequiredService<IPermissionAssignmentManager>();

      var createA = await manager.Create(
        new InternalDtos.CreatePermissionAssignmentRequestDto(
          PermissionPrincipalKind.User, targetA.Id, PermissionNames.DeviceRead,
          PermissionEffect.Allow, PermissionScopeKind.Tenant, tenantA.Id, null),
        tenantA.Id, tenantAdminA.Id, TestContext.Current.CancellationToken);
      Assert.True(createA.IsSuccess, $"Tenant A assignment failed: {createA.Reason}");

      var createB = await manager.Create(
        new InternalDtos.CreatePermissionAssignmentRequestDto(
          PermissionPrincipalKind.User, targetB.Id, PermissionNames.DeviceRead,
          PermissionEffect.Allow, PermissionScopeKind.Tenant, tenantB.Id, null),
        tenantB.Id, serverAdmin.Id, TestContext.Current.CancellationToken);
      Assert.True(createB.IsSuccess, $"Tenant B assignment failed: {createB.Reason}");
    }

    return (tenantA, tenantB, serverAdmin, tenantAdminA);
  }
}
