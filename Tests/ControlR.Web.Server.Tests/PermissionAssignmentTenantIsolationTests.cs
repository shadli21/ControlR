using System.Net;
using System.Net.Http.Json;
using ControlR.Web.Server.Authn;
using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Data.Entities;
using ControlR.Web.Server.Services;
using ControlR.Web.Server.Tests.Helpers;
using Microsoft.Extensions.DependencyInjection;

namespace ControlR.Web.Server.Tests;

public class PermissionAssignmentTenantIsolationTests(ITestOutputHelper testOutput)
{
  private readonly ITestOutputHelper _testOutput = testOutput;

  [Fact]
  public async Task Create_ServerScopeByTenantAdmin_ReturnsForbidden()
  {
    using var testServer = await TestWebServerBuilder.CreateTestServer(_testOutput);
    var (clientA, _, _, userA) = await CreateTenantAdminEnvironment(testServer, "Tenant A");

    var response = await clientA.PostAsJsonAsync(
      HttpConstants.Internal.PermissionAssignmentsEndpoint,
      new InternalDtos.CreatePermissionAssignmentRequestDto(
        PermissionPrincipalKind.User,
        userA.Id,
        PermissionNames.ServerAdmin,
        PermissionEffect.Allow,
        PermissionScopeKind.Server,
        null,
        null),
      TestContext.Current.CancellationToken);

    Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
  }

  [Fact]
  public async Task Delete_CrossTenantAssignment_ReturnsNotFound()
  {
    using var testServer = await TestWebServerBuilder.CreateTestServer(_testOutput);
    var (clientA, tenantA, _, userA) = await CreateTenantAdminEnvironment(testServer, "Tenant A");
    var (clientB, _, _, _) = await CreateTenantAdminEnvironment(testServer, "Tenant B");

    var assignmentId = await CreateDeviceReadAssignment(clientA, tenantA, userA.Id);

    var response = await clientB.DeleteAsync(
      $"{HttpConstants.Internal.PermissionAssignmentsEndpoint}/{assignmentId}",
      TestContext.Current.CancellationToken);

    Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);

    var remaining = await GetAssignments(clientA, userA.Id);
    Assert.Contains(remaining, a => a.Id == assignmentId);
  }

  [Fact]
  public async Task GetByPrincipal_CrossTenantPrincipal_ReturnsEmpty()
  {
    using var testServer = await TestWebServerBuilder.CreateTestServer(_testOutput);
    var (clientA, tenantA, _, userA) = await CreateTenantAdminEnvironment(testServer, "Tenant A");
    var (clientB, _, _, _) = await CreateTenantAdminEnvironment(testServer, "Tenant B");

    await CreateDeviceReadAssignment(clientA, tenantA, userA.Id);

    var assignments = await GetAssignments(clientB, userA.Id);

    Assert.Empty(assignments);
  }

  private static async Task<Guid> CreateDeviceReadAssignment(HttpClient client, Guid tenantId, Guid principalId)
  {
    var response = await client.PostAsJsonAsync(
      HttpConstants.Internal.PermissionAssignmentsEndpoint,
      new InternalDtos.CreatePermissionAssignmentRequestDto(
        PermissionPrincipalKind.User,
        principalId,
        PermissionNames.DeviceRead,
        PermissionEffect.Allow,
        PermissionScopeKind.Tenant,
        tenantId,
        null),
      TestContext.Current.CancellationToken);
    response.EnsureSuccessStatusCode();

    var created = await response.Content.ReadFromJsonAsync<InternalDtos.PermissionAssignmentDto>(
      TestContext.Current.CancellationToken);
    Assert.NotNull(created);
    return created.Id;
  }

  private static async Task<InternalDtos.PermissionAssignmentDto[]> GetAssignments(HttpClient client, Guid principalId)
  {
    var response = await client.GetAsync(
      $"{HttpConstants.Internal.PermissionAssignmentsEndpoint}?principalKind=User&principalId={principalId}",
      TestContext.Current.CancellationToken);
    response.EnsureSuccessStatusCode();

    var assignments = await response.Content.ReadFromJsonAsync<InternalDtos.PermissionAssignmentDto[]>(
      TestContext.Current.CancellationToken);
    Assert.NotNull(assignments);
    return assignments;
  }

  private async Task<HttpClient> CreatePatClient(TestWebServer testServer, Guid userId)
  {
    var patManager = testServer.Services.GetRequiredService<IPersonalAccessTokenManager>();
    var patResult = await patManager.CreateToken(
      new InternalDtos.CreatePersonalAccessTokenRequestDto("Tenant Isolation Test PAT"), userId);
    Assert.True(patResult.IsSuccess, $"PAT creation failed: {patResult.Reason}");

    var client = testServer.Factory.CreateClient();
    client.DefaultRequestHeaders.Add(
      PersonalAccessTokenAuthenticationSchemeOptions.DefaultHeaderName,
      patResult.Value.PlainTextToken);
    return client;
  }

  private async Task<(HttpClient Client, Guid TenantId, AppUser Admin, AppUser RegularUser)> CreateTenantAdminEnvironment(
    TestWebServer testServer, string tenantName)
  {
    var tenant = await testServer.Services.CreateTestTenant(tenantName);
    await testServer.Services.CreateTestUser(tenant.Id, email: $"seed-{Guid.NewGuid():N}@t.local");
    var admin = await testServer.Services.CreateTestUser(
      tenant.Id, $"admin-{Guid.NewGuid():N}@t.local", PermissionPresets.TenantAdministrator);
    var regularUser = await testServer.Services.CreateTestUser(
      tenant.Id, $"user-{Guid.NewGuid():N}@t.local");

    var client = await CreatePatClient(testServer, admin.Id);
    return (client, tenant.Id, admin, regularUser);
  }
}
