using System.Net;
using System.Net.Http.Json;
using ControlR.Libraries.Api.Contracts.Enums;
using ControlR.Web.Client.Authz;
using ControlR.Web.Server.Authn;
using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Data;
using ControlR.Web.Server.Services;
using ControlR.Web.Server.Services.Tenants;
using ControlR.Web.Server.Tests.Helpers;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;


namespace ControlR.Web.Server.Tests;

public class PermissionManagementIntegrationTests(ITestOutputHelper testOutput)
{
  [Fact]
  public async Task DeviceGroup_AddAndRemoveMembers_UpdatesMembership()
  {
    var (testServer, client, tenantId, _) = await CreateAuthenticatedServer();
    using var _ = testServer;

    var device1 = await testServer.Services.CreateTestDevice(tenantId);
    var device2 = await testServer.Services.CreateTestDevice(tenantId);

    var createResponse = await client.PostAsJsonAsync(
      HttpConstants.Internal.DeviceGroupsEndpoint,
      new InternalDtos.CreateDeviceGroupRequestDto("Member Test Group", null),
      TestContext.Current.CancellationToken);
    var group = await createResponse.Content.ReadFromJsonAsync<InternalDtos.DeviceGroupDetailDto>(
      TestContext.Current.CancellationToken);
    Assert.NotNull(group);

    var addResponse = await client.PostAsJsonAsync(
      $"{HttpConstants.Internal.DeviceGroupsEndpoint}/{group.Id}/members",
      new InternalDtos.AddDeviceGroupMembersRequestDto([device1.Id, device2.Id]),
      TestContext.Current.CancellationToken);
    Assert.Equal(HttpStatusCode.NoContent, addResponse.StatusCode);

    var getResponse = await client.GetAsync(
      $"{HttpConstants.Internal.DeviceGroupsEndpoint}/{group.Id}",
      TestContext.Current.CancellationToken);
    var withMembers = await getResponse.Content.ReadFromJsonAsync<InternalDtos.DeviceGroupDetailDto>(
      TestContext.Current.CancellationToken);
    Assert.NotNull(withMembers);
    Assert.Equal(2, withMembers.Members.Count);

    var removeResponse = await client.SendAsync(new HttpRequestMessage(HttpMethod.Delete,
      $"{HttpConstants.Internal.DeviceGroupsEndpoint}/{group.Id}/members")
    {
      Content = JsonContent.Create(new InternalDtos.RemoveDeviceGroupMembersRequestDto([device1.Id]))
    }, TestContext.Current.CancellationToken);
    Assert.Equal(HttpStatusCode.NoContent, removeResponse.StatusCode);

    var afterRemove = await client.GetAsync(
      $"{HttpConstants.Internal.DeviceGroupsEndpoint}/{group.Id}",
      TestContext.Current.CancellationToken);
    var afterRemoveDto = await afterRemove.Content.ReadFromJsonAsync<InternalDtos.DeviceGroupDetailDto>(
      TestContext.Current.CancellationToken);
    Assert.NotNull(afterRemoveDto);
    Assert.Single(afterRemoveDto.Members);
    Assert.Equal(device2.Id, afterRemoveDto.Members[0].DeviceId);
  }

  [Fact]
  public async Task DeviceGroup_CreateGetUpdateDelete_CompletesFullCycle()
  {
    var (testServer, client, _, _) = await CreateAuthenticatedServer();
    using var _ = testServer;

    var createResponse = await client.PostAsJsonAsync(
      HttpConstants.Internal.DeviceGroupsEndpoint,
      new InternalDtos.CreateDeviceGroupRequestDto("Production Servers", "Main production fleet"),
      TestContext.Current.CancellationToken);

    Assert.Equal(HttpStatusCode.OK, createResponse.StatusCode);
    var created = await createResponse.Content.ReadFromJsonAsync<InternalDtos.DeviceGroupDetailDto>(
      TestContext.Current.CancellationToken);
    Assert.NotNull(created);
    Assert.Equal("Production Servers", created.Name);
    Assert.Equal("Main production fleet", created.Description);
    Assert.NotEqual(Guid.Empty, created.Id);
    Assert.Empty(created.Members);

    var getResponse = await client.GetAsync(
      $"{HttpConstants.Internal.DeviceGroupsEndpoint}/{created.Id}",
      TestContext.Current.CancellationToken);
    Assert.Equal(HttpStatusCode.OK, getResponse.StatusCode);
    var fetched = await getResponse.Content.ReadFromJsonAsync<InternalDtos.DeviceGroupDetailDto>(
      TestContext.Current.CancellationToken);
    Assert.NotNull(fetched);
    Assert.Equal(created.Id, fetched.Id);

    var updateResponse = await client.PutAsJsonAsync(
      $"{HttpConstants.Internal.DeviceGroupsEndpoint}/{created.Id}",
      new InternalDtos.UpdateDeviceGroupRequestDto("Staging Servers", "Staging fleet"),
      TestContext.Current.CancellationToken);
    Assert.Equal(HttpStatusCode.OK, updateResponse.StatusCode);
    var updated = await updateResponse.Content.ReadFromJsonAsync<InternalDtos.DeviceGroupDetailDto>(
      TestContext.Current.CancellationToken);
    Assert.NotNull(updated);
    Assert.Equal("Staging Servers", updated.Name);
    Assert.Equal("Staging fleet", updated.Description);

    var deleteResponse = await client.DeleteAsync(
      $"{HttpConstants.Internal.DeviceGroupsEndpoint}/{created.Id}",
      TestContext.Current.CancellationToken);
    Assert.Equal(HttpStatusCode.NoContent, deleteResponse.StatusCode);

    var getAfterDelete = await client.GetAsync(
      $"{HttpConstants.Internal.DeviceGroupsEndpoint}/{created.Id}",
      TestContext.Current.CancellationToken);
    Assert.Equal(HttpStatusCode.NotFound, getAfterDelete.StatusCode);
  }

  [Fact]
  public async Task DeviceGroup_Delete_CascadesPermissionAssignments()
  {
    var (testServer, client, tenantId, userId) = await CreateAuthenticatedServer();
    using var _ = testServer;

    var createGroupResponse = await client.PostAsJsonAsync(
      HttpConstants.Internal.DeviceGroupsEndpoint,
      new InternalDtos.CreateDeviceGroupRequestDto("Cascade Test Group", null),
      TestContext.Current.CancellationToken);
    var group = await createGroupResponse.Content.ReadFromJsonAsync<InternalDtos.DeviceGroupDetailDto>(
      TestContext.Current.CancellationToken);
    Assert.NotNull(group);

    var createAssignmentResponse = await client.PostAsJsonAsync(
      HttpConstants.Internal.PermissionAssignmentsEndpoint,
      new InternalDtos.CreatePermissionAssignmentRequestDto(
        PermissionPrincipalKind.User,
        userId,
        "device.read",
        PermissionEffect.Allow,
        PermissionScopeKind.DeviceGroup,
        group.Id,
        null),
      TestContext.Current.CancellationToken);
    Assert.Equal(HttpStatusCode.OK, createAssignmentResponse.StatusCode);

    var deleteResponse = await client.DeleteAsync(
      $"{HttpConstants.Internal.DeviceGroupsEndpoint}/{group.Id}",
      TestContext.Current.CancellationToken);
    Assert.Equal(HttpStatusCode.NoContent, deleteResponse.StatusCode);

    using var scope = testServer.Services.CreateScope();
    await using var db = scope.ServiceProvider.GetRequiredService<AppDb>();
    var remaining = await db.PermissionAssignments
      .CountAsync(x => x.ScopeKind == PermissionScopeKind.DeviceGroup && x.ScopeId == group.Id,
        TestContext.Current.CancellationToken);
    Assert.Equal(0, remaining);
  }

  [Fact]
  public async Task DeviceGroup_GetAll_ReturnsCreatedGroups()
  {
    var (testServer, client, _, _) = await CreateAuthenticatedServer();
    using var _ = testServer;

    await client.PostAsJsonAsync(
      HttpConstants.Internal.DeviceGroupsEndpoint,
      new InternalDtos.CreateDeviceGroupRequestDto("Group A", null),
      TestContext.Current.CancellationToken);
    await client.PostAsJsonAsync(
      HttpConstants.Internal.DeviceGroupsEndpoint,
      new InternalDtos.CreateDeviceGroupRequestDto("Group B", null),
      TestContext.Current.CancellationToken);

    var response = await client.GetAsync(
      HttpConstants.Internal.DeviceGroupsEndpoint,
      TestContext.Current.CancellationToken);
    Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    var groups = await response.Content.ReadFromJsonAsync<InternalDtos.DeviceGroupDto[]>(
      TestContext.Current.CancellationToken);
    Assert.NotNull(groups);
    Assert.Equal(2, groups.Length);
  }

  [Fact]
  public async Task DeviceGroup_Unauthenticated_Returns401()
  {
    using var testServer = await TestWebServerBuilder.CreateTestServer(testOutput);
    using var client = testServer.Factory.CreateClient();

    var response = await client.GetAsync(
      HttpConstants.Internal.DeviceGroupsEndpoint,
      TestContext.Current.CancellationToken);
    Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
  }

  [Fact]
  public async Task EffectivePermission_Query_ReturnsAllowedForTenantAdmin()
  {
    var (testServer, client, tenantId, userId) = await CreateAuthenticatedServer();
    using var _ = testServer;

    var queryResponse = await client.PostAsJsonAsync(
      $"{HttpConstants.Internal.EffectivePermissionsEndpoint}/query",
      new InternalDtos.EffectivePermissionQueryRequestDto(
        PermissionPrincipalKind.User,
        userId,
        "tenant.permissions.read",
        PermissionScopeKind.Tenant,
        tenantId),
      TestContext.Current.CancellationToken);

    Assert.Equal(HttpStatusCode.OK, queryResponse.StatusCode);
    var result = await queryResponse.Content.ReadFromJsonAsync<InternalDtos.EffectivePermissionQueryResponseDto>(
      TestContext.Current.CancellationToken);
    Assert.NotNull(result);
    Assert.True(result.IsAllowed);
  }

  [Fact]
  public async Task EffectivePermission_Query_ReturnsDeniedForNonAdmin()
  {
    var (testServer, client, tenantId, _) = await CreateAuthenticatedServer();
    using var _ = testServer;

    var normalUser = await testServer.Services.CreateTestUser(
      tenantId, $"normal-{Guid.NewGuid():N}@t.local");

    var queryResponse = await client.PostAsJsonAsync(
      $"{HttpConstants.Internal.EffectivePermissionsEndpoint}/query",
      new InternalDtos.EffectivePermissionQueryRequestDto(
        PermissionPrincipalKind.User,
        normalUser.Id,
        "tenant.permissions.write",
        PermissionScopeKind.Tenant,
        tenantId),
      TestContext.Current.CancellationToken);

    Assert.Equal(HttpStatusCode.OK, queryResponse.StatusCode);
    var result = await queryResponse.Content.ReadFromJsonAsync<InternalDtos.EffectivePermissionQueryResponseDto>(
      TestContext.Current.CancellationToken);
    Assert.NotNull(result);
    Assert.False(result.IsAllowed);
  }

  [Fact]
  public async Task PermissionAssignment_CreateAndGetByPrincipal_ReturnsAssignment()
  {
    var (testServer, client, tenantId, userId) = await CreateAuthenticatedServer();
    using var _ = testServer;

    var createResponse = await client.PostAsJsonAsync(
      HttpConstants.Internal.PermissionAssignmentsEndpoint,
      new InternalDtos.CreatePermissionAssignmentRequestDto(
        PermissionPrincipalKind.User,
        userId,
        "device.read",
        PermissionEffect.Allow,
        PermissionScopeKind.Tenant,
        tenantId,
        "Test assignment"),
      TestContext.Current.CancellationToken);

    Assert.Equal(HttpStatusCode.OK, createResponse.StatusCode);
    var created = await createResponse.Content.ReadFromJsonAsync<InternalDtos.PermissionAssignmentDto>(
      TestContext.Current.CancellationToken);
    Assert.NotNull(created);
    Assert.Equal("device.read", created.PermissionName);
    Assert.Equal(PermissionEffect.Allow, created.Effect);
    Assert.Equal(PermissionScopeKind.Tenant, created.ScopeKind);
    Assert.Equal(tenantId, created.ScopeId);
    Assert.True(created.IsEnabled);

    var getResponse = await client.GetAsync(
      $"{HttpConstants.Internal.PermissionAssignmentsEndpoint}?principalKind=User&principalId={userId}",
      TestContext.Current.CancellationToken);
    Assert.Equal(HttpStatusCode.OK, getResponse.StatusCode);
    var assignments = await getResponse.Content.ReadFromJsonAsync<InternalDtos.PermissionAssignmentDto[]>(
      TestContext.Current.CancellationToken);
    Assert.NotNull(assignments);
    Assert.Contains(assignments, a => a.Id == created.Id);
  }

  [Fact]
  public async Task PermissionAssignment_Delete_RemovesAssignment()
  {
    var (testServer, client, tenantId, userId) = await CreateAuthenticatedServer();
    using var _ = testServer;

    var createResponse = await client.PostAsJsonAsync(
      HttpConstants.Internal.PermissionAssignmentsEndpoint,
      new InternalDtos.CreatePermissionAssignmentRequestDto(
        PermissionPrincipalKind.User,
        userId,
        PermissionNames.DeviceRead,
        PermissionEffect.Deny,
        PermissionScopeKind.Tenant,
        tenantId,
        null),
      TestContext.Current.CancellationToken);
    var created = await createResponse.Content.ReadFromJsonAsync<InternalDtos.PermissionAssignmentDto>(
      TestContext.Current.CancellationToken);
    Assert.NotNull(created);

    var deleteResponse = await client.DeleteAsync(
      $"{HttpConstants.Internal.PermissionAssignmentsEndpoint}/{created.Id}",
      TestContext.Current.CancellationToken);
    Assert.Equal(HttpStatusCode.NoContent, deleteResponse.StatusCode);

    var getResponse = await client.GetAsync(
      $"{HttpConstants.Internal.PermissionAssignmentsEndpoint}?principalKind=User&principalId={userId}",
      TestContext.Current.CancellationToken);
    var assignments = await getResponse.Content.ReadFromJsonAsync<InternalDtos.PermissionAssignmentDto[]>(
      TestContext.Current.CancellationToken);
    Assert.NotNull(assignments);
    Assert.DoesNotContain(assignments, a => a.Id == created.Id);
  }

  [Fact]
  public async Task TenantDeletion_CascadesPermissionAssignments()
  {
    using var testServer = await TestWebServerBuilder.CreateTestServer(testOutput, useInMemoryDatabase: false);
    var services = testServer.Services;

    var tenant = await services.CreateTestTenant();
    var user = await services.CreateTestUser(
      tenant.Id, $"cascade-{Guid.NewGuid():N}@t.local", RoleNames.TenantAdministrator);

    using (var scope = services.CreateScope())
    {
      await using var db = scope.ServiceProvider.GetRequiredService<AppDb>();
      db.PermissionAssignments.Add(new Data.Entities.PermissionAssignment
      {
        PrincipalKind = PermissionPrincipalKind.User,
        PrincipalId = user.Id,
        PermissionName = "device.read",
        Effect = PermissionEffect.Allow,
        ScopeKind = PermissionScopeKind.Tenant,
        ScopeId = tenant.Id,
        IsEnabled = true,
        OwningTenantId = tenant.Id,
        CreatedByPrincipalType = "user",
        CreatedByPrincipalId = user.Id.ToString()
      });
      await db.SaveChangesAsync(TestContext.Current.CancellationToken);
    }

    using (var scope = services.CreateScope())
    {
      await using var db = scope.ServiceProvider.GetRequiredService<AppDb>();
      var count = await db.PermissionAssignments
        .IgnoreQueryFilters()
        .CountAsync(x => x.OwningTenantId == tenant.Id, TestContext.Current.CancellationToken);
      Assert.True(count > 0);
    }

    using (var scope = services.CreateScope())
    {
      var tenantProvisioning = scope.ServiceProvider.GetRequiredService<ITenantProvisioningService>();
      await tenantProvisioning.DeleteTenant(tenant.Id, TestContext.Current.CancellationToken);
    }

    using (var scope = services.CreateScope())
    {
      await using var db = scope.ServiceProvider.GetRequiredService<AppDb>();
      var remaining = await db.PermissionAssignments
        .IgnoreQueryFilters()
        .CountAsync(x => x.OwningTenantId == tenant.Id, TestContext.Current.CancellationToken);
      Assert.Equal(0, remaining);
    }
  }

  [Fact]
  public async Task UserGroup_AddAndRemoveMembers_UpdatesMembership()
  {
    var (testServer, client, tenantId, _) = await CreateAuthenticatedServer();
    using var _ = testServer;

    var memberUser = await testServer.Services.CreateTestUser(
      tenantId, $"member-{Guid.NewGuid():N}@t.local");

    var createResponse = await client.PostAsJsonAsync(
      HttpConstants.Internal.UserGroupsEndpoint,
      new InternalDtos.CreateUserGroupRequestDto("Member Test Group", null),
      TestContext.Current.CancellationToken);
    var group = await createResponse.Content.ReadFromJsonAsync<InternalDtos.UserGroupDetailDto>(
      TestContext.Current.CancellationToken);
    Assert.NotNull(group);

    var addResponse = await client.PostAsJsonAsync(
      $"{HttpConstants.Internal.UserGroupsEndpoint}/{group.Id}/members",
      new InternalDtos.AddUserGroupMembersRequestDto([memberUser.Id]),
      TestContext.Current.CancellationToken);
    Assert.Equal(HttpStatusCode.NoContent, addResponse.StatusCode);

    var getResponse = await client.GetAsync(
      $"{HttpConstants.Internal.UserGroupsEndpoint}/{group.Id}",
      TestContext.Current.CancellationToken);
    var withMembers = await getResponse.Content.ReadFromJsonAsync<InternalDtos.UserGroupDetailDto>(
      TestContext.Current.CancellationToken);
    Assert.NotNull(withMembers);
    Assert.Single(withMembers.Members);
    Assert.Equal(memberUser.Id, withMembers.Members[0].UserId);

    var removeResponse = await client.SendAsync(new HttpRequestMessage(HttpMethod.Delete,
      $"{HttpConstants.Internal.UserGroupsEndpoint}/{group.Id}/members")
    {
      Content = JsonContent.Create(new InternalDtos.RemoveUserGroupMembersRequestDto([memberUser.Id]))
    }, TestContext.Current.CancellationToken);
    Assert.Equal(HttpStatusCode.NoContent, removeResponse.StatusCode);

    var afterRemove = await client.GetAsync(
      $"{HttpConstants.Internal.UserGroupsEndpoint}/{group.Id}",
      TestContext.Current.CancellationToken);
    var afterRemoveDto = await afterRemove.Content.ReadFromJsonAsync<InternalDtos.UserGroupDetailDto>(
      TestContext.Current.CancellationToken);
    Assert.NotNull(afterRemoveDto);
    Assert.Empty(afterRemoveDto.Members);
  }

  [Fact]
  public async Task UserGroup_CreateGetUpdateDelete_CompletesFullCycle()
  {
    var (testServer, client, _, _) = await CreateAuthenticatedServer();
    using var _ = testServer;

    var createResponse = await client.PostAsJsonAsync(
      HttpConstants.Internal.UserGroupsEndpoint,
      new InternalDtos.CreateUserGroupRequestDto("Engineering", "Engineering team"),
      TestContext.Current.CancellationToken);

    Assert.Equal(HttpStatusCode.OK, createResponse.StatusCode);
    var created = await createResponse.Content.ReadFromJsonAsync<InternalDtos.UserGroupDetailDto>(
      TestContext.Current.CancellationToken);
    Assert.NotNull(created);
    Assert.Equal("Engineering", created.Name);
    Assert.Equal("Engineering team", created.Description);
    Assert.NotEqual(Guid.Empty, created.Id);
    Assert.Empty(created.Members);

    var getResponse = await client.GetAsync(
      $"{HttpConstants.Internal.UserGroupsEndpoint}/{created.Id}",
      TestContext.Current.CancellationToken);
    Assert.Equal(HttpStatusCode.OK, getResponse.StatusCode);

    var updateResponse = await client.PutAsJsonAsync(
      $"{HttpConstants.Internal.UserGroupsEndpoint}/{created.Id}",
      new InternalDtos.UpdateUserGroupRequestDto("Platform Engineering", "Platform team"),
      TestContext.Current.CancellationToken);
    Assert.Equal(HttpStatusCode.OK, updateResponse.StatusCode);
    var updated = await updateResponse.Content.ReadFromJsonAsync<InternalDtos.UserGroupDetailDto>(
      TestContext.Current.CancellationToken);
    Assert.NotNull(updated);
    Assert.Equal("Platform Engineering", updated.Name);

    var deleteResponse = await client.DeleteAsync(
      $"{HttpConstants.Internal.UserGroupsEndpoint}/{created.Id}",
      TestContext.Current.CancellationToken);
    Assert.Equal(HttpStatusCode.NoContent, deleteResponse.StatusCode);

    var getAfterDelete = await client.GetAsync(
      $"{HttpConstants.Internal.UserGroupsEndpoint}/{created.Id}",
      TestContext.Current.CancellationToken);
    Assert.Equal(HttpStatusCode.NotFound, getAfterDelete.StatusCode);
  }

  [Fact]
  public async Task UserGroup_Delete_CascadesPermissionAssignments()
  {
    var (testServer, client, tenantId, userId) = await CreateAuthenticatedServer();
    using var _ = testServer;

    var createGroupResponse = await client.PostAsJsonAsync(
      HttpConstants.Internal.UserGroupsEndpoint,
      new InternalDtos.CreateUserGroupRequestDto("Cascade Test User Group", null),
      TestContext.Current.CancellationToken);
    var group = await createGroupResponse.Content.ReadFromJsonAsync<InternalDtos.UserGroupDetailDto>(
      TestContext.Current.CancellationToken);
    Assert.NotNull(group);

    var createAssignmentResponse = await client.PostAsJsonAsync(
      HttpConstants.Internal.PermissionAssignmentsEndpoint,
      new InternalDtos.CreatePermissionAssignmentRequestDto(
        PermissionPrincipalKind.UserGroup,
        group.Id,
        "device.read",
        PermissionEffect.Allow,
        PermissionScopeKind.Tenant,
        tenantId,
        null),
      TestContext.Current.CancellationToken);
    Assert.Equal(HttpStatusCode.OK, createAssignmentResponse.StatusCode);

    var deleteResponse = await client.DeleteAsync(
      $"{HttpConstants.Internal.UserGroupsEndpoint}/{group.Id}",
      TestContext.Current.CancellationToken);
    Assert.Equal(HttpStatusCode.NoContent, deleteResponse.StatusCode);

    using var scope = testServer.Services.CreateScope();
    await using var db = scope.ServiceProvider.GetRequiredService<AppDb>();
    var remaining = await db.PermissionAssignments
      .CountAsync(x => x.PrincipalKind == PermissionPrincipalKind.UserGroup && x.PrincipalId == group.Id,
        TestContext.Current.CancellationToken);
    Assert.Equal(0, remaining);
  }

  [Fact]
  public async Task UserGroup_GetAll_ReturnsCreatedGroups()
  {
    var (testServer, client, _, _) = await CreateAuthenticatedServer();
    using var _ = testServer;

    await client.PostAsJsonAsync(
      HttpConstants.Internal.UserGroupsEndpoint,
      new InternalDtos.CreateUserGroupRequestDto("Team A", null),
      TestContext.Current.CancellationToken);
    await client.PostAsJsonAsync(
      HttpConstants.Internal.UserGroupsEndpoint,
      new InternalDtos.CreateUserGroupRequestDto("Team B", null),
      TestContext.Current.CancellationToken);

    var response = await client.GetAsync(
      HttpConstants.Internal.UserGroupsEndpoint,
      TestContext.Current.CancellationToken);
    Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    var groups = await response.Content.ReadFromJsonAsync<InternalDtos.UserGroupDto[]>(
      TestContext.Current.CancellationToken);
    Assert.NotNull(groups);
    Assert.Equal(2, groups.Length);
  }

  private async Task<(TestWebServer server, HttpClient client, Guid tenantId, Guid userId)> CreateAuthenticatedServer()
  {
    var testServer = await TestWebServerBuilder.CreateTestServer(testOutput);
    var httpClient = testServer.Factory.CreateClient();

    var tenant = await testServer.Services.CreateTestTenant();
    var user = await testServer.Services.CreateTestUser(
      tenant.Id,
      $"admin-{Guid.NewGuid():N}@t.local",
      RoleNames.TenantAdministrator);

    var patManager = testServer.Services.GetRequiredService<IPersonalAccessTokenManager>();
    var patResult = await patManager.CreateToken(
      new InternalDtos.CreatePersonalAccessTokenRequestDto("Integration Test PAT"),
      user.Id);
    Assert.True(patResult.IsSuccess, $"PAT creation failed: {patResult.Reason}");

    httpClient.DefaultRequestHeaders.Add(
      PersonalAccessTokenAuthenticationSchemeOptions.DefaultHeaderName,
      patResult.Value.PlainTextToken);

    return (testServer, httpClient, tenant.Id, user.Id);
  }
}
