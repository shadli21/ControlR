using System.Net;
using System.Net.Http.Json;
using ControlR.Web.Server.Authn;
using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Data;
using ControlR.Web.Server.Data.Entities;
using ControlR.Web.Server.Data.Enums;
using ControlR.Web.Server.Primitives;
using ControlR.Web.Server.Services;
using ControlR.Web.Server.Services.PermissionAssignments;
using ControlR.Web.Server.Tests.Helpers;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace ControlR.Web.Server.Tests;

/// <summary>
/// Grant-authority matrix: locks down who may grant what. Delegated administration (a
/// tenant writer may grant permissions they do not hold), the server.admin requirement for
/// server-scoped grants, replace visibility semantics, and the policy-layer gate for
/// principals without tenant.permissions.write.
/// </summary>
public class PermissionGrantAuthorityTests(ITestOutputHelper testOutput)
{
  private readonly ITestOutputHelper _testOutput = testOutput;

  [Fact]
  public async Task Create_ServerScoped_ByNonServerAdmin_Forbidden()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    await testApp.App.Services.CreateTestUser(tenant.Id, email: $"seed-{Guid.NewGuid():N}@t.local");
    var actor = await testApp.App.Services.CreateTestUser(tenant.Id, email: $"actor-{Guid.NewGuid():N}@t.local");
    var target = await testApp.App.Services.CreateTestUser(tenant.Id, email: $"target-{Guid.NewGuid():N}@t.local");

    using var scope = testApp.CreateScope();
    var manager = scope.ServiceProvider.GetRequiredService<IPermissionAssignmentManager>();

    var result = await manager.Create(
      new InternalDtos.CreatePermissionAssignmentRequestDto(
        PermissionPrincipalKind.User,
        target.Id,
        PermissionNames.ServerAdmin,
        PermissionEffect.Allow,
        PermissionScopeKind.Server,
        null,
        null),
      tenant.Id,
      actor.Id,
      TestContext.Current.CancellationToken);

    Assert.False(result.IsSuccess);
    Assert.Equal(HttpResultErrorCode.Forbidden, result.ErrorCode);
  }

  [Fact]
  public async Task Create_ServerScoped_ByServerAdmin_Succeeds()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    await testApp.App.Services.CreateTestUser(tenant.Id, email: $"seed-{Guid.NewGuid():N}@t.local");
    var actor = await testApp.App.Services.CreateTestUser(tenant.Id, email: $"actor-{Guid.NewGuid():N}@t.local");
    var target = await testApp.App.Services.CreateTestUser(tenant.Id, email: $"target-{Guid.NewGuid():N}@t.local");

    await SeedAssignment(testApp, PermissionAssignment.CreateGrant(
      PermissionPrincipalKind.User,
      actor.Id,
      PermissionNames.ServerAdmin,
      PermissionScopeKind.Server,
      null,
      tenant.Id,
      "test",
      actor.Id.ToString()));

    using var scope = testApp.CreateScope();
    var manager = scope.ServiceProvider.GetRequiredService<IPermissionAssignmentManager>();

    var result = await manager.Create(
      new InternalDtos.CreatePermissionAssignmentRequestDto(
        PermissionPrincipalKind.User,
        target.Id,
        PermissionNames.ServerAlertsRead,
        PermissionEffect.Allow,
        PermissionScopeKind.Server,
        null,
        null),
      tenant.Id,
      actor.Id,
      TestContext.Current.CancellationToken);

    Assert.True(result.IsSuccess, $"Expected server-admin grant to succeed: {result.Reason}");
  }

  [Fact]
  public async Task Create_TenantScopedPermission_NotHeldByActor_Succeeds()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    await testApp.App.Services.CreateTestUser(tenant.Id, email: $"seed-{Guid.NewGuid():N}@t.local");
    var actor = await testApp.App.Services.CreateTestUser(tenant.Id, email: $"actor-{Guid.NewGuid():N}@t.local");
    var target = await testApp.App.Services.CreateTestUser(tenant.Id, email: $"target-{Guid.NewGuid():N}@t.local");

    using var scope = testApp.CreateScope();
    var manager = scope.ServiceProvider.GetRequiredService<IPermissionAssignmentManager>();

    var result = await manager.Create(
      new InternalDtos.CreatePermissionAssignmentRequestDto(
        PermissionPrincipalKind.User,
        target.Id,
        PermissionNames.DeviceRead,
        PermissionEffect.Allow,
        PermissionScopeKind.Tenant,
        tenant.Id,
        null),
      tenant.Id,
      actor.Id,
      TestContext.Current.CancellationToken);

    Assert.True(result.IsSuccess, $"Expected delegated-admin grant to succeed: {result.Reason}");
  }

  [Fact]
  public async Task Create_ViaApi_WithoutWritePermission_ReturnsForbidden()
  {
    using var testServer = await TestWebServerBuilder.CreateTestServer(_testOutput);
    using var httpClient = testServer.Factory.CreateClient();

    var tenant = await testServer.Services.CreateTestTenant();
    await testServer.Services.CreateTestUser(tenant.Id, email: $"seed-{Guid.NewGuid():N}@t.local");
    var user = await testServer.Services.CreateTestUser(tenant.Id, $"no-write-{Guid.NewGuid():N}@t.local");

    var patManager = testServer.Services.GetRequiredService<IPersonalAccessTokenManager>();
    var patResult = await patManager.CreateToken(
      new InternalDtos.CreatePersonalAccessTokenRequestDto("Grant Authority Test PAT"), user.Id);
    Assert.True(patResult.IsSuccess);
    httpClient.DefaultRequestHeaders.Add(
      PersonalAccessTokenAuthenticationSchemeOptions.DefaultHeaderName,
      patResult.Value.PlainTextToken);

    var response = await httpClient.PostAsJsonAsync(
      HttpConstants.Internal.PermissionAssignmentsEndpoint,
      new InternalDtos.CreatePermissionAssignmentRequestDto(
        PermissionPrincipalKind.User,
        user.Id,
        PermissionNames.DeviceRead,
        PermissionEffect.Allow,
        PermissionScopeKind.Tenant,
        tenant.Id,
        null),
      TestContext.Current.CancellationToken);

    Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
  }

  [Fact]
  public async Task Replace_ByServerAdmin_RewritesTenantAndServerRows()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    await testApp.App.Services.CreateTestUser(tenant.Id, email: $"seed-{Guid.NewGuid():N}@t.local");
    var actor = await testApp.App.Services.CreateTestUser(tenant.Id, email: $"actor-{Guid.NewGuid():N}@t.local");
    var target = await testApp.App.Services.CreateTestUser(tenant.Id, email: $"target-{Guid.NewGuid():N}@t.local");

    await SeedAssignment(testApp, PermissionAssignment.CreateGrant(
      PermissionPrincipalKind.User,
      actor.Id,
      PermissionNames.ServerAdmin,
      PermissionScopeKind.Server,
      null,
      tenant.Id,
      "test",
      actor.Id.ToString()));

    var tenantRow = PermissionAssignment.CreateGrant(
      PermissionPrincipalKind.User,
      target.Id,
      PermissionNames.DeviceRead,
      PermissionScopeKind.Tenant,
      tenant.Id,
      tenant.Id,
      "test",
      actor.Id.ToString());

    var serverRow = PermissionAssignment.CreateGrant(
      PermissionPrincipalKind.User,
      target.Id,
      PermissionNames.ServerAlertsRead,
      PermissionScopeKind.Server,
      null,
      tenant.Id,
      "test",
      actor.Id.ToString());

    await SeedAssignment(testApp, tenantRow);
    await SeedAssignment(testApp, serverRow);

    using var scope = testApp.CreateScope();
    var manager = scope.ServiceProvider.GetRequiredService<IPermissionAssignmentManager>();

    var replaceResult = await manager.ReplaceForPrincipal(
      PermissionPrincipalKind.User,
      target.Id,
      tenant.Id,
      actor.Id,
      [
        new InternalDtos.CreatePermissionAssignmentRequestDto(
          PermissionPrincipalKind.User,
          target.Id,
          PermissionNames.DeviceLogsRead,
          PermissionEffect.Allow,
          PermissionScopeKind.Tenant,
          tenant.Id,
          null)
      ],
      TestContext.Current.CancellationToken);

    Assert.True(replaceResult.IsSuccess, $"Expected replace to succeed: {replaceResult.Reason}");

    var remaining = await manager.GetByPrincipal(
      PermissionPrincipalKind.User, target.Id, tenant.Id, actor.Id, TestContext.Current.CancellationToken);

    Assert.Single(remaining);
    Assert.Equal(PermissionNames.DeviceLogsRead, remaining[0].PermissionName);
  }

  [Fact]
  public async Task Update_ToServerScope_ByNonServerAdmin_Forbidden()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    await testApp.App.Services.CreateTestUser(tenant.Id, email: $"seed-{Guid.NewGuid():N}@t.local");
    var actor = await testApp.App.Services.CreateTestUser(tenant.Id, email: $"actor-{Guid.NewGuid():N}@t.local");
    var target = await testApp.App.Services.CreateTestUser(tenant.Id, email: $"target-{Guid.NewGuid():N}@t.local");

    var assignment = PermissionAssignment.CreateGrant(
      PermissionPrincipalKind.User,
      target.Id,
      PermissionNames.ServerAlertsRead,
      PermissionScopeKind.Tenant,
      tenant.Id,
      tenant.Id,
      "test",
      actor.Id.ToString());

    await SeedAssignment(testApp, assignment);

    using var scope = testApp.CreateScope();
    var manager = scope.ServiceProvider.GetRequiredService<IPermissionAssignmentManager>();

    var result = await manager.Update(
      assignment.Id,
      new InternalDtos.UpdatePermissionAssignmentRequestDto(
        PermissionNames.ServerAlertsRead,
        PermissionEffect.Allow,
        PermissionScopeKind.Server,
        null,
        null,
        true),
      tenant.Id,
      actor.Id,
      TestContext.Current.CancellationToken);

    Assert.False(result.IsSuccess);
    Assert.Equal(HttpResultErrorCode.Forbidden, result.ErrorCode);
  }

  private static async Task SeedAssignment(TestApp testApp, PermissionAssignment assignment)
  {
    using var scope = testApp.CreateScope();
    await using var db = scope.ServiceProvider.GetRequiredService<AppDb>();
    db.PermissionAssignments.Add(assignment);
    await db.SaveChangesAsync(TestContext.Current.CancellationToken);
  }
}
