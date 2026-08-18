using System.Net;
using System.Net.Http.Json;
using ControlR.Web.Server.Authn;
using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Data;
using ControlR.Web.Server.Data.Entities;
using ControlR.Web.Server.Primitives;
using ControlR.Web.Server.Services;
using ControlR.Web.Server.Services.PermissionAssignments;
using ControlR.Web.Server.Services.ServiceAccounts;
using ControlR.Web.Server.Tests.Helpers;
using Microsoft.Extensions.DependencyInjection;

namespace ControlR.Web.Server.Tests;

/// <summary>
/// Grant-authority matrix: locks down who may grant what. Delegated administration (a
/// tenant writer may grant permissions they do not hold), the server.permissions.write requirement for
/// server-scoped grants, replace visibility semantics, and the policy-layer gate for
/// principals without tenant.permissions.write.
/// </summary>
public class PermissionGrantAuthorityTests(ITestOutputHelper testOutput)
{
  private readonly ITestOutputHelper _testOutput = testOutput;

    [Fact]
    public async Task ApplyPresets_WithMixedScopesAndRequiredPermissions_Succeeds()
    {
      await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
      var tenant = await testApp.App.Services.CreateTestTenant();
      await testApp.App.Services.CreateTestUser(tenant.Id, email: $"seed-{Guid.NewGuid():N}@t.local");
      var actor = await testApp.App.Services.CreateTestUser(tenant.Id, email: $"actor-{Guid.NewGuid():N}@t.local");
      var target = await testApp.App.Services.CreateTestUser(tenant.Id, email: $"target-{Guid.NewGuid():N}@t.local");

      await SeedAssignment(testApp, PermissionAssignment.CreateGrant(
        PermissionPrincipalKind.User,
        actor.Id,
        PermissionNames.ServerPermissionsWrite,
        PermissionScopeKind.Server,
        null,
        tenant.Id,
        "test",
        actor.Id.ToString()));
      await SeedAssignment(testApp, PermissionAssignment.CreateGrant(
        PermissionPrincipalKind.User,
        actor.Id,
        PermissionNames.TenantPermissionsWrite,
        PermissionScopeKind.Tenant,
        tenant.Id,
        tenant.Id,
        "test",
        actor.Id.ToString()));

      using var scope = testApp.CreateScope();
      var manager = scope.ServiceProvider.GetRequiredService<IPermissionAssignmentManager>();

      var result = await manager.ApplyPresets(
        new InternalDtos.ApplyPermissionPresetsRequestDto(
          PermissionPrincipalKind.User,
          target.Id,
          [PermissionPresets.ServerAdministrator],
          ReplaceExisting: false),
        tenant.Id,
        Actor(actor.Id, tenant.Id),
        TestContext.Current.CancellationToken);

      Assert.True(result.IsSuccess, $"Expected preset application to succeed: {result.Reason}");
      Assert.Equal(PermissionPresets.GetPermissions(PermissionPresets.ServerAdministrator).Count, result.Value);
    }

  [Fact]
  public async Task Create_AssignmentTargetingServerServiceAccount_ByServerAdmin_Succeeds()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    await testApp.App.Services.CreateTestUser(tenant.Id, email: $"seed-{Guid.NewGuid():N}@t.local");
    var actor = await testApp.App.Services.CreateTestUser(tenant.Id, email: $"actor-{Guid.NewGuid():N}@t.local");

    await SeedAssignment(testApp, PermissionAssignment.CreateGrant(
      PermissionPrincipalKind.User,
      actor.Id,
      PermissionNames.ServerPermissionsWrite,
      PermissionScopeKind.Server,
      null,
      tenant.Id,
      "test",
      actor.Id.ToString()));

    using var setupScope = testApp.CreateScope();
    var accountManager = setupScope.ServiceProvider.GetRequiredService<IServiceAccountManager>();
    var accountResult = await accountManager.CreateForServer(
      $"server-sa-{Guid.NewGuid():N}", null, TestContext.Current.CancellationToken);
    Assert.True(accountResult.IsSuccess);
    var accountId = accountResult.Value.Id;

    using var scope = testApp.CreateScope();
    var manager = scope.ServiceProvider.GetRequiredService<IPermissionAssignmentManager>();

    var result = await manager.Create(
      new InternalDtos.CreatePermissionAssignmentRequestDto(
        PermissionPrincipalKind.ServiceAccount,
        accountId,
        PermissionNames.ServerAlertsRead,
        PermissionEffect.Allow,
        PermissionScopeKind.Server,
        null,
        null),
      tenant.Id,
      Actor(actor.Id, tenant.Id),
      TestContext.Current.CancellationToken);

    Assert.True(result.IsSuccess, $"Expected to succeed: {result.Reason}");
  }

  [Fact]
  public async Task Create_AssignmentTargetingServerServiceAccount_ByTenantAdmin_Forbidden()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    await testApp.App.Services.CreateTestUser(tenant.Id, email: $"seed-{Guid.NewGuid():N}@t.local");
    var actor = await testApp.App.Services.CreateTestUser(tenant.Id, email: $"actor-{Guid.NewGuid():N}@t.local");

    // Tenant admin with TenantPermissionsWrite but no ServerPermissionsWrite. A server
    // service account is a cross-tenant principal, so targeting one must require server
    // write authority; a tenant-scoped grant must not be attachable to it.
    await SeedAssignment(testApp, PermissionAssignment.CreateGrant(
      PermissionPrincipalKind.User,
      actor.Id,
      PermissionNames.TenantPermissionsWrite,
      PermissionScopeKind.Tenant,
      tenant.Id,
      tenant.Id,
      "test",
      actor.Id.ToString()));

    // Create a server-scoped service account to target.
    using var setupScope = testApp.CreateScope();
    var accountManager = setupScope.ServiceProvider.GetRequiredService<IServiceAccountManager>();
    var accountResult = await accountManager.CreateForServer(
      $"server-sa-{Guid.NewGuid():N}", null, TestContext.Current.CancellationToken);
    Assert.True(accountResult.IsSuccess);
    var accountId = accountResult.Value.Id;

    using var scope = testApp.CreateScope();
    var manager = scope.ServiceProvider.GetRequiredService<IPermissionAssignmentManager>();

    var result = await manager.Create(
      new InternalDtos.CreatePermissionAssignmentRequestDto(
        PermissionPrincipalKind.ServiceAccount,
        accountId,
        PermissionNames.DeviceRead,
        PermissionEffect.Allow,
        PermissionScopeKind.Tenant,
        tenant.Id,
        null),
      tenant.Id,
      Actor(actor.Id, tenant.Id),
      TestContext.Current.CancellationToken);

    Assert.False(result.IsSuccess);
    Assert.Equal(HttpResultErrorCode.Forbidden, result.ErrorCode);
  }

  [Fact]
  public async Task Create_IdenticalAssignment_ReturnsConflict_WhileOppositeEffectSucceeds()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    await testApp.App.Services.CreateTestUser(tenant.Id, email: $"seed-{Guid.NewGuid():N}@t.local");
    var actor = await testApp.App.Services.CreateTestUser(tenant.Id, email: $"actor-{Guid.NewGuid():N}@t.local");
    var target = await testApp.App.Services.CreateTestUser(tenant.Id, email: $"target-{Guid.NewGuid():N}@t.local");

    await SeedAssignment(testApp, PermissionAssignment.CreateGrant(
      PermissionPrincipalKind.User,
      actor.Id,
      PermissionNames.TenantPermissionsWrite,
      PermissionScopeKind.Tenant,
      tenant.Id,
      tenant.Id,
      "test",
      actor.Id.ToString()));
    await SeedAssignment(testApp, PermissionAssignment.CreateGrant(
      PermissionPrincipalKind.User,
      actor.Id,
      PermissionNames.TenantPermissionsDeny,
      PermissionScopeKind.Tenant,
      tenant.Id,
      tenant.Id,
      "test",
      actor.Id.ToString()));

    using var scope = testApp.CreateScope();
    var manager = scope.ServiceProvider.GetRequiredService<IPermissionAssignmentManager>();
    var request = new InternalDtos.CreatePermissionAssignmentRequestDto(
      PermissionPrincipalKind.User,
      target.Id,
      PermissionNames.DeviceRead,
      PermissionEffect.Allow,
      PermissionScopeKind.Tenant,
      tenant.Id,
      null);

    var first = await manager.Create(request, tenant.Id, Actor(actor.Id, tenant.Id), TestContext.Current.CancellationToken);
    var duplicate = await manager.Create(request, tenant.Id, Actor(actor.Id, tenant.Id), TestContext.Current.CancellationToken);
    var deny = await manager.Create(
      request with { Effect = PermissionEffect.Deny },
      tenant.Id,
      Actor(actor.Id, tenant.Id),
      TestContext.Current.CancellationToken);

    Assert.True(first.IsSuccess);
    Assert.False(duplicate.IsSuccess);
    Assert.Equal(HttpResultErrorCode.Conflict, duplicate.ErrorCode);
    Assert.True(deny.IsSuccess);
  }

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
        Actor(actor.Id, tenant.Id),
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
      PermissionNames.ServerPermissionsWrite,
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
        Actor(actor.Id, tenant.Id),
        TestContext.Current.CancellationToken);

    Assert.True(result.IsSuccess, $"Expected server-admin grant to succeed: {result.Reason}");
  }

  [Fact]
  public async Task Create_TenantScopedPermission_WithTenantPermissionsWrite_Succeeds()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    await testApp.App.Services.CreateTestUser(tenant.Id, email: $"seed-{Guid.NewGuid():N}@t.local");
    var actor = await testApp.App.Services.CreateTestUser(tenant.Id, email: $"actor-{Guid.NewGuid():N}@t.local");
    var target = await testApp.App.Services.CreateTestUser(tenant.Id, email: $"target-{Guid.NewGuid():N}@t.local");

    await SeedAssignment(testApp, PermissionAssignment.CreateGrant(
      PermissionPrincipalKind.User,
      actor.Id,
      PermissionNames.TenantPermissionsWrite,
      PermissionScopeKind.Tenant,
      tenant.Id,
      tenant.Id,
      "test",
      actor.Id.ToString()));

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
        Actor(actor.Id, tenant.Id),
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
      PermissionNames.ServerPermissionsWrite,
      PermissionScopeKind.Server,
      null,
      tenant.Id,
      "test",
      actor.Id.ToString()));
    await SeedAssignment(testApp, PermissionAssignment.CreateGrant(
      PermissionPrincipalKind.User,
      actor.Id,
      PermissionNames.TenantPermissionsWrite,
      PermissionScopeKind.Tenant,
      tenant.Id,
      tenant.Id,
      "test",
      actor.Id.ToString()));
    await SeedAssignment(testApp, PermissionAssignment.CreateGrant(
      PermissionPrincipalKind.User,
      actor.Id,
      PermissionNames.ServerPermissionsRead,
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
        Actor(actor.Id, tenant.Id),
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
      PermissionPrincipalKind.User,
      target.Id,
      tenant.Id,
        Actor(actor.Id, tenant.Id),
        TestContext.Current.CancellationToken);

    Assert.Equal(2, remaining.Count);
    Assert.Contains(remaining, assignment => assignment.PermissionName == PermissionNames.DeviceLogsRead);
    Assert.Contains(remaining, assignment => assignment.PermissionName == PermissionNames.ServerAlertsRead);
  }

  [Fact]
  public async Task Replace_ByServerAdmin_WithServerScopedAssignments_PreservesTenantRows()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    await testApp.App.Services.CreateTestUser(tenant.Id, email: $"seed-{Guid.NewGuid():N}@t.local");
    var actor = await testApp.App.Services.CreateTestUser(tenant.Id, email: $"actor-{Guid.NewGuid():N}@t.local");
    var target = await testApp.App.Services.CreateTestUser(tenant.Id, email: $"target-{Guid.NewGuid():N}@t.local");

    await SeedAssignment(testApp, PermissionAssignment.CreateGrant(
      PermissionPrincipalKind.User,
      actor.Id,
      PermissionNames.ServerPermissionsWrite,
      PermissionScopeKind.Server,
      null,
      tenant.Id,
      "test",
      actor.Id.ToString()));
    await SeedAssignment(testApp, PermissionAssignment.CreateGrant(
      PermissionPrincipalKind.User,
      actor.Id,
      PermissionNames.ServerPermissionsRead,
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
        Actor(actor.Id, tenant.Id),
      [
        new InternalDtos.CreatePermissionAssignmentRequestDto(
          PermissionPrincipalKind.User,
          target.Id,
          PermissionNames.ServerTelemetryRead,
          PermissionEffect.Allow,
          PermissionScopeKind.Server,
          null,
          null)
      ],
        TestContext.Current.CancellationToken);

    Assert.True(replaceResult.IsSuccess, $"Expected replace to succeed: {replaceResult.Reason}");

    var remaining = await manager.GetByPrincipal(
      PermissionPrincipalKind.User,
      target.Id,
      tenant.Id,
        Actor(actor.Id, tenant.Id),
        TestContext.Current.CancellationToken);

    Assert.Contains(remaining, x => x.Id == tenantRow.Id && x.PermissionName == PermissionNames.DeviceRead);
    Assert.DoesNotContain(remaining, x => x.Id == serverRow.Id);
    Assert.Contains(remaining, x => x.PermissionName == PermissionNames.ServerTelemetryRead);
  }

    [Fact]
    public async Task Update_ServerScopeToTenantScope_WithoutTenantPermissionsWrite_Forbidden()
    {
      await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
      var tenant = await testApp.App.Services.CreateTestTenant();
      await testApp.App.Services.CreateTestUser(tenant.Id, email: $"seed-{Guid.NewGuid():N}@t.local");
      var actor = await testApp.App.Services.CreateTestUser(tenant.Id, email: $"actor-{Guid.NewGuid():N}@t.local");
      var target = await testApp.App.Services.CreateTestUser(tenant.Id, email: $"target-{Guid.NewGuid():N}@t.local");

      await SeedAssignment(testApp, PermissionAssignment.CreateGrant(
        PermissionPrincipalKind.User,
        actor.Id,
        PermissionNames.ServerPermissionsWrite,
        PermissionScopeKind.Server,
        null,
        tenant.Id,
        "test",
        actor.Id.ToString()));

      var assignment = PermissionAssignment.CreateGrant(
        PermissionPrincipalKind.User,
        target.Id,
        PermissionNames.ServerAlertsRead,
        PermissionScopeKind.Server,
        null,
        tenant.Id,
        "test",
        actor.Id.ToString());
      await SeedAssignment(testApp, assignment);

      using var scope = testApp.CreateScope();
      var manager = scope.ServiceProvider.GetRequiredService<IPermissionAssignmentManager>();

      var result = await manager.Update(
        assignment.Id,
        new InternalDtos.UpdatePermissionAssignmentRequestDto(
          PermissionNames.DeviceRead,
          PermissionEffect.Allow,
          PermissionScopeKind.Tenant,
          tenant.Id,
          null,
          true),
        tenant.Id,
        Actor(actor.Id, tenant.Id),
        TestContext.Current.CancellationToken);

      Assert.False(result.IsSuccess);
      Assert.Equal(HttpResultErrorCode.Forbidden, result.ErrorCode);
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
        Actor(actor.Id, tenant.Id),
      TestContext.Current.CancellationToken);

    Assert.False(result.IsSuccess);
      Assert.Equal(HttpResultErrorCode.Forbidden, result.ErrorCode);
  }

    private static PrincipalDescriptor Actor(Guid principalId, Guid tenantId) =>
      new(PrincipalClaimTypes.User, principalId, tenantId, "test");

  private static async Task SeedAssignment(TestApp testApp, PermissionAssignment assignment)
  {
    using var scope = testApp.CreateScope();
    await using var db = scope.ServiceProvider.GetRequiredService<AppDb>();
    db.PermissionAssignments.Add(assignment);
    await db.SaveChangesAsync(TestContext.Current.CancellationToken);
  }
}
