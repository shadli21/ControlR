using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Authn;
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
/// PAT scope-creation flow: optional least-privilege scopes are validated against the
/// owner's effective permissions and persisted as PAT-principal assignment rows.
/// </summary>
public class PersonalAccessTokenScopeTests(ITestOutputHelper testOutput)
{
  private readonly ITestOutputHelper _testOutput = testOutput;

  [Fact]
  public async Task CreateAssignment_ForPatPrincipal_OutsideOwnerPermissions_Fails()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    await testApp.App.Services.CreateTestUser(tenant.Id, email: $"seed-{Guid.NewGuid():N}@t.local");
    var user = await testApp.App.Services.CreateTestUser(
      tenant.Id,
      $"pat-owner-{Guid.NewGuid():N}@t.local",
      PermissionPresets.TenantAdministrator);
    var device = await testApp.App.Services.CreateTestDevice(tenant.Id);

    using var scope = testApp.CreateScope();
    var patManager = scope.ServiceProvider.GetRequiredService<IPersonalAccessTokenManager>();
    var assignmentManager = scope.ServiceProvider.GetRequiredService<IPermissionAssignmentManager>();

    var patResult = await patManager.CreateToken(
      new InternalDtos.CreatePersonalAccessTokenRequestDto("Panel-Scoped PAT"), user.Id);
    Assert.True(patResult.IsSuccess);

    var tokenId = patResult.Value.PersonalAccessToken.Id;

    var result = await assignmentManager.Create(
      new InternalDtos.CreatePermissionAssignmentRequestDto(
        PermissionPrincipalKind.PersonalAccessToken,
        tokenId,
        PermissionNames.DeviceRead,
        PermissionEffect.Allow,
        PermissionScopeKind.Device,
        device.Id,
        null),
      tenant.Id,
      new PrincipalDescriptor(PrincipalClaimTypes.User, user.Id, tenant.Id, "test"),
      TestContext.Current.CancellationToken);

    Assert.False(result.IsSuccess);
    Assert.Equal(HttpResultErrorCode.BadRequest, result.ErrorCode);
  }

  [Fact]
  public async Task CreateAssignment_ForPatPrincipal_WithinOwnerPermissions_Succeeds()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    await testApp.App.Services.CreateTestUser(tenant.Id, email: $"seed-{Guid.NewGuid():N}@t.local");
    var user = await testApp.App.Services.CreateTestUser(
      tenant.Id,
      $"pat-owner-{Guid.NewGuid():N}@t.local",
      PermissionPresets.DeviceSuperUser,
      PermissionPresets.TenantAdministrator);
    var device = await testApp.App.Services.CreateTestDevice(tenant.Id);

    using var scope = testApp.CreateScope();
    var patManager = scope.ServiceProvider.GetRequiredService<IPersonalAccessTokenManager>();
    var assignmentManager = scope.ServiceProvider.GetRequiredService<IPermissionAssignmentManager>();

    var patResult = await patManager.CreateToken(
      new InternalDtos.CreatePersonalAccessTokenRequestDto("Panel-Scoped PAT"), user.Id);
    Assert.True(patResult.IsSuccess);

    var tokenId = patResult.Value.PersonalAccessToken.Id;

    var result = await assignmentManager.Create(
      new InternalDtos.CreatePermissionAssignmentRequestDto(
        PermissionPrincipalKind.PersonalAccessToken,
        tokenId,
        PermissionNames.DeviceRead,
        PermissionEffect.Allow,
        PermissionScopeKind.Device,
        device.Id,
        null),
      tenant.Id,
      new PrincipalDescriptor(PrincipalClaimTypes.User, user.Id, tenant.Id, "test"),
      TestContext.Current.CancellationToken);

    Assert.True(result.IsSuccess, $"Expected panel assignment to succeed: {result.Reason}");
  }

  [Fact]
  public async Task CreateToken_WithoutScopes_RemainsUserEquivalent()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    await testApp.App.Services.CreateTestUser(tenant.Id, email: $"seed-{Guid.NewGuid():N}@t.local");
    var user = await testApp.App.Services.CreateTestUser(tenant.Id, $"pat-owner-{Guid.NewGuid():N}@t.local");

    using var scope = testApp.CreateScope();
    var manager = scope.ServiceProvider.GetRequiredService<IPersonalAccessTokenManager>();

    var result = await manager.CreateToken(
      new InternalDtos.CreatePersonalAccessTokenRequestDto("Unscoped PAT"),
      user.Id);

    Assert.True(result.IsSuccess);

    await using var db = scope.ServiceProvider.GetRequiredService<AppDb>();
    var scopeRows = await db.PermissionAssignments
      .IgnoreQueryFilters()
      .CountAsync(x => x.PrincipalKind == PermissionPrincipalKind.PersonalAccessToken &&
                       x.PrincipalId == result.Value.PersonalAccessToken.Id,
        TestContext.Current.CancellationToken);
    Assert.Equal(0, scopeRows);
  }

  [Fact]
  public async Task CreateToken_WithScopeOutsideOwnerPermissions_FailsAndCreatesNothing()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    await testApp.App.Services.CreateTestUser(tenant.Id, email: $"seed-{Guid.NewGuid():N}@t.local");
    var user = await testApp.App.Services.CreateTestUser(tenant.Id, $"pat-owner-{Guid.NewGuid():N}@t.local");
    var device = await testApp.App.Services.CreateTestDevice(tenant.Id);

    using var scope = testApp.CreateScope();
    var manager = scope.ServiceProvider.GetRequiredService<IPersonalAccessTokenManager>();

    var result = await manager.CreateToken(
      new InternalDtos.CreatePersonalAccessTokenRequestDto(
        "Scoped PAT",
        Scopes: [new InternalDtos.CredentialScopeDto(PermissionNames.DeviceRead, PermissionScopeKind.Device, device.Id)]),
      user.Id);

    Assert.False(result.IsSuccess);

    await using var db = scope.ServiceProvider.GetRequiredService<AppDb>();
    var tokenCount = await db.PersonalAccessTokens
      .IgnoreQueryFilters()
      .CountAsync(x => x.UserId == user.Id, TestContext.Current.CancellationToken);
    Assert.Equal(0, tokenCount);
  }

  [Fact]
  public async Task CreateToken_WithValidScopes_WritesScopeRows()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    await testApp.App.Services.CreateTestUser(tenant.Id, email: $"seed-{Guid.NewGuid():N}@t.local");
    var user = await testApp.App.Services.CreateTestUser(
      tenant.Id, $"pat-owner-{Guid.NewGuid():N}@t.local", PermissionPresets.DeviceSuperUser);
    var device = await testApp.App.Services.CreateTestDevice(tenant.Id);

    using var scope = testApp.CreateScope();
    var manager = scope.ServiceProvider.GetRequiredService<IPersonalAccessTokenManager>();

    var result = await manager.CreateToken(
      new InternalDtos.CreatePersonalAccessTokenRequestDto(
        "Scoped PAT",
        Scopes: [new InternalDtos.CredentialScopeDto(PermissionNames.DeviceRead, PermissionScopeKind.Device, device.Id)]),
      user.Id);

    Assert.True(result.IsSuccess, $"Scoped PAT creation failed: {result.Reason}");

    await using var db = scope.ServiceProvider.GetRequiredService<AppDb>();
    var tokenId = result.Value.PersonalAccessToken.Id;

    var scopeRows = await db.PermissionAssignments
      .IgnoreQueryFilters()
      .Where(x => x.PrincipalKind == PermissionPrincipalKind.PersonalAccessToken && x.PrincipalId == tokenId)
      .ToListAsync(TestContext.Current.CancellationToken);

    var row = Assert.Single(scopeRows);
    Assert.Equal(PermissionNames.DeviceRead, row.PermissionName);
    Assert.Equal(PermissionScopeKind.Device, row.ScopeKind);
    Assert.Equal(device.Id, row.ScopeId);
    Assert.Equal(tenant.Id, row.OwningTenantId);

    var changeLogCount = await db.AuthorizationChangeLogs
      .IgnoreQueryFilters()
      .CountAsync(x => x.TargetId == tokenId, TestContext.Current.CancellationToken);
    Assert.Equal(1, changeLogCount);
  }

  [Fact]
  public async Task CreateToken_WithValidScopes_OnPostgres_WritesScopeRowsKeyedByRealTokenId()
  {
    // Regression test: entity Ids are database-generated (gen_random_uuid()) on Postgres, so
    // scope rows must be written after the token is saved. A pre-save Id would be Guid.Empty,
    // orphaning the scope rows and silently granting the PAT the owner's full permissions.
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput, useInMemoryDatabase: false);
    var tenant = await testApp.App.Services.CreateTestTenant();
    await testApp.App.Services.CreateTestUser(tenant.Id, email: $"seed-{Guid.NewGuid():N}@t.local");
    var user = await testApp.App.Services.CreateTestUser(
      tenant.Id, $"pat-owner-{Guid.NewGuid():N}@t.local", PermissionPresets.DeviceSuperUser);
    var device = await testApp.App.Services.CreateTestDevice(tenant.Id);

    using var scope = testApp.CreateScope();
    var manager = scope.ServiceProvider.GetRequiredService<IPersonalAccessTokenManager>();

    var result = await manager.CreateToken(
      new InternalDtos.CreatePersonalAccessTokenRequestDto(
        "Scoped PAT",
        Scopes: [new InternalDtos.CredentialScopeDto(PermissionNames.DeviceRead, PermissionScopeKind.Device, device.Id)]),
      user.Id);

    Assert.True(result.IsSuccess, $"Scoped PAT creation failed: {result.Reason}");

    await using var db = scope.ServiceProvider.GetRequiredService<AppDb>();
    var tokenId = result.Value.PersonalAccessToken.Id;

    Assert.NotEqual(Guid.Empty, tokenId);

    var scopeRows = await db.PermissionAssignments
      .IgnoreQueryFilters()
      .Where(x => x.PrincipalKind == PermissionPrincipalKind.PersonalAccessToken && x.PrincipalId == tokenId)
      .ToListAsync(TestContext.Current.CancellationToken);

    var row = Assert.Single(scopeRows);
    Assert.Equal(PermissionNames.DeviceRead, row.PermissionName);
    Assert.Equal(PermissionScopeKind.Device, row.ScopeKind);
    Assert.Equal(device.Id, row.ScopeId);
    Assert.Equal(tenant.Id, row.OwningTenantId);

    var changeLogCount = await db.AuthorizationChangeLogs
      .IgnoreQueryFilters()
      .CountAsync(x => x.TargetId == tokenId, TestContext.Current.CancellationToken);
    Assert.Equal(1, changeLogCount);
  }
}
