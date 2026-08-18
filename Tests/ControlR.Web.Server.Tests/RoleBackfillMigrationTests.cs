using ControlR.Web.Server.Data;
using ControlR.Web.Server.Data.Entities;
using ControlR.Web.Server.Tests.Helpers;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.DependencyInjection;

namespace ControlR.Web.Server.Tests;

/// <summary>
/// Verifies the Remove_Roles migration backfills each user's legacy role memberships into
/// permission assignments before dropping the role tables, so existing users keep their access
/// when upgrading across the role-to-permission cutover.
/// </summary>
public class RoleBackfillMigrationTests(ITestOutputHelper output)
{
  private const string PreRemoveRolesMigration = "20260729192550_Update_EntityBase";

  [Fact]
  public async Task RemoveRoles_BackfillsRoleMembershipsIntoPermissionAssignments()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(
      output,
      useInMemoryDatabase: false,
      applyMigrations: false);

    using var scope = testApp.CreateScope();
    await using var db = scope.ServiceProvider.GetRequiredService<AppDb>();
    var migrator = db.GetInfrastructure().GetRequiredService<IMigrator>();

    // Stage the database at the migration just before Remove_Roles: the role tables (with the
    // seeded built-in roles) and the PermissionAssignments table both exist.
    await migrator.MigrateAsync(PreRemoveRolesMigration, TestContext.Current.CancellationToken);

    var tenant = new Tenant { Id = Guid.NewGuid(), Name = "Backfill Tenant" };
    db.Tenants.Add(tenant);
    await db.SaveChangesAsync(TestContext.Current.CancellationToken);

    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<AppUser>>();
    var user = new AppUser
    {
      TenantId = tenant.Id,
      UserName = "backfill@test.local",
      Email = "backfill@test.local"
    };
    var createResult = await userManager.CreateAsync(user, "T3stP@ssw0rd!");
    Assert.True(createResult.Succeeded);

    // Give the user three legacy roles. Installer Key Manager and Tenant Administrator
    // overlap on agent.install (server-scoped and tenant-scoped respectively).
    await db.Database.ExecuteSqlRawAsync(
      """
      INSERT INTO "AspNetUserRoles" ("UserId", "RoleId")
      SELECT {0}, "Id" FROM "AspNetRoles" WHERE "Name" IN ('Server Administrator', 'Tenant Administrator', 'Installer Key Manager');
      """,
      user.Id);

    // Apply Remove_Roles: backfills permission assignments, then drops the role tables.
    await migrator.MigrateAsync(cancellationToken: TestContext.Current.CancellationToken);

    using var verifyScope = testApp.CreateScope();
    await using var verifyDb = verifyScope.ServiceProvider.GetRequiredService<AppDb>();

    // Server Administrator preset permissions — server-scoped, no ScopeId, no OwningTenantId.
    var serverAdminPermissions = await verifyDb.PermissionAssignments
      .Where(x => x.PrincipalId == user.Id &&
                  x.ScopeKind == PermissionScopeKind.Server &&
                 (x.PermissionName == PermissionNames.ServerAdmin ||
                  x.PermissionName == PermissionNames.ServerTelemetryRead ||
                  x.PermissionName == PermissionNames.ServerServiceAccountsWrite))
      .ToListAsync(TestContext.Current.CancellationToken);

    Assert.NotEmpty(serverAdminPermissions);
    foreach (var perm in serverAdminPermissions)
    {
      Assert.Null(perm.ScopeId);
      Assert.Null(perm.OwningTenantId);
      Assert.Equal(PermissionScopeKind.Server, perm.ScopeKind);
    }

    // Tenant Administrator preset permissions — tenant-scoped with ScopeId = tenantId,
    // which PermissionEvaluator.ScopeMatches requires for tenant-scoped assignments.
    var tenantAdminPermissions = await verifyDb.PermissionAssignments
      .Where(x => x.PrincipalId == user.Id &&
                 (x.PermissionName == PermissionNames.TenantSettingsWrite ||
                  x.PermissionName == PermissionNames.TenantUsersRead))
      .ToListAsync(TestContext.Current.CancellationToken);

    Assert.NotEmpty(tenantAdminPermissions);
    foreach (var perm in tenantAdminPermissions)
    {
      Assert.Equal(tenant.Id, perm.ScopeId);
      Assert.Equal(PermissionScopeKind.Tenant, perm.ScopeKind);
      Assert.Equal(tenant.Id, perm.OwningTenantId);
    }

    // Installer Key Manager permissions are tenant-scoped, even when the user also has
    // Tenant Administrator, and duplicate permissions collapse to one assignment.
    var installerKeyPermissions = await verifyDb.PermissionAssignments
      .Where(x => x.PrincipalId == user.Id &&
                 (x.PermissionName == PermissionNames.InstallerKeyRead ||
                  x.PermissionName == PermissionNames.InstallerKeyWrite ||
                  x.PermissionName == PermissionNames.AgentInstall))
      .ToListAsync(TestContext.Current.CancellationToken);

    Assert.Equal(3, installerKeyPermissions.Count);
    foreach (var permission in installerKeyPermissions)
    {
      Assert.Equal(tenant.Id, permission.ScopeId);
      Assert.Equal(PermissionScopeKind.Tenant, permission.ScopeKind);
      Assert.Equal(tenant.Id, permission.OwningTenantId);
    }
  }
}
