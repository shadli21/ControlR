using ControlR.Web.Client.Authz;
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
  private const string PreRemoveRolesMigration = "20260729011817_Remove_UserTags";

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

    // Give the user two legacy roles whose presets overlap (both include agent.install).
    await db.Database.ExecuteSqlRawAsync(
      """
      INSERT INTO "AspNetUserRoles" ("UserId", "RoleId")
      SELECT {0}, "Id" FROM "AspNetRoles" WHERE "Name" IN ('Server Administrator', 'Tenant Administrator');
      """,
      user.Id);

    // Apply Remove_Roles: backfills permission assignments, then drops the role tables.
    await migrator.MigrateAsync(cancellationToken: TestContext.Current.CancellationToken);

    using var verifyScope = testApp.CreateScope();
    await using var verifyDb = verifyScope.ServiceProvider.GetRequiredService<AppDb>();
    var permissions = await verifyDb.PermissionAssignments
      .Where(x => x.PrincipalId == user.Id)
      .Select(x => x.PermissionName)
      .ToListAsync(TestContext.Current.CancellationToken);

    // Server Administrator preset permissions.
    Assert.Contains(PermissionNames.ServerAdmin, permissions);
    Assert.Contains(PermissionNames.ServerTelemetryRead, permissions);
    Assert.Contains(PermissionNames.ServerServiceAccountsWrite, permissions);

    // Tenant Administrator preset permissions.
    Assert.Contains(PermissionNames.TenantSettingsWrite, permissions);
    Assert.Contains(PermissionNames.TenantUsersRead, permissions);

    // Overlapping permission is granted once, scoped to the user's tenant.
    var agentInstallAssignments = await verifyDb.PermissionAssignments
      .Where(x => x.PrincipalId == user.Id && x.PermissionName == PermissionNames.AgentInstall)
      .ToListAsync(TestContext.Current.CancellationToken);
    var agentInstall = Assert.Single(agentInstallAssignments);
    Assert.Equal(tenant.Id, agentInstall.ScopeId);
    Assert.Equal(tenant.Id, agentInstall.OwningTenantId);
  }
}
