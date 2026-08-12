using ControlR.Web.Server.Data;
using ControlR.Web.Server.Data.Entities;
using ControlR.Web.Server.Data.Enums;
using ControlR.Web.Server.Tests.Helpers;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.DependencyInjection;

namespace ControlR.Web.Server.Tests;

/// <summary>
/// Verifies the MakeChangeLogIdsUuid migration converts the authorization change-log ID columns
/// from varchar to uuid, normalizing the legacy empty-GUID (<c>00000000-...</c>) placeholders
/// (written by pre-save ID reads) to NULL and preserving valid GUID strings.
/// </summary>
public class AuthorizationChangeLogUuidMigrationTests(ITestOutputHelper output)
{
  private const string PreUuidMigration = "20260729192550_Update_EntityBase";

  [Fact]
  public async Task MakeChangeLogIdsUuid_NormalizesEmptyGuidsAndCastsColumns()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(
      output,
      useInMemoryDatabase: false,
      applyMigrations: false);

    using var scope = testApp.CreateScope();
    await using var db = scope.ServiceProvider.GetRequiredService<AppDb>();
    var migrator = db.GetInfrastructure().GetRequiredService<IMigrator>();

    // Stage the database just before the uuid conversion: ActorPrincipalId/TargetId are still varchar.
    await migrator.MigrateAsync(PreUuidMigration, TestContext.Current.CancellationToken);

    var tenantId = Guid.NewGuid();
    var validActorId = Guid.NewGuid();
    var validTargetId = Guid.NewGuid();

    // Seed legacy rows: a valid pair, an empty-GUID pair (the bug this migration repairs),
    // and a malformed non-GUID string to confirm the cast guard.
    await db.Database.ExecuteSqlRawAsync(
      """
      INSERT INTO "AuthorizationChangeLogs"
        ("Id", "ActionType", "ActorPrincipalType", "ActorPrincipalId", "TargetType", "TargetId", "OwningTenantId")
      VALUES
        ({0}, 'action', 'user', {1}, 'ServiceAccount', {2}, {3}),
        ({4}, 'action', 'user', '00000000-0000-0000-0000-000000000000', 'ServiceAccountCredential', '00000000-0000-0000-0000-000000000000', {3}),
        ({5}, 'action', 'user', 'not-a-guid', 'DeviceGroup', NULL, {3});
      """,
      Guid.NewGuid(),
      validActorId.ToString(),
      validTargetId.ToString(),
      tenantId,
      Guid.NewGuid(),
      Guid.NewGuid());

    // Apply MakeChangeLogIdsUuid.
    await migrator.MigrateAsync(cancellationToken: TestContext.Current.CancellationToken);

    using var verifyScope = testApp.CreateScope();
    await using var verifyDb = verifyScope.ServiceProvider.GetRequiredService<AppDb>();

    var rows = await verifyDb.AuthorizationChangeLogs.AsNoTracking().ToListAsync(TestContext.Current.CancellationToken);
    Assert.Equal(3, rows.Count);

    var validRow = Assert.Single(rows, x => x.TargetId == validTargetId);
    Assert.Equal(validActorId, validRow.ActorPrincipalId);

    var emptyGuidRow = Assert.Single(
      rows, x => x.TargetType == AuthorizationChangeLogTargetTypes.ServiceAccountCredential);
    Assert.NotNull(emptyGuidRow);
    Assert.Null(emptyGuidRow.ActorPrincipalId);
    Assert.Null(emptyGuidRow.TargetId);

    var malformedRow = Assert.Single(rows, x => x.TargetType == AuthorizationChangeLogTargetTypes.DeviceGroup);
    Assert.NotNull(malformedRow);
    Assert.Null(malformedRow.ActorPrincipalId);
    Assert.Null(malformedRow.TargetId);

    // Confirm the columns are now uuid (not varchar) at the database level.
    var actorColumnType = await verifyDb.Database
      .SqlQueryRaw<string>(
        """
        SELECT data_type::text AS "Value"
        FROM information_schema.columns
        WHERE table_name = 'AuthorizationChangeLogs'
          AND column_name = 'ActorPrincipalId'
        """)
      .SingleOrDefaultAsync(TestContext.Current.CancellationToken);

    var targetColumnType = await verifyDb.Database
      .SqlQueryRaw<string>(
        """
        SELECT data_type::text AS "Value"
        FROM information_schema.columns
        WHERE table_name = 'AuthorizationChangeLogs'
          AND column_name = 'TargetId'
        """)
      .SingleOrDefaultAsync(TestContext.Current.CancellationToken);

    Assert.Equal("uuid", actorColumnType);
    Assert.Equal("uuid", targetColumnType);
  }
}
