using ControlR.Libraries.Shared.Constants;
using ControlR.Libraries.Shared.Dtos.ServerApi;
using ControlR.Libraries.Shared.Helpers;
using ControlR.Web.Server.Api;
using ControlR.Web.Server.Data;
using ControlR.Web.Server.Data.Entities;
using ControlR.Web.Server.Services.Users;
using ControlR.Web.Server.Tests.Helpers;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Npgsql;
using Xunit.Abstractions;

namespace ControlR.Web.Server.Tests;

public class InviteAcceptanceForeignKeyTests(ITestOutputHelper testOutput)
{
  [Fact]
  public async Task AcceptInvite_WhenTenantRowMissing_UserPreferenceInsertThrowsForeignKeyViolation()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(testOutput);
    using var scope = testApp.CreateScope();

    var userCreator = scope.ServiceProvider.GetRequiredService<IUserCreator>();
    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<AppUser>>();
    var logger = scope.ServiceProvider.GetRequiredService<ILogger<InvitesController>>();

    var adminResult = await userCreator.CreateUser("admin@example.com", "Password123!", returnUrl: null);
    Assert.True(adminResult.Succeeded);
    var adminUser = adminResult.User!;
    var tenantAId = adminUser.TenantId;

    var user2Result = await userCreator.CreateUser("user2@example.com", "Password123!", returnUrl: null);
    Assert.True(user2Result.Succeeded);
    var user2 = user2Result.User!;
    var tenantBId = user2.TenantId;

    var dbFactory = scope.ServiceProvider.GetRequiredService<IDbContextFactory<AppDb>>();

    await using (var setupDb = await dbFactory.CreateDbContextAsync())
    {
      setupDb.UserPreferences.Add(new UserPreference
      {
        Name = UserPreferenceNames.UserDisplayName,
        Value = "Admin",
        UserId = adminUser.Id,
        TenantId = tenantAId
      });

      setupDb.UserPreferences.Add(new UserPreference
      {
        Name = UserPreferenceNames.UserDisplayName,
        Value = "User2",
        UserId = user2.Id,
        TenantId = tenantBId
      });

      var activationCode = RandomGenerator.GenerateString(64);
      setupDb.TenantInvites.Add(new TenantInvite
      {
        ActivationCode = activationCode,
        InviteeEmail = "user2@example.com",
        TenantId = tenantAId
      });

      await setupDb.SaveChangesAsync();

      var controller = new InvitesController();
      var acceptResult = await controller.AcceptInvite(
        new AcceptInvitationRequestDto(
          ActivationCode: activationCode,
          Email: "user2@example.com",
          Password: "Password123!"),
        setupDb,
        userManager,
        logger);

      Assert.True(acceptResult.Value?.IsSuccessful);
    }

    await using (var verifyDb = await dbFactory.CreateDbContextAsync())
    {
      var movedUser = await verifyDb.Users.AsNoTracking().FirstAsync(x => x.Id == user2.Id);
      Assert.Equal(tenantAId, movedUser.TenantId);
    }

    var pgHost = testApp.App.Configuration.GetValue<string>("POSTGRES_HOST");
    var pgUser = testApp.App.Configuration.GetValue<string>("POSTGRES_USER");
    var pgPass = testApp.App.Configuration.GetValue<string>("POSTGRES_PASSWORD");
    var pgDb = testApp.App.Configuration.GetValue<string>("POSTGRES_DB");
    var pgPort = testApp.App.Configuration.GetValue<int>("POSTGRES_PORT");

    var csb = new NpgsqlConnectionStringBuilder
    {
      Host = pgHost,
      Port = pgPort,
      Username = pgUser,
      Password = pgPass,
      Database = pgDb,
      Pooling = false
    };

    await using (var adminConnection = new NpgsqlConnection(csb.ConnectionString))
    {
      await adminConnection.OpenAsync();

      await using var cmd = adminConnection.CreateCommand();
      cmd.CommandText = "SET session_replication_role = replica;" +
        "DELETE FROM \"Tenants\" WHERE \"Id\" = @tenantId;" +
        "SET session_replication_role = origin;";
      _ = cmd.Parameters.AddWithValue("tenantId", tenantAId);

      await cmd.ExecuteNonQueryAsync();
    }

    await using (var brokenDb = await dbFactory.CreateDbContextAsync())
    {
      brokenDb.UserPreferences.Add(new UserPreference
      {
        Name = UserPreferenceNames.ThemeMode,
        Value = "Dark",
        UserId = user2.Id,
        TenantId = tenantAId
      });

      var ex = await Assert.ThrowsAsync<DbUpdateException>(() => brokenDb.SaveChangesAsync());
      var pgEx = ex.InnerException as PostgresException;

      Assert.NotNull(pgEx);
      Assert.Equal("23503", pgEx!.SqlState);
      Assert.Equal("FK_UserPreferences_Tenants_TenantId", pgEx.ConstraintName);

      testOutput.WriteLine($"SqlState: {pgEx.SqlState}");
      testOutput.WriteLine($"Constraint: {pgEx.ConstraintName}");
      testOutput.WriteLine($"Message: {pgEx.MessageText}");
    }
  }
}
