using ControlR.Web.Server.Data;
using ControlR.Web.Server.Data.Configuration;
using ControlR.Web.Server.Data.Entities;
using ControlR.Web.Server.Extensions.Database;
using ControlR.Web.Server.Tests.Helpers;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace ControlR.Web.Server.Tests;

public class AppDbExtensionsTests(ITestOutputHelper testOutput)
{
  private readonly ITestOutputHelper _testOutput = testOutput;

  [Fact]
  public async Task AddOrUpdate_WhenTrackedEntityMatches_UpdatesTrackedEntityWithoutDuplicate()
  {
    var cancellationToken = TestContext.Current.CancellationToken;
    await using var testApp = await TestAppBuilder.CreateTestApp(
      _testOutput,
      testDatabaseName: $"{Guid.NewGuid()}");

    var tenant = await testApp.Services.CreateTestTenant();

    await using var scope = testApp.Services.CreateAsyncScope();
    var db = scope.ServiceProvider.GetRequiredService<AppDb>();

    var existingSetting = new TenantSetting
    {
      Name = "instance-id",
      TenantId = tenant.Id,
      Value = "alpha"
    };

    db.TenantSettings.Add(existingSetting);
    await db.SaveChangesAsync(cancellationToken);

    await db.AddOrUpdate(
      new TenantSetting
      {
        Name = "instance-id",
        TenantId = tenant.Id,
        Value = "beta"
      },
      x => x.Name == "instance-id" && x.TenantId == tenant.Id,
      cancellationToken);

    Assert.Equal("beta", existingSetting.Value);

    var storedSettings = await db.TenantSettings
      .AsNoTracking()
      .Where(x => x.TenantId == tenant.Id && x.Name == "instance-id")
      .ToListAsync(cancellationToken);

    var storedSetting = Assert.Single(storedSettings);
    Assert.Equal(existingSetting.Id, storedSetting.Id);
    Assert.Equal("beta", storedSetting.Value);
  }

  [Fact]
  public async Task AddOrUpdate_WhenUpdating_IgnoresStoreGeneratedColumns()
  {
    var cancellationToken = TestContext.Current.CancellationToken;
    await using var testApp = await TestAppBuilder.CreateTestApp(
      _testOutput,
      testDatabaseName: $"{Guid.NewGuid()}",
      useInMemoryDatabase: false);

    var tenant = await testApp.Services.CreateTestTenant();
    var requestedUpdateCreatedAt = DateTimeOffset.Parse("2002-03-04T05:06:07+00:00");

    await using (var arrangeScope = testApp.Services.CreateAsyncScope())
    {
      var db = arrangeScope.ServiceProvider.GetRequiredService<AppDb>();

      var entity = new TenantSetting
      {
        Name = "instance-id",
        TenantId = tenant.Id,
        Value = "alpha"
      };

      db.TenantSettings.Add(entity);
      await db.SaveChangesAsync(cancellationToken);
    }

    Guid originalId;
    DateTimeOffset storedCreatedAt;
    await using (var firstAssertScope = testApp.Services.CreateAsyncScope())
    {
      var db = firstAssertScope.ServiceProvider.GetRequiredService<AppDb>();
      var storedSetting = await db.TenantSettings
        .AsNoTracking()
        .SingleAsync(x => x.TenantId == tenant.Id && x.Name == "instance-id", cancellationToken);

      Assert.NotEqual(Guid.Empty, storedSetting.Id);
      originalId = storedSetting.Id;
      storedCreatedAt = storedSetting.CreatedAt;
    }

    await using (var updateScope = testApp.Services.CreateAsyncScope())
    {
      var db = updateScope.ServiceProvider.GetRequiredService<AppDb>();

      await db.AddOrUpdate(
        new TenantSetting
        {
          Name = "instance-id",
          TenantId = tenant.Id,
          Value = "beta",
          CreatedAt = requestedUpdateCreatedAt
        },
        x => x.Name == "instance-id" && x.TenantId == tenant.Id,
        cancellationToken);
    }

    await using var finalAssertScope = testApp.Services.CreateAsyncScope();
    var assertDb = finalAssertScope.ServiceProvider.GetRequiredService<AppDb>();
    var updatedSetting = await assertDb.TenantSettings
      .AsNoTracking()
      .SingleAsync(x => x.TenantId == tenant.Id && x.Name == "instance-id", cancellationToken);

    Assert.Equal(originalId, updatedSetting.Id);
    Assert.Equal("beta", updatedSetting.Value);
    Assert.Equal(storedCreatedAt, updatedSetting.CreatedAt);
    Assert.NotEqual(requestedUpdateCreatedAt, updatedSetting.CreatedAt);
  }

  [Fact]
  public async Task AddOrUpdate_WhenUpdating_PreservesOriginalPrimaryKey()
  {
    var cancellationToken = TestContext.Current.CancellationToken;
    await using var testApp = await TestAppBuilder.CreateTestApp(
      _testOutput,
      testDatabaseName: $"{Guid.NewGuid()}");

    var tenant = await testApp.Services.CreateTestTenant();

    await using var scope = testApp.Services.CreateAsyncScope();
    var db = scope.ServiceProvider.GetRequiredService<AppDb>();

    var entity = new TenantSetting
    {
      Name = "instance-id",
      TenantId = tenant.Id,
      Value = "alpha"
    };

    db.TenantSettings.Add(entity);
    await db.SaveChangesAsync(cancellationToken);
    var originalId = entity.Id;

    await db.AddOrUpdate(
      new TenantSetting
      {
        Name = "instance-id",
        TenantId = tenant.Id,
        Value = "beta"
      },
      x => x.Name == "instance-id" && x.TenantId == tenant.Id,
      cancellationToken);

    var storedSettings = await db.TenantSettings
      .AsNoTracking()
      .Where(x => x.TenantId == tenant.Id && x.Name == "instance-id")
      .ToListAsync(cancellationToken);

    var storedSetting = Assert.Single(storedSettings);
    Assert.Equal(originalId, storedSetting.Id);
    Assert.Equal("beta", storedSetting.Value);
  }

  [Fact]
  public async Task AddOrUpdate_WithInMemoryProvider_UpdatesExistingRow()
  {
    var cancellationToken = TestContext.Current.CancellationToken;
    await using var testApp = await TestAppBuilder.CreateTestApp(
      _testOutput,
      testDatabaseName: $"{Guid.NewGuid()}");

    var tenant = await testApp.Services.CreateTestTenant();

    await using var scope = testApp.Services.CreateAsyncScope();
    var db = scope.ServiceProvider.GetRequiredService<AppDb>();

    await db.AddOrUpdate(
      new TenantSetting
      {
        Name = "instance-id",
        TenantId = tenant.Id,
        Value = "alpha"
      },
      x => x.Name == "instance-id" && x.TenantId == tenant.Id,
      cancellationToken);

    await db.AddOrUpdate(
      new TenantSetting
      {
        Name = "instance-id",
        TenantId = tenant.Id,
        Value = "beta"
      },
      x => x.Name == "instance-id" && x.TenantId == tenant.Id,
      cancellationToken);

    var storedSettings = await db.TenantSettings
      .AsNoTracking()
      .Where(x => x.TenantId == tenant.Id && x.Name == "instance-id")
      .ToListAsync(cancellationToken);

    var storedSetting = Assert.Single(storedSettings);
    Assert.Equal("beta", storedSetting.Value);
  }

  [Fact]
  public async Task AddOrUpdate_WithNaturalKey_UsesAlternateUniqueIndex()
  {
    var cancellationToken = TestContext.Current.CancellationToken;
    await using var testApp = await TestAppBuilder.CreateTestApp(
      _testOutput,
      testDatabaseName: $"{Guid.NewGuid()}",
      useInMemoryDatabase: false);

    var tenant = await testApp.Services.CreateTestTenant();

    Guid originalId;
    await using (var arrangeScope = testApp.Services.CreateAsyncScope())
    {
      var db = arrangeScope.ServiceProvider.GetRequiredService<AppDb>();

      var entity = new TenantSetting
      {
        Name = "instance-id",
        TenantId = tenant.Id,
        Value = "alpha"
      };

      db.TenantSettings.Add(entity);
      await db.SaveChangesAsync(cancellationToken);
      originalId = entity.Id;
    }

    await using (var updateScope = testApp.Services.CreateAsyncScope())
    {
      var db = updateScope.ServiceProvider.GetRequiredService<AppDb>();

      await db.AddOrUpdate(
        new TenantSetting
        {
          Name = "instance-id",
          TenantId = tenant.Id,
          Value = "beta"
        },
        x => x.Name == "instance-id" && x.TenantId == tenant.Id,
        cancellationToken);
    }

    await using var assertScope = testApp.Services.CreateAsyncScope();
    var assertDb = assertScope.ServiceProvider.GetRequiredService<AppDb>();
    var storedSettings = await assertDb.TenantSettings
      .AsNoTracking()
      .Where(x => x.TenantId == tenant.Id && x.Name == "instance-id")
      .ToListAsync(cancellationToken);

    var storedSetting = Assert.Single(storedSettings);
    Assert.Equal(originalId, storedSetting.Id);
    Assert.Equal("beta", storedSetting.Value);
  }

  [Fact]
  public async Task AddOrUpdate_WithPrimaryKey_UpdatesExistingRow()
  {
    var cancellationToken = TestContext.Current.CancellationToken;
    await using var testApp = await TestAppBuilder.CreateTestApp(
      _testOutput,
      testDatabaseName: $"{Guid.NewGuid()}",
      useInMemoryDatabase: false);

    var tenant = await testApp.Services.CreateTestTenant();

    Guid settingId;
    await using (var arrangeScope = testApp.Services.CreateAsyncScope())
    {
      var db = arrangeScope.ServiceProvider.GetRequiredService<AppDb>();

      var entity = new TenantSetting
      {
        Name = "append-instance-id",
        TenantId = tenant.Id,
        Value = bool.TrueString
      };

      db.TenantSettings.Add(entity);
      await db.SaveChangesAsync(cancellationToken);
      settingId = entity.Id;
    }

    await using (var updateScope = testApp.Services.CreateAsyncScope())
    {
      var db = updateScope.ServiceProvider.GetRequiredService<AppDb>();

      await db.AddOrUpdate(
        new TenantSetting
        {
          Name = "append-instance-id",
          TenantId = tenant.Id,
          Value = bool.FalseString
        },
        x => x.Id == settingId,
        cancellationToken);
    }

    await using var assertScope = testApp.Services.CreateAsyncScope();
    var assertDb = assertScope.ServiceProvider.GetRequiredService<AppDb>();
    var storedSetting = await assertDb.TenantSettings
      .AsNoTracking()
      .SingleAsync(x => x.Id == settingId, cancellationToken);

    Assert.Equal(bool.FalseString, storedSetting.Value);
    Assert.NotEqual(default, storedSetting.CreatedAt);
  }

  [Fact]
  public async Task AddOrUpdate_WithUserClaimsFilter_UpdatesExistingRowOwnedByAnotherUser()
  {
    var cancellationToken = TestContext.Current.CancellationToken;
    await using var testApp = await TestAppBuilder.CreateTestApp(
      _testOutput,
      testDatabaseName: $"{Guid.NewGuid()}",
      useInMemoryDatabase: false);

    var tenant = await testApp.Services.CreateTestTenant();
    var creator = await testApp.Services.CreateTestUser(tenant.Id, email: "creator@t.local");
    var guest = await testApp.Services.CreateTestUser(tenant.Id, email: "guest@t.local");

    string connectionString;
    await using (var setupScope = testApp.Services.CreateAsyncScope())
    {
      var setupDb = setupScope.ServiceProvider.GetRequiredService<AppDb>();
      connectionString = setupDb.Database.GetDbConnection().ConnectionString;

      // The guest already has this preference. Seeded through an unfiltered context.
      setupDb.UserPreferences.Add(new UserPreference
      {
        Name = "display-name",
        UserId = guest.Id,
        Value = "original"
      });
      await setupDb.SaveChangesAsync(cancellationToken);
    }

    // A context scoped to the creator's claims. Its UserPreference query filter only
    // sees the creator's own preferences, so the guest's row is invisible to queries.
    await using var creatorDb = CreateClaimsScopedAppDb(connectionString, tenant.Id, creator.Id);

    // Upserting the guest's preference must update the existing row. Before the fix the
    // claims filter hides the row from both the existence check and the conflict re-check,
    // so this attempted a duplicate insert and threw DbUpdateException (23505).
    var saved = await creatorDb.AddOrUpdate(
      new UserPreference
      {
        Name = "display-name",
        UserId = guest.Id,
        Value = "updated"
      },
      x => x.Name == "display-name" && x.UserId == guest.Id,
      cancellationToken);

    Assert.Equal(guest.Id, saved.UserId);
    Assert.Equal("updated", saved.Value);

    await using var assertScope = testApp.Services.CreateAsyncScope();
    var assertDb = assertScope.ServiceProvider.GetRequiredService<AppDb>();
    var stored = await assertDb.UserPreferences
      .IgnoreQueryFilters()
      .Where(x => x.UserId == guest.Id && x.Name == "display-name")
      .ToListAsync(cancellationToken);

    var storedPreference = Assert.Single(stored);
    Assert.Equal("updated", storedPreference.Value);
  }

  [Fact]
  public async Task AddOrUpdate_WithUserClaimsFilter_ConcurrentUpsertsForAnotherUser_AllSucceed()
  {
    var cancellationToken = TestContext.Current.CancellationToken;
    await using var testApp = await TestAppBuilder.CreateTestApp(
      _testOutput,
      testDatabaseName: $"{Guid.NewGuid()}",
      useInMemoryDatabase: false);

    var tenant = await testApp.Services.CreateTestTenant();
    var creator = await testApp.Services.CreateTestUser(tenant.Id, email: "creator@t.local");
    var guest = await testApp.Services.CreateTestUser(tenant.Id, email: "guest@t.local");

    string connectionString;
    await using (var setupScope = testApp.Services.CreateAsyncScope())
    {
      var setupDb = setupScope.ServiceProvider.GetRequiredService<AppDb>();
      connectionString = setupDb.Database.GetDbConnection().ConnectionString;
    }

    // The claims filter blinds each context's existence check to the guest's row, so every
    // context attempts an insert. Exactly one wins; the rest hit the unique index and must
    // recover through the conflict path rather than throwing.
    var tasks = Enumerable.Range(0, 5).Select(index => Task.Run(async () =>
    {
      await using var db = CreateClaimsScopedAppDb(connectionString, tenant.Id, creator.Id);
      await db.AddOrUpdate(
        new UserPreference
        {
          Name = "display-name",
          UserId = guest.Id,
          Value = $"value-{index}"
        },
        x => x.Name == "display-name" && x.UserId == guest.Id,
        TestContext.Current.CancellationToken);
    }));

    await Task.WhenAll(tasks);

    await using var assertScope = testApp.Services.CreateAsyncScope();
    var assertDb = assertScope.ServiceProvider.GetRequiredService<AppDb>();
    var stored = await assertDb.UserPreferences
      .IgnoreQueryFilters()
      .Where(x => x.UserId == guest.Id && x.Name == "display-name")
      .ToListAsync(cancellationToken);

    var storedPreference = Assert.Single(stored);
    Assert.StartsWith("value-", storedPreference.Value);
  }

  private static AppDb CreateClaimsScopedAppDb(string connectionString, Guid tenantId, Guid userId)
  {
    var optionsBuilder = new DbContextOptionsBuilder<AppDb>();
    optionsBuilder.UseNpgsql(connectionString);

    var infrastructure = (IDbContextOptionsBuilderInfrastructure)optionsBuilder;
    infrastructure.AddOrUpdateExtension(new ClaimsDbContextOptionsExtension(new ClaimsDbContextOptions
    {
      TenantId = tenantId,
      UserId = userId
    }));

    return new AppDb(optionsBuilder.Options);
  }
}
