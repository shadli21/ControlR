using ControlR.Web.Server.Data;
using ControlR.Web.Server.Data.Entities;
using ControlR.Web.Server.Services.ServiceAccounts;
using ControlR.Web.Server.Tests.Helpers;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace ControlR.Web.Server.Tests.V1;

public class ServiceAccountManagerTests(ITestOutputHelper testOutput)
{
  [Fact]
  public async Task DeleteForTenant_RemovesPermissionAssignments()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();

    using var managerScope = testApp.CreateScope();
    var manager = managerScope.ServiceProvider.GetRequiredService<IServiceAccountManager>();

    var createResult = await manager.CreateForTenant(
      "Tenant SA", null, tenant.Id, Guid.NewGuid(), TestContext.Current.CancellationToken);
    Assert.True(createResult.IsSuccess);

    var accountId = createResult.Value.ServiceAccount.Id;

    using (var seedScope = testApp.CreateScope())
    {
      await using var db = seedScope.ServiceProvider.GetRequiredService<AppDb>();
      db.PermissionAssignments.Add(new PermissionAssignment
      {
        PrincipalKind = PermissionPrincipalKind.ServiceAccount,
        PrincipalId = accountId,
        PermissionName = PermissionNames.DeviceRead,
        Effect = PermissionEffect.Allow,
        ScopeKind = PermissionScopeKind.Tenant,
        ScopeId = tenant.Id,
        OwningTenantId = tenant.Id,
        IsEnabled = true
      });
      await db.SaveChangesAsync(TestContext.Current.CancellationToken);
    }

    var deleteResult = await manager.DeleteForTenant(
      accountId, tenant.Id, Guid.NewGuid(), TestContext.Current.CancellationToken);
    Assert.True(deleteResult.IsSuccess);

    using (var verifyScope = testApp.CreateScope())
    {
      await using var db = verifyScope.ServiceProvider.GetRequiredService<AppDb>();
      var hasOrphanedAssignments = await db.PermissionAssignments
        .IgnoreQueryFilters()
        .AnyAsync(x => x.PrincipalKind == PermissionPrincipalKind.ServiceAccount &&
                       x.PrincipalId == accountId,
          TestContext.Current.CancellationToken);

      Assert.False(hasOrphanedAssignments);
    }
  }

  [Fact]
  public async Task ServiceAccountLifecycle_Full_Succeeds()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(testOutput);
    using var scope = testApp.CreateScope();
    var services = scope.ServiceProvider;
    var manager = services.GetRequiredService<IServiceAccountManager>();

    var createResult = await manager.CreateForServer(
      "Lifecycle SA",
      "Created by test",
      TestContext.Current.CancellationToken);
    Assert.True(createResult.IsSuccess);

    var accountId = createResult.Value.ServiceAccount.Id;
    var credentialId = createResult.Value.ServiceAccount.Credentials[0].Id;
    var apiKey = createResult.Value.PlainTextSecretKey;

    var validateResult = await manager.ValidateCredential(apiKey, TestContext.Current.CancellationToken);
    Assert.True(validateResult.IsSuccess);
    Assert.Equal(accountId, validateResult.Value.ServiceAccount.Id);

    var addCredResult = await manager.AddCredential(
      accountId,
      "Secondary key",
      Guid.NewGuid(),
      TestContext.Current.CancellationToken);
    Assert.True(addCredResult.IsSuccess);
    var secondApiKey = addCredResult.Value.PlainTextSecretKey;

    await manager.RevokeCredential(accountId, credentialId, Guid.NewGuid(), TestContext.Current.CancellationToken);

    var shouldFail = await manager.ValidateCredential(apiKey, TestContext.Current.CancellationToken);
    Assert.False(shouldFail.IsSuccess);

    var shouldPass = await manager.ValidateCredential(secondApiKey, TestContext.Current.CancellationToken);
    Assert.True(shouldPass.IsSuccess);

    // Authorization isn't exercised here — any valid principal ID is acceptable.
    await manager.Delete(accountId, Guid.NewGuid(), TestContext.Current.CancellationToken);

    var allAccounts = await manager.GetAllForServer(TestContext.Current.CancellationToken);
    Assert.DoesNotContain(allAccounts, a => a.Id == accountId);
  }
}
