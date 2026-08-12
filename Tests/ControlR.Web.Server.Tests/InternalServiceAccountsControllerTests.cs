using ControlR.Web.Server.Api.Internal;
using ControlR.Web.Server.Data;
using ControlR.Web.Server.Services.ServiceAccounts;
using ControlR.Web.Server.Tests.Helpers;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace ControlR.Web.Server.Tests;

public class InternalServiceAccountsControllerTests(ITestOutputHelper testOutput)
{
  [Fact]
  public async Task AddCredentialForTenant_DisabledAccount_Returns403()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(testOutput);
    using var scope = testApp.CreateScope();
    var (controller, tenant, _) = await scope.CreateControllerWithTestData<ServiceAccountsController>(
      userEmail: "tenant-disabled-test@t.local");

    Guid accountId;
    using (var innerScope = testApp.CreateScope())
    {
      var manager = innerScope.ServiceProvider.GetRequiredService<IServiceAccountManager>();
      await using var appDb = innerScope.ServiceProvider.GetRequiredService<AppDb>();

      var saResult = await manager.CreateForTenant(
        "Disabled Tenant SA", null, tenant.Id, Guid.NewGuid(), TestContext.Current.CancellationToken);
      Assert.True(saResult.IsSuccess);
      accountId = saResult.Value.Id;

      var account = await appDb.ServiceAccounts
        .FirstOrDefaultAsync(x => x.Id == accountId, TestContext.Current.CancellationToken);
      Assert.NotNull(account);
      account.IsEnabled = false;
      await appDb.SaveChangesAsync(TestContext.Current.CancellationToken);
    }

    var result = await controller.AddCredential(
      accountId,
      new InternalDtos.CreateTenantServiceAccountCredentialRequestDto("New Credential", null),
      TestContext.Current.CancellationToken);

    var forbidden = Assert.IsType<ObjectResult>(result.Result);
    Assert.Equal(403, forbidden.StatusCode);
  }
}
