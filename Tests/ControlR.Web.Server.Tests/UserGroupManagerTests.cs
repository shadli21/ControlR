using ControlR.Web.Server.Primitives;
using ControlR.Web.Server.Services.UserGroups;
using ControlR.Web.Server.Tests.Helpers;
using Microsoft.Extensions.DependencyInjection;

namespace ControlR.Web.Server.Tests;

public class UserGroupManagerTests(ITestOutputHelper testOutput)
{
  [Fact]
  public async Task Update_WithNameConflictingWithOtherGroup_ReturnsConflict()
  {
    // Real Postgres is required: the EF in-memory provider does not enforce the unique
    // (TenantId, Name) index, which is what turns this conflict into a 500 in production.
    await using var testApp = await TestAppBuilder.CreateTestApp(testOutput, useInMemoryDatabase: false);
    var tenant = await testApp.App.Services.CreateTestTenant();

    using var scope = testApp.CreateScope();
    var manager = scope.ServiceProvider.GetRequiredService<IUserGroupManager>();
    var actorId = Guid.NewGuid();

    var first = await manager.Create("Group A", null, tenant.Id, actorId, TestContext.Current.CancellationToken);
    Assert.True(first.IsSuccess);

    var second = await manager.Create("Group B", null, tenant.Id, actorId, TestContext.Current.CancellationToken);
    Assert.True(second.IsSuccess);

    var result = await manager.Update(
      second.Value.Id, "Group A", null, tenant.Id, actorId, TestContext.Current.CancellationToken);

    Assert.False(result.IsSuccess);
    Assert.Equal(HttpResultErrorCode.Conflict, result.ErrorCode);
  }

  [Fact]
  public async Task Update_WithOwnNameUnchanged_Succeeds()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();

    using var scope = testApp.CreateScope();
    var manager = scope.ServiceProvider.GetRequiredService<IUserGroupManager>();
    var actorId = Guid.NewGuid();

    var created = await manager.Create("Group A", null, tenant.Id, actorId, TestContext.Current.CancellationToken);
    Assert.True(created.IsSuccess);

    var result = await manager.Update(
      created.Value.Id, "Group A", "Updated description", tenant.Id, actorId, TestContext.Current.CancellationToken);

    Assert.True(result.IsSuccess);
  }
}
