using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Data;
using ControlR.Web.Server.Data.Entities;
using ControlR.Web.Server.Primitives;
using ControlR.Web.Server.Services.UserGroups;
using ControlR.Web.Server.Tests.Helpers;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace ControlR.Web.Server.Tests;

public class UserGroupManagerTenantIsolationTests(ITestOutputHelper testOutput)
{
  private readonly ITestOutputHelper _testOutputHelper = testOutput;

  [Fact]
  public async Task AddMembers_CrossTenantUser_ReturnsBadRequest()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutputHelper);
    using var scope = testApp.App.Services.CreateScope();
    var manager = scope.ServiceProvider.GetRequiredService<IUserGroupManager>();
    await using var db = scope.ServiceProvider.GetRequiredService<AppDb>();

    var tenantA = await testApp.Services.CreateTestTenant("Tenant A");
    var tenantB = await testApp.Services.CreateTestTenant("Tenant B");
    var actor = await testApp.Services.CreateTestUser(tenantA.Id, $"a-{Guid.NewGuid():N}@t.local");
    var userB = await testApp.Services.CreateTestUser(tenantB.Id, $"b-{Guid.NewGuid():N}@t.local");

    var groupA = await CreateGroup(db, tenantA.Id, "Group A");

    var result = await manager.AddMembers(
      groupA.Id,
      [userB.Id],
      tenantA.Id,
      new PrincipalDescriptor(PrincipalType.User, actor.Id, tenantA.Id, "test"),
      TestContext.Current.CancellationToken);

    Assert.False(result.IsSuccess);
    Assert.Equal(HttpResultErrorCode.BadRequest, result.ErrorCode);

    var memberExists = await db.UserGroupMembers.AnyAsync(
      x => x.UserGroupId == groupA.Id && x.UserId == userB.Id,
      TestContext.Current.CancellationToken);
    Assert.False(memberExists, "Cross-tenant user must not be added to a group.");
  }

  [Fact]
  public async Task Delete_CrossTenantUserGroup_ReturnsNotFound_AndDoesNotRemove()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutputHelper);
    using var scope = testApp.App.Services.CreateScope();
    var manager = scope.ServiceProvider.GetRequiredService<IUserGroupManager>();
    await using var db = scope.ServiceProvider.GetRequiredService<AppDb>();

    var tenantA = await testApp.Services.CreateTestTenant("Tenant A");
    var tenantB = await testApp.Services.CreateTestTenant("Tenant B");
    var actor = await testApp.Services.CreateTestUser(tenantA.Id, $"a-{Guid.NewGuid():N}@t.local");

    var groupB = await CreateGroup(db, tenantB.Id, "Group B");

    var result = await manager.Delete(
      groupB.Id,
      tenantA.Id,
      new PrincipalDescriptor(PrincipalType.User, actor.Id, tenantA.Id, "test"),
      TestContext.Current.CancellationToken);

    Assert.False(result.IsSuccess);
    Assert.Equal(HttpResultErrorCode.NotFound, result.ErrorCode);

    var stillExists = await db.UserGroups.AnyAsync(
      x => x.Id == groupB.Id,
      TestContext.Current.CancellationToken);
    Assert.True(stillExists, "Cross-tenant user group must not be deleted.");
  }

  [Fact]
  public async Task GetAll_ExcludesOtherTenantUserGroups()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutputHelper);
    using var scope = testApp.App.Services.CreateScope();
    var manager = scope.ServiceProvider.GetRequiredService<IUserGroupManager>();
    await using var db = scope.ServiceProvider.GetRequiredService<AppDb>();

    var tenantA = await testApp.Services.CreateTestTenant("Tenant A");
    var tenantB = await testApp.Services.CreateTestTenant("Tenant B");
    var actor = await testApp.Services.CreateTestUser(tenantA.Id, $"a-{Guid.NewGuid():N}@t.local");

    var groupA = await CreateGroup(db, tenantA.Id, "Group A");
    await CreateGroup(db, tenantB.Id, "Group B");

    var all = await manager.GetAll(tenantA.Id, TestContext.Current.CancellationToken);

    Assert.Contains(all, g => g.Id == groupA.Id);
    Assert.DoesNotContain(all, g => g.Name == "Group B");
  }

  [Fact]
  public async Task Get_CrossTenantUserGroup_ReturnsNotFound()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutputHelper);
    using var scope = testApp.App.Services.CreateScope();
    var manager = scope.ServiceProvider.GetRequiredService<IUserGroupManager>();
    await using var db = scope.ServiceProvider.GetRequiredService<AppDb>();

    var tenantA = await testApp.Services.CreateTestTenant("Tenant A");
    var tenantB = await testApp.Services.CreateTestTenant("Tenant B");
    var actor = await testApp.Services.CreateTestUser(tenantA.Id, $"a-{Guid.NewGuid():N}@t.local");

    var groupB = await CreateGroup(db, tenantB.Id, "Group B");

    var result = await manager.Get(groupB.Id, tenantA.Id, TestContext.Current.CancellationToken);

    Assert.False(result.IsSuccess);
    Assert.Equal(HttpResultErrorCode.NotFound, result.ErrorCode);
  }

  [Fact]
  public async Task Update_CrossTenantUserGroup_ReturnsNotFound()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutputHelper);
    using var scope = testApp.App.Services.CreateScope();
    var manager = scope.ServiceProvider.GetRequiredService<IUserGroupManager>();
    await using var db = scope.ServiceProvider.GetRequiredService<AppDb>();

    var tenantA = await testApp.Services.CreateTestTenant("Tenant A");
    var tenantB = await testApp.Services.CreateTestTenant("Tenant B");
    var actor = await testApp.Services.CreateTestUser(tenantA.Id, $"a-{Guid.NewGuid():N}@t.local");

    var groupB = await CreateGroup(db, tenantB.Id, "Group B");

    var result = await manager.Update(
      groupB.Id,
      "Renamed",
      null,
      tenantA.Id,
      new PrincipalDescriptor(PrincipalType.User, actor.Id, tenantA.Id, "test"),
      TestContext.Current.CancellationToken);

    Assert.False(result.IsSuccess);
    Assert.Equal(HttpResultErrorCode.NotFound, result.ErrorCode);
  }

  private static async Task<UserGroup> CreateGroup(
    AppDb db,
    Guid tenantId,
    string name)
  {
    var group = new UserGroup
    {
      Name = name,
      TenantId = tenantId,
      Members = []
    };
    db.UserGroups.Add(group);
    await db.SaveChangesAsync(TestContext.Current.CancellationToken);
    return group;
  }
}
