using ControlR.Web.Server.Data;
using ControlR.Web.Server.Data.Entities;
using ControlR.Web.Server.Primitives;
using ControlR.Web.Server.Services.DeviceGroups;
using ControlR.Web.Server.Tests.Helpers;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace ControlR.Web.Server.Tests;

public class DeviceGroupManagerTenantIsolationTests(ITestOutputHelper testOutput)
{
  private readonly ITestOutputHelper _testOutputHelper = testOutput;

  [Fact]
  public async Task AddMembers_CrossTenantDevice_ReturnsBadRequest()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutputHelper);
    using var scope = testApp.App.Services.CreateScope();
    var manager = scope.ServiceProvider.GetRequiredService<IDeviceGroupManager>();
    await using var db = scope.ServiceProvider.GetRequiredService<AppDb>();

    var tenantA = await testApp.Services.CreateTestTenant("Tenant A");
    var tenantB = await testApp.Services.CreateTestTenant("Tenant B");
    var actor = await testApp.Services.CreateTestUser(tenantA.Id, $"a-{Guid.NewGuid():N}@t.local");

    var groupA = await CreateGroup(db, tenantA.Id, "Group A", actor.Id);
    var deviceB = await testApp.Services.CreateTestDevice(tenantB.Id);

    var result = await manager.AddMembers(
      groupA.Id,
      [deviceB.Id],
      tenantA.Id,
      actor.Id,
      TestContext.Current.CancellationToken);

    Assert.False(result.IsSuccess);
    Assert.Equal(HttpResultErrorCode.BadRequest, result.ErrorCode);

    var memberExists = await db.DeviceGroupMembers.AnyAsync(
      x => x.DeviceGroupId == groupA.Id && x.DeviceId == deviceB.Id,
      TestContext.Current.CancellationToken);
    Assert.False(memberExists, "Cross-tenant device must not be added to a group.");
  }

  [Fact]
  public async Task Delete_CrossTenantDeviceGroup_ReturnsNotFound_AndDoesNotRemove()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutputHelper);
    using var scope = testApp.App.Services.CreateScope();
    var manager = scope.ServiceProvider.GetRequiredService<IDeviceGroupManager>();
    await using var db = scope.ServiceProvider.GetRequiredService<AppDb>();

    var tenantA = await testApp.Services.CreateTestTenant("Tenant A");
    var tenantB = await testApp.Services.CreateTestTenant("Tenant B");
    var actor = await testApp.Services.CreateTestUser(tenantA.Id, $"a-{Guid.NewGuid():N}@t.local");

    var groupB = await CreateGroup(db, tenantB.Id, "Group B", actor.Id);

    var result = await manager.Delete(
      groupB.Id,
      tenantA.Id,
      actor.Id,
      TestContext.Current.CancellationToken);

    Assert.False(result.IsSuccess);
    Assert.Equal(HttpResultErrorCode.NotFound, result.ErrorCode);

    var stillExists = await db.DeviceGroups.AnyAsync(
      x => x.Id == groupB.Id,
      TestContext.Current.CancellationToken);
    Assert.True(stillExists, "Cross-tenant device group must not be deleted.");
  }

  [Fact]
  public async Task GetAll_ExcludesOtherTenantDeviceGroups()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutputHelper);
    using var scope = testApp.App.Services.CreateScope();
    var manager = scope.ServiceProvider.GetRequiredService<IDeviceGroupManager>();
    await using var db = scope.ServiceProvider.GetRequiredService<AppDb>();

    var tenantA = await testApp.Services.CreateTestTenant("Tenant A");
    var tenantB = await testApp.Services.CreateTestTenant("Tenant B");
    var actor = await testApp.Services.CreateTestUser(tenantA.Id, $"a-{Guid.NewGuid():N}@t.local");

    var groupA = await CreateGroup(db, tenantA.Id, "Group A", actor.Id);
    await CreateGroup(db, tenantB.Id, "Group B", actor.Id);

    var all = await manager.GetAll(tenantA.Id, TestContext.Current.CancellationToken);

    Assert.Contains(all, g => g.Id == groupA.Id);
    Assert.DoesNotContain(all, g => g.Name == "Group B");
  }

  [Fact]
  public async Task Get_CrossTenantDeviceGroup_ReturnsNotFound()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutputHelper);
    using var scope = testApp.App.Services.CreateScope();
    var manager = scope.ServiceProvider.GetRequiredService<IDeviceGroupManager>();
    await using var db = scope.ServiceProvider.GetRequiredService<AppDb>();

    var tenantA = await testApp.Services.CreateTestTenant("Tenant A");
    var tenantB = await testApp.Services.CreateTestTenant("Tenant B");
    var actor = await testApp.Services.CreateTestUser(tenantA.Id, $"a-{Guid.NewGuid():N}@t.local");

    var groupB = await CreateGroup(db, tenantB.Id, "Group B", actor.Id);

    var result = await manager.Get(groupB.Id, tenantA.Id, TestContext.Current.CancellationToken);

    Assert.False(result.IsSuccess);
    Assert.Equal(HttpResultErrorCode.NotFound, result.ErrorCode);
  }

  [Fact]
  public async Task Update_CrossTenantDeviceGroup_ReturnsNotFound()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutputHelper);
    using var scope = testApp.App.Services.CreateScope();
    var manager = scope.ServiceProvider.GetRequiredService<IDeviceGroupManager>();
    await using var db = scope.ServiceProvider.GetRequiredService<AppDb>();

    var tenantA = await testApp.Services.CreateTestTenant("Tenant A");
    var tenantB = await testApp.Services.CreateTestTenant("Tenant B");
    var actor = await testApp.Services.CreateTestUser(tenantA.Id, $"a-{Guid.NewGuid():N}@t.local");

    var groupB = await CreateGroup(db, tenantB.Id, "Group B", actor.Id);

    var result = await manager.Update(
      groupB.Id,
      "Renamed",
      null,
      tenantA.Id,
      actor.Id,
      TestContext.Current.CancellationToken);

    Assert.False(result.IsSuccess);
    Assert.Equal(HttpResultErrorCode.NotFound, result.ErrorCode);
  }

  private static async Task<DeviceGroup> CreateGroup(
    AppDb db,
    Guid tenantId,
    string name,
    Guid actorPrincipalId)
  {
    var group = new DeviceGroup
    {
      Name = name,
      TenantId = tenantId,
      Members = []
    };
    db.DeviceGroups.Add(group);
    await db.SaveChangesAsync(TestContext.Current.CancellationToken);
    return group;
  }
}
