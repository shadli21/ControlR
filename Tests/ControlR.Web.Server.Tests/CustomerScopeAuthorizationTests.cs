using System.Security.Claims;
using ControlR.Web.Server.Authn;
using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Data;
using ControlR.Web.Server.Data.Entities;
using ControlR.Web.Server.Primitives;
using ControlR.Web.Server.Services.DeviceManagement;
using ControlR.Web.Server.Services.PermissionAssignments;
using ControlR.Web.Server.Tests.Helpers;
using Microsoft.Extensions.DependencyInjection;

namespace ControlR.Web.Server.Tests;

public class CustomerScopeAuthorizationTests(ITestOutputHelper testOutput)
{
  private readonly ITestOutputHelper _testOutput = testOutput;

  [Fact]
  public async Task Create_CustomerScopeWithoutScopeId_ReturnsBadRequest()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var user = await testApp.App.Services.CreateTestUser(tenant.Id);

    await using (var setupScope = testApp.App.Services.CreateAsyncScope())
    {
      var db = setupScope.ServiceProvider.GetRequiredService<AppDb>();
      db.PermissionAssignments.Add(PermissionAssignment.CreateGrant(
        PermissionPrincipalKind.User,
        user.Id,
        PermissionNames.TenantPermissionsWrite,
        PermissionScopeKind.Tenant,
        tenant.Id,
        tenant.Id,
        new PrincipalDescriptor(PrincipalType.User, user.Id, tenant.Id, "test")));
      await db.SaveChangesAsync(TestContext.Current.CancellationToken);
    }

    using var scope = testApp.App.Services.CreateScope();
    var manager = scope.ServiceProvider.GetRequiredService<IPermissionAssignmentManager>();

    var result = await manager.Create(
      new InternalDtos.CreatePermissionAssignmentRequestDto(
        PermissionPrincipalKind.User,
        user.Id,
        PermissionNames.DeviceRead,
        PermissionEffect.Allow,
        PermissionScopeKind.CustomerTenant,
        null,
        null),
      tenant.Id,
      new PrincipalDescriptor(PrincipalType.User, user.Id, tenant.Id, "test"),
      TestContext.Current.CancellationToken);

    Assert.False(result.IsSuccess);
    Assert.Equal(HttpResultErrorCode.BadRequest, result.ErrorCode);
  }

  [Fact]
  public async Task Resolve_CustomerScopeAssignment_ReturnsForCustomers()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var user = await testApp.App.Services.CreateTestUser(tenant.Id);
    var customerId = Guid.NewGuid();

    using var scope = testApp.App.Services.CreateScope();
    await using var db = scope.ServiceProvider.GetRequiredService<AppDb>();
    db.PermissionAssignments.Add(new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.User,
      PrincipalId = user.Id,
      PermissionName = PermissionNames.DeviceRead,
      Effect = PermissionEffect.Allow,
      ScopeKind = PermissionScopeKind.CustomerTenant,
      ScopeId = customerId,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });
    await db.SaveChangesAsync(TestContext.Current.CancellationToken);

    var resolver = scope.ServiceProvider.GetRequiredService<IDeviceAccessScopeResolver>();
    var principal = new ClaimsPrincipal(new ClaimsIdentity([
      new Claim(PrincipalClaimTypes.PrincipalType, PrincipalClaimValues.User),
      new Claim(PrincipalClaimTypes.PrincipalId, user.Id.ToString()),
      new Claim(UserClaimTypes.TenantId, tenant.Id.ToString())
    ], "TestAuth"));

    var result = await resolver.Resolve(principal, TestContext.Current.CancellationToken);

    Assert.Contains(customerId, result.IncludedCustomerIds);
  }
}
