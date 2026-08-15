using System.Security.Claims;
using ControlR.Web.Server.Authn;
using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Data;
using ControlR.Web.Server.Data.Entities;
using ControlR.Web.Server.Extensions.Database;
using ControlR.Web.Server.Services.Authorization;
using ControlR.Web.Server.Services.Authorization.PermissionRules;
using ControlR.Web.Server.Services.DeviceManagement;
using ControlR.Web.Server.Tests.Helpers;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace ControlR.Web.Server.Tests;

/// <summary>
/// Parity tests asserting that the set-enumeration path (<see cref="IDeviceAccessScopeResolver"/>
/// projected through <c>ApplyAccessScope</c>) and the point-authorization path
/// (<see cref="IPermissionEvaluator"/>) agree on which devices a principal may access. Both paths
/// interpret assignments through the shared <see cref="IPermissionRuleResolver"/>; these tests use
/// assignment-scoped principals (no role bridges) across each scope kind.
/// </summary>
public class DeviceScopeParityTests(ITestOutputHelper testOutput)
{
  private readonly ITestOutputHelper _testOutput = testOutput;

  [Fact]
  public async Task Parity_CustomerScopedAssignment()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var user = await testApp.App.Services.CreateTestUser(tenant.Id);
    var deviceA = await testApp.App.Services.CreateTestDevice(tenant.Id);
    var deviceB = await testApp.App.Services.CreateTestDevice(tenant.Id);
    var customerId = Guid.NewGuid();

    using (var scope = testApp.App.Services.CreateScope())
    {
      await using var db = scope.ServiceProvider.GetRequiredService<AppDb>();
      db.Customers.Add(new Customer { Id = customerId, Name = $"customer-{customerId:N}", TenantId = tenant.Id });
      await db.SaveChangesAsync(TestContext.Current.CancellationToken);

      var device = await db.Devices.FindAsync([deviceA.Id], TestContext.Current.CancellationToken);
      device!.CustomerId = customerId;
      await db.SaveChangesAsync(TestContext.Current.CancellationToken);
    }

    await SeedAssignment(testApp, new PermissionAssignment
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

    var (claims, principal) = CreateUserPrincipalPair(user.Id, tenant.Id);

    await AssertResolverEvaluatorParity(testApp, tenant.Id, claims, principal,
    [
      new ParityDevice(deviceA.Id, customerId, []),
      new ParityDevice(deviceB.Id, null, [])
    ]);
  }

  [Fact]
  public async Task Parity_DeviceGroupScopedAssignment()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var user = await testApp.App.Services.CreateTestUser(tenant.Id);
    var deviceA = await testApp.App.Services.CreateTestDevice(tenant.Id);
    var deviceB = await testApp.App.Services.CreateTestDevice(tenant.Id);
    var groupId = Guid.NewGuid();

    using (var scope = testApp.App.Services.CreateScope())
    {
      await using var db = scope.ServiceProvider.GetRequiredService<AppDb>();
      db.DeviceGroups.Add(new DeviceGroup { Id = groupId, Name = $"group-{groupId:N}", TenantId = tenant.Id });
      db.DeviceGroupMembers.Add(new DeviceGroupMember { DeviceId = deviceA.Id, DeviceGroupId = groupId });
      await db.SaveChangesAsync(TestContext.Current.CancellationToken);
    }

    await SeedAssignment(testApp, new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.User,
      PrincipalId = user.Id,
      PermissionName = PermissionNames.DeviceRead,
      Effect = PermissionEffect.Allow,
      ScopeKind = PermissionScopeKind.DeviceGroup,
      ScopeId = groupId,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });

    var (claims, principal) = CreateUserPrincipalPair(user.Id, tenant.Id);

    await AssertResolverEvaluatorParity(testApp, tenant.Id, claims, principal,
    [
      new ParityDevice(deviceA.Id, null, [groupId]),
      new ParityDevice(deviceB.Id, null, [])
    ]);
  }

  [Fact]
  public async Task Parity_DeviceScopedAssignment()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var user = await testApp.App.Services.CreateTestUser(tenant.Id);
    var deviceA = await testApp.App.Services.CreateTestDevice(tenant.Id);
    var deviceB = await testApp.App.Services.CreateTestDevice(tenant.Id);

    await SeedAssignment(testApp, new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.User,
      PrincipalId = user.Id,
      PermissionName = PermissionNames.DeviceRead,
      Effect = PermissionEffect.Allow,
      ScopeKind = PermissionScopeKind.Device,
      ScopeId = deviceA.Id,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });

    var (claims, principal) = CreateUserPrincipalPair(user.Id, tenant.Id);

    await AssertResolverEvaluatorParity(testApp, tenant.Id, claims, principal,
    [
      new ParityDevice(deviceA.Id, null, []),
      new ParityDevice(deviceB.Id, null, [])
    ]);
  }

  [Fact]
  public async Task Parity_MultiCategoryAllows_EnumeratesAllCategories()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var user = await testApp.App.Services.CreateTestUser(tenant.Id);
    var deviceA = await testApp.App.Services.CreateTestDevice(tenant.Id);
    var deviceB = await testApp.App.Services.CreateTestDevice(tenant.Id);
    var deviceC = await testApp.App.Services.CreateTestDevice(tenant.Id);
    var groupId = Guid.NewGuid();
    var customerId = Guid.NewGuid();

    using (var scope = testApp.App.Services.CreateScope())
    {
      await using var db = scope.ServiceProvider.GetRequiredService<AppDb>();
      db.DeviceGroups.Add(new DeviceGroup { Id = groupId, Name = $"group-{groupId:N}", TenantId = tenant.Id });
      db.DeviceGroupMembers.Add(new DeviceGroupMember { DeviceId = deviceA.Id, DeviceGroupId = groupId });
      db.Customers.Add(new Customer { Id = customerId, Name = $"customer-{customerId:N}", TenantId = tenant.Id });
      await db.SaveChangesAsync(TestContext.Current.CancellationToken);

      var device = await db.Devices.FindAsync([deviceB.Id], TestContext.Current.CancellationToken);
      device!.CustomerId = customerId;
      await db.SaveChangesAsync(TestContext.Current.CancellationToken);
    }

    await SeedAssignment(testApp, new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.User,
      PrincipalId = user.Id,
      PermissionName = PermissionNames.DeviceRead,
      Effect = PermissionEffect.Allow,
      ScopeKind = PermissionScopeKind.DeviceGroup,
      ScopeId = groupId,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });

    await SeedAssignment(testApp, new PermissionAssignment
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

    var (claims, principal) = CreateUserPrincipalPair(user.Id, tenant.Id);

    await AssertResolverEvaluatorParity(testApp, tenant.Id, claims, principal,
    [
      new ParityDevice(deviceA.Id, null, [groupId]),
      new ParityDevice(deviceB.Id, customerId, []),
      new ParityDevice(deviceC.Id, null, [])
    ]);
  }

  [Fact]
  public async Task Parity_TenantAllowWithDeviceDeny_ExcludesDeniedDevice()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var user = await testApp.App.Services.CreateTestUser(tenant.Id);
    var deviceA = await testApp.App.Services.CreateTestDevice(tenant.Id);
    var deviceB = await testApp.App.Services.CreateTestDevice(tenant.Id);

    await SeedAssignment(testApp, new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.User,
      PrincipalId = user.Id,
      PermissionName = PermissionNames.DeviceRead,
      Effect = PermissionEffect.Allow,
      ScopeKind = PermissionScopeKind.Tenant,
      ScopeId = tenant.Id,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });

    await SeedAssignment(testApp, new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.User,
      PrincipalId = user.Id,
      PermissionName = PermissionNames.DeviceRead,
      Effect = PermissionEffect.Deny,
      ScopeKind = PermissionScopeKind.Device,
      ScopeId = deviceB.Id,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });

    var (claims, principal) = CreateUserPrincipalPair(user.Id, tenant.Id);

    await AssertResolverEvaluatorParity(testApp, tenant.Id, claims, principal,
    [
      new ParityDevice(deviceA.Id, null, []),
      new ParityDevice(deviceB.Id, null, [])
    ]);
  }

  [Fact]
  public async Task Parity_TenantScopedAssignment()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var user = await testApp.App.Services.CreateTestUser(tenant.Id);
    var deviceA = await testApp.App.Services.CreateTestDevice(tenant.Id);
    var deviceB = await testApp.App.Services.CreateTestDevice(tenant.Id);

    await SeedAssignment(testApp, new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.User,
      PrincipalId = user.Id,
      PermissionName = PermissionNames.DeviceRead,
      Effect = PermissionEffect.Allow,
      ScopeKind = PermissionScopeKind.Tenant,
      ScopeId = tenant.Id,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });

    var (claims, principal) = CreateUserPrincipalPair(user.Id, tenant.Id);

    await AssertResolverEvaluatorParity(testApp, tenant.Id, claims, principal,
    [
      new ParityDevice(deviceA.Id, null, []),
      new ParityDevice(deviceB.Id, null, [])
    ]);
  }

  private static async Task AssertResolverEvaluatorParity(
    TestApp testApp,
    Guid tenantId,
    ClaimsPrincipal claimsPrincipal,
    PrincipalDescriptor principal,
    IReadOnlyList<ParityDevice> devices)
  {
    var cancellationToken = TestContext.Current.CancellationToken;
    using var scope = testApp.App.Services.CreateScope();
    await using var db = scope.ServiceProvider.GetRequiredService<AppDb>();
    var resolver = scope.ServiceProvider.GetRequiredService<IDeviceAccessScopeResolver>();
    var evaluator = scope.ServiceProvider.GetRequiredService<IPermissionEvaluator>();

    var accessScope = await resolver.Resolve(claimsPrincipal, tenantId, cancellationToken);

    var listedDeviceIds = await db.Devices
      .ApplyAccessScope(tenantId, accessScope)
      .Select(x => x.Id)
      .ToListAsync(cancellationToken);

    foreach (var device in devices)
    {
      var descriptor = new ResourceDescriptor(
        PermissionScopeKind.Device, device.Id, tenantId, device.CustomerId, DeviceGroupIds: device.GroupIds);

      var result = await evaluator.Evaluate(principal, PermissionNames.DeviceRead, descriptor, cancellationToken);

      Assert.Equal(result.Allowed, listedDeviceIds.Contains(device.Id));
    }
  }

  private static (ClaimsPrincipal Claims, PrincipalDescriptor Descriptor) CreateUserPrincipalPair(
    Guid userId, Guid tenantId)
  {
    var claims = new ClaimsPrincipal(new ClaimsIdentity(
    [
      new Claim(PrincipalClaimTypes.PrincipalType, PrincipalClaimTypes.User),
      new Claim(PrincipalClaimTypes.PrincipalId, userId.ToString()),
      new Claim(UserClaimTypes.TenantId, tenantId.ToString())
    ], "TestAuth"));

    var descriptor = PrincipalDescriptorBuilder.FromClaims(claims)
      ?? throw new InvalidOperationException("Failed to build principal descriptor from claims.");

    return (claims, descriptor);
  }

  private static async Task SeedAssignment(TestApp testApp, PermissionAssignment assignment)
  {
    using var scope = testApp.App.Services.CreateScope();
    await using var db = scope.ServiceProvider.GetRequiredService<AppDb>();
    db.PermissionAssignments.Add(assignment);
    await db.SaveChangesAsync(TestContext.Current.CancellationToken);
  }

  private sealed record ParityDevice(Guid Id, Guid? CustomerId, IReadOnlyCollection<Guid> GroupIds);
}
