using System.Security.Claims;
using ControlR.Web.Server.Authn;
using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Data;
using ControlR.Web.Server.Data.Entities;
using ControlR.Web.Server.Extensions.Database;
using ControlR.Web.Server.Services.Authorization;
using ControlR.Web.Server.Services.DeviceManagement;
using ControlR.Web.Server.Tests.Helpers;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace ControlR.Web.Server.Tests;

/// <summary>
/// Randomized parity coverage: for many generated assignment sets (allow/deny across every
/// scope kind) over a device topology with groups and customers, enumeration membership
/// (resolver + ApplyAccessScope) must equal point evaluation for every device. Guards the
/// two-path parity invariant beyond the hand-picked shapes in DeviceScopeParityTests.
/// </summary>
public class DeviceScopeParityPropertyTests(ITestOutputHelper testOutput)
{
  private const int RandomSeed = 20260804;
  private const int ScenarioCount = 40;

  private readonly ITestOutputHelper _testOutput = testOutput;

  [Fact]
  public async Task Parity_RandomizedAssignmentSets_MatchPointEvaluation()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var user = await testApp.App.Services.CreateTestUser(tenant.Id);

    var devices = new List<Guid>();
    for (var i = 0; i < 6; i++)
    {
      var device = await testApp.App.Services.CreateTestDevice(tenant.Id);
      devices.Add(device.Id);
    }

    var group1 = Guid.NewGuid();
    var group2 = Guid.NewGuid();
    var customer1 = Guid.NewGuid();
    var customer2 = Guid.NewGuid();

    using (var setupScope = testApp.App.Services.CreateScope())
    {
      await using var setupDb = setupScope.ServiceProvider.GetRequiredService<AppDb>();
      setupDb.DeviceGroups.Add(new DeviceGroup { Id = group1, Name = $"group-{group1:N}", TenantId = tenant.Id });
      setupDb.DeviceGroups.Add(new DeviceGroup { Id = group2, Name = $"group-{group2:N}", TenantId = tenant.Id });
      setupDb.Customers.Add(new Customer { Id = customer1, Name = $"customer-{customer1:N}", TenantId = tenant.Id });
      setupDb.Customers.Add(new Customer { Id = customer2, Name = $"customer-{customer2:N}", TenantId = tenant.Id });
      setupDb.DeviceGroupMembers.Add(new DeviceGroupMember { DeviceId = devices[0], DeviceGroupId = group1 });
      setupDb.DeviceGroupMembers.Add(new DeviceGroupMember { DeviceId = devices[1], DeviceGroupId = group1 });
      setupDb.DeviceGroupMembers.Add(new DeviceGroupMember { DeviceId = devices[2], DeviceGroupId = group2 });
      setupDb.DeviceGroupMembers.Add(new DeviceGroupMember { DeviceId = devices[3], DeviceGroupId = group2 });
      await setupDb.SaveChangesAsync(TestContext.Current.CancellationToken);

      var device2 = await setupDb.Devices.FindAsync([devices[2]], TestContext.Current.CancellationToken);
      device2!.CustomerId = customer1;
      var device4 = await setupDb.Devices.FindAsync([devices[4]], TestContext.Current.CancellationToken);
      device4!.CustomerId = customer2;
      await setupDb.SaveChangesAsync(TestContext.Current.CancellationToken);
    }

    // Topology: d0,d1 in group1; d2,d3 in group2; d2 also in customer1; d4 in customer2; d5 unaffiliated.
    var topology = new (Guid Id, Guid? CustomerId, IReadOnlyCollection<Guid> GroupIds)[]
    {
      (devices[0], null, new[] { group1 }),
      (devices[1], null, new[] { group1 }),
      (devices[2], customer1, new[] { group2 }),
      (devices[3], null, new[] { group2 }),
      (devices[4], customer2, Array.Empty<Guid>()),
      (devices[5], null, Array.Empty<Guid>())
    };

    var (claims, principal) = CreateUserPrincipalPair(user.Id, tenant.Id);
    var rowTemplates = BuildRowTemplates(user.Id, tenant.Id, devices, [group1, group2], [customer1, customer2]);

    using var scope = testApp.App.Services.CreateScope();
    await using var db = scope.ServiceProvider.GetRequiredService<AppDb>();
    var resolver = scope.ServiceProvider.GetRequiredService<IDeviceAccessScopeResolver>();
    var evaluator = scope.ServiceProvider.GetRequiredService<IPermissionEvaluator>();
    var cancellationToken = TestContext.Current.CancellationToken;

    var random = new Random(RandomSeed);

    for (var scenario = 0; scenario < ScenarioCount; scenario++)
    {
      var existing = await db.PermissionAssignments
        .IgnoreQueryFilters()
        .Where(x => x.PrincipalKind == PermissionPrincipalKind.User && x.PrincipalId == user.Id)
        .ToListAsync(cancellationToken);
      db.PermissionAssignments.RemoveRange(existing);
      await db.SaveChangesAsync(cancellationToken);

      var rows = rowTemplates
        .Where(template => random.NextDouble() < 0.25)
        .Select(template => template())
        .ToList();

      if (rows.Count == 0)
      {
        rows.Add(rowTemplates[random.Next(rowTemplates.Count)]());
      }

      foreach (var row in rows)
      {
        db.PermissionAssignments.Add(row);
      }
      await db.SaveChangesAsync(cancellationToken);

      var accessScope = await resolver.Resolve(claims, cancellationToken);
      var listedDeviceIds = await db.Devices
        .ApplyAccessScope(tenant.Id, accessScope)
        .Select(x => x.Id)
        .ToListAsync(cancellationToken);

      foreach (var device in topology)
      {
        var descriptor = new ResourceDescriptor(
          PermissionScopeKind.Device, device.Id, tenant.Id, device.CustomerId, DeviceGroupIds: device.GroupIds);

        var result = await evaluator.Evaluate(principal, PermissionNames.DeviceRead, descriptor, cancellationToken);
        var listed = listedDeviceIds.Contains(device.Id);

        Assert.True(
          result.Allowed == listed,
          $"Scenario {scenario}: device {device.Id} enumerated={listed} but point evaluation allowed={result.Allowed}. " +
          $"Rows: {string.Join(", ", rows.Select(r => $"{r.Effect}@{r.ScopeKind}"))}");
      }
    }
  }

  private static List<Func<PermissionAssignment>> BuildRowTemplates(
    Guid userId,
    Guid tenantId,
    List<Guid> devices,
    List<Guid> groupIds,
    List<Guid> customerIds)
  {
    var scopes = new List<(PermissionScopeKind Kind, Guid? ScopeId)>
    {
      (PermissionScopeKind.Server, null),
      (PermissionScopeKind.Tenant, tenantId)
    };
    scopes.AddRange(groupIds.Select(id => (PermissionScopeKind.DeviceGroup, (Guid?)id)));
    scopes.AddRange(customerIds.Select(id => (PermissionScopeKind.CustomerTenant, (Guid?)id)));
    scopes.AddRange(devices.Select(id => (PermissionScopeKind.Device, (Guid?)id)));

    var templates = new List<Func<PermissionAssignment>>();
    foreach (var effect in new[] { PermissionEffect.Allow, PermissionEffect.Deny })
    {
      foreach (var (kind, scopeId) in scopes)
      {
        templates.Add(() => PermissionAssignment.CreateGrant(
          PermissionPrincipalKind.User,
          userId,
          PermissionNames.DeviceRead,
          kind,
          scopeId,
          tenantId,
          new PrincipalDescriptor(PrincipalType.User, userId, tenantId, "parity-test"),
          effect));
      }
    }

    return templates;
  }

  private static (ClaimsPrincipal Claims, PrincipalDescriptor Descriptor) CreateUserPrincipalPair(
    Guid userId, Guid tenantId)
  {
    var claims = new ClaimsPrincipal(new ClaimsIdentity(
    [
      new Claim(PrincipalClaimTypes.PrincipalType, PrincipalClaimValues.User),
      new Claim(PrincipalClaimTypes.PrincipalId, userId.ToString()),
      new Claim(UserClaimTypes.TenantId, tenantId.ToString())
    ], "TestAuth"));

    var descriptor = claims.ToPrincipalDescriptor()
      ?? throw new InvalidOperationException("Failed to build principal descriptor from claims.");

    return (claims, descriptor);
  }
}
