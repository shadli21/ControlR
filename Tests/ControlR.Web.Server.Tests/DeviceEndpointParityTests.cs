using System.Net;
using System.Net.Http.Json;
using ControlR.Web.Server.Authn;
using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Data;
using ControlR.Web.Server.Data.Entities;
using ControlR.Web.Server.Services;
using ControlR.Web.Server.Tests.Helpers;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace ControlR.Web.Server.Tests;

/// <summary>
/// Boundary-level parity: the device list endpoint (scope resolver + ApplyAccessScope) and
/// the single-device endpoint (resource policy evaluation) must agree on which devices a
/// principal can read, across deny and multi-category assignment shapes.
/// </summary>
public class DeviceEndpointParityTests(ITestOutputHelper testOutput)
{
  private readonly ITestOutputHelper _testOutput = testOutput;

  [Fact]
  public async Task ListEndpoint_And_SingleDeviceEndpoint_AgreeOnReadableDevices()
  {
    using var testServer = await TestWebServerBuilder.CreateTestServer(_testOutput);

    var tenant = await testServer.Services.CreateTestTenant();
    await testServer.Services.CreateTestUser(tenant.Id, email: $"seed-{Guid.NewGuid():N}@t.local");

    var deviceInGroup = await testServer.Services.CreateTestDevice(tenant.Id);
    var deviceInCustomer = await testServer.Services.CreateTestDevice(tenant.Id);
    var plainDevice = await testServer.Services.CreateTestDevice(tenant.Id);
    var deniedDevice = await testServer.Services.CreateTestDevice(tenant.Id);
    var groupId = Guid.NewGuid();
    var customerId = Guid.NewGuid();

    using (var scope = testServer.Services.CreateScope())
    {
      await using var db = scope.ServiceProvider.GetRequiredService<AppDb>();
      db.DeviceGroups.Add(new DeviceGroup { Id = groupId, Name = $"group-{groupId:N}", TenantId = tenant.Id });
      db.DeviceGroupMembers.Add(new DeviceGroupMember { DeviceId = deviceInGroup.Id, DeviceGroupId = groupId });
      db.Customers.Add(new Customer { Id = customerId, Name = $"customer-{customerId:N}", TenantId = tenant.Id });
      await db.SaveChangesAsync(TestContext.Current.CancellationToken);

      var customerDevice = await db.Devices.FindAsync([deviceInCustomer.Id], TestContext.Current.CancellationToken);
      customerDevice!.CustomerId = customerId;
      await db.SaveChangesAsync(TestContext.Current.CancellationToken);
    }

    var allDevices = new[] { deviceInGroup.Id, deviceInCustomer.Id, plainDevice.Id, deniedDevice.Id };

    // Scenario 1: tenant-wide allow with a device-scoped deny.
    var tenantAllowUser = await testServer.Services.CreateTestUser(tenant.Id, $"tenant-allow-{Guid.NewGuid():N}@t.local");
    await SeedAssignment(testServer, CreateGrant(tenantAllowUser.Id, PermissionNames.DeviceRead,
      PermissionScopeKind.Tenant, tenant.Id, tenant.Id));
    await SeedAssignment(testServer, CreateGrant(tenantAllowUser.Id, PermissionNames.DeviceRead,
      PermissionScopeKind.Device, deniedDevice.Id, tenant.Id, PermissionEffect.Deny));
    await AssertParity(testServer, tenantAllowUser.Id, allDevices,
      expectedReadable: [deviceInGroup.Id, deviceInCustomer.Id, plainDevice.Id]);

    // Scenario 2: group-scoped allow only.
    var groupAllowUser = await testServer.Services.CreateTestUser(tenant.Id, $"group-allow-{Guid.NewGuid():N}@t.local");
    await SeedAssignment(testServer, CreateGrant(groupAllowUser.Id, PermissionNames.DeviceRead,
      PermissionScopeKind.DeviceGroup, groupId, tenant.Id));
    await AssertParity(testServer, groupAllowUser.Id, allDevices,
      expectedReadable: [deviceInGroup.Id]);

    // Scenario 3: customer-scoped allow only.
    var customerAllowUser = await testServer.Services.CreateTestUser(tenant.Id, $"customer-allow-{Guid.NewGuid():N}@t.local");
    await SeedAssignment(testServer, CreateGrant(customerAllowUser.Id, PermissionNames.DeviceRead,
      PermissionScopeKind.CustomerTenant, customerId, tenant.Id));
    await AssertParity(testServer, customerAllowUser.Id, allDevices,
      expectedReadable: [deviceInCustomer.Id]);
  }

  [Fact]
  public async Task PatListEndpoint_And_SingleDeviceEndpoint_AgreeOnExplicitPatScope()
  {
    using var testServer = await TestWebServerBuilder.CreateTestServer(_testOutput);
    var tenant = await testServer.Services.CreateTestTenant();
    await testServer.Services.CreateTestUser(tenant.Id, email: $"seed-{Guid.NewGuid():N}@t.local");
    var user = await testServer.Services.CreateTestUser(tenant.Id, $"pat-owner-{Guid.NewGuid():N}@t.local");
    var deviceA = await testServer.Services.CreateTestDevice(tenant.Id);
    var deviceB = await testServer.Services.CreateTestDevice(tenant.Id);
    await SeedAssignment(testServer, CreateGrant(
      user.Id,
      PermissionNames.DeviceRead,
      PermissionScopeKind.Tenant,
      tenant.Id,
      tenant.Id));

    var patManager = testServer.Services.GetRequiredService<IPersonalAccessTokenManager>();
    var patResult = await patManager.CreateToken(
      new InternalDtos.CreatePersonalAccessTokenRequestDto("Explicit PAT parity", PersonalAccessTokenPermissionMode.InheritOwner),
      user.Id);
    Assert.True(patResult.IsSuccess);

    using (var scope = testServer.Services.CreateScope())
    {
      await using var db = scope.ServiceProvider.GetRequiredService<AppDb>();
      var patRow = await db.PersonalAccessTokens.SingleAsync(
        token => token.Id == patResult.Value.PersonalAccessToken.Id,
        TestContext.Current.CancellationToken);
      patRow.PermissionMode = PersonalAccessTokenPermissionMode.Restricted;
      db.PermissionAssignments.Add(PermissionAssignment.CreateGrant(
        PermissionPrincipalKind.PersonalAccessToken,
        patResult.Value.PersonalAccessToken.Id,
        PermissionNames.DeviceRead,
        PermissionScopeKind.Device,
        deviceA.Id,
        tenant.Id,
        "test",
        user.Id.ToString()));
      await db.SaveChangesAsync(TestContext.Current.CancellationToken);
    }

    using var httpClient = testServer.Factory.CreateClient();
    httpClient.DefaultRequestHeaders.Add(
      PersonalAccessTokenAuthenticationSchemeOptions.DefaultHeaderName,
      patResult.Value.PlainTextToken);
    var listResponse = await httpClient.GetAsync(
      HttpConstants.Internal.DevicesEndpoint,
      TestContext.Current.CancellationToken);
    var listedDevices = await listResponse.Content.ReadFromJsonAsync<InternalDtos.DeviceResponseDto[]>(
      TestContext.Current.CancellationToken);
    Assert.Equal(HttpStatusCode.OK, listResponse.StatusCode);
    Assert.NotNull(listedDevices);
    Assert.True(
      new[] { deviceA.Id }.SequenceEqual(listedDevices.Select(device => device.Id)));

    var deviceAResponse = await httpClient.GetAsync(
      $"{HttpConstants.Internal.DevicesEndpoint}/{deviceA.Id}",
      TestContext.Current.CancellationToken);
    var deviceBResponse = await httpClient.GetAsync(
      $"{HttpConstants.Internal.DevicesEndpoint}/{deviceB.Id}",
      TestContext.Current.CancellationToken);
    Assert.Equal(HttpStatusCode.OK, deviceAResponse.StatusCode);
    Assert.Equal(HttpStatusCode.Forbidden, deviceBResponse.StatusCode);
  }

  private static PermissionAssignment CreateGrant(
    Guid userId,
    string permissionName,
    PermissionScopeKind scopeKind,
    Guid? scopeId,
    Guid tenantId,
    PermissionEffect effect = PermissionEffect.Allow) =>
    PermissionAssignment.CreateGrant(
      PermissionPrincipalKind.User,
      userId,
      permissionName,
      scopeKind,
      scopeId,
      tenantId,
      "parity-test",
      userId.ToString(),
      effect);

  private static async Task SeedAssignment(TestWebServer testServer, PermissionAssignment assignment)
  {
    using var scope = testServer.Services.CreateScope();
    await using var db = scope.ServiceProvider.GetRequiredService<AppDb>();
    db.PermissionAssignments.Add(assignment);
    await db.SaveChangesAsync(TestContext.Current.CancellationToken);
  }

  private async Task AssertParity(
    TestWebServer testServer,
    Guid userId,
    Guid[] allDevices,
    Guid[] expectedReadable)
  {
    using var httpClient = await CreatePatClient(testServer, userId);

    var listResponse = await httpClient.GetAsync(
      HttpConstants.Internal.DevicesEndpoint, TestContext.Current.CancellationToken);
    Assert.Equal(HttpStatusCode.OK, listResponse.StatusCode);

    var listedDevices = await listResponse.Content.ReadFromJsonAsync<InternalDtos.DeviceResponseDto[]>(
      TestContext.Current.CancellationToken);
    Assert.NotNull(listedDevices);
    var listedIds = listedDevices.Select(x => x.Id).ToHashSet();

    Assert.True(
      expectedReadable.ToHashSet().SetEquals(listedIds),
      $"List endpoint returned [{string.Join(", ", listedIds)}], expected [{string.Join(", ", expectedReadable)}].");

    foreach (var deviceId in allDevices)
    {
      var singleResponse = await httpClient.GetAsync(
        $"{HttpConstants.Internal.DevicesEndpoint}/{deviceId}", TestContext.Current.CancellationToken);

      var readable = singleResponse.StatusCode == HttpStatusCode.OK;
      Assert.True(
        readable == listedIds.Contains(deviceId),
        $"Device {deviceId}: listed={listedIds.Contains(deviceId)} but single-device GET returned {singleResponse.StatusCode}.");
      Assert.True(
        readable == expectedReadable.Contains(deviceId),
        $"Device {deviceId}: expected readable={expectedReadable.Contains(deviceId)} but single-device GET returned {singleResponse.StatusCode}.");
      Assert.False(
        singleResponse.StatusCode == HttpStatusCode.Forbidden && listedIds.Contains(deviceId),
        $"Device {deviceId} was listed but the single-device GET forbade it — data leaked in enumeration.");
    }
  }

  private async Task<HttpClient> CreatePatClient(TestWebServer testServer, Guid userId)
  {
    var patManager = testServer.Services.GetRequiredService<IPersonalAccessTokenManager>();
    var patResult = await patManager.CreateToken(
      new InternalDtos.CreatePersonalAccessTokenRequestDto("Device Endpoint Parity PAT", PersonalAccessTokenPermissionMode.InheritOwner), userId);
    Assert.True(patResult.IsSuccess);

    var client = testServer.Factory.CreateClient();
    client.DefaultRequestHeaders.Add(
      PersonalAccessTokenAuthenticationSchemeOptions.DefaultHeaderName,
      patResult.Value.PlainTextToken);
    return client;
  }
}
