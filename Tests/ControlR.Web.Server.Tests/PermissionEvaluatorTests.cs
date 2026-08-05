using ControlR.Web.Server.Authn;
using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Data;
using ControlR.Web.Server.Data.Entities;
using ControlR.Web.Server.Data.Enums;
using ControlR.Web.Server.Services.Authorization;
using ControlR.Web.Server.Tests.Helpers;
using Microsoft.Extensions.DependencyInjection;

namespace ControlR.Web.Server.Tests;

public class PermissionEvaluatorTests(ITestOutputHelper testOutput)
{
  private readonly ITestOutputHelper _testOutput = testOutput;

  [Fact]
  public async Task CustomerScopeAssignment_CoversDeviceInCustomer()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var user = await testApp.App.Services.CreateTestUser(tenant.Id);
    var device = await testApp.App.Services.CreateTestDevice(tenant.Id);
    var customerId = Guid.NewGuid();

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

    var evaluator = GetEvaluator(testApp);
    var principal = CreateUserPrincipal(user.Id, tenant.Id);
    var resource = new ResourceDescriptor(PermissionScopeKind.Device, device.Id, tenant.Id, customerId);

    var result = await evaluator.Evaluate(principal, PermissionNames.DeviceRead, resource, TestContext.Current.CancellationToken);

    Assert.True(result.Allowed);
  }

  [Fact]
  public async Task CustomerScopeAssignment_DeniesDeviceInOtherCustomer()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var user = await testApp.App.Services.CreateTestUser(tenant.Id);
    var device = await testApp.App.Services.CreateTestDevice(tenant.Id);
    var customerId = Guid.NewGuid();

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

    var evaluator = GetEvaluator(testApp);
    var principal = CreateUserPrincipal(user.Id, tenant.Id);
    var resource = new ResourceDescriptor(PermissionScopeKind.Device, device.Id, tenant.Id, Guid.NewGuid());

    var result = await evaluator.Evaluate(principal, PermissionNames.DeviceRead, resource, TestContext.Current.CancellationToken);

    Assert.False(result.Allowed);
    Assert.Contains("default deny", result.DenialReason);
  }

  [Fact]
  public async Task CustomerScopeAssignment_DeniesUnassignedDevice()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var user = await testApp.App.Services.CreateTestUser(tenant.Id);
    var device = await testApp.App.Services.CreateTestDevice(tenant.Id);
    var customerId = Guid.NewGuid();

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

    var evaluator = GetEvaluator(testApp);
    var principal = CreateUserPrincipal(user.Id, tenant.Id);
    var resource = new ResourceDescriptor(PermissionScopeKind.Device, device.Id, tenant.Id);

    var result = await evaluator.Evaluate(principal, PermissionNames.DeviceRead, resource, TestContext.Current.CancellationToken);

    Assert.False(result.Allowed);
  }

  [Fact]
  public async Task CustomerScopeDeny_OverridesTenantAllow()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var user = await testApp.App.Services.CreateTestUser(tenant.Id);
    var device = await testApp.App.Services.CreateTestDevice(tenant.Id);
    var customerId = Guid.NewGuid();

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
      ScopeKind = PermissionScopeKind.CustomerTenant,
      ScopeId = customerId,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });

    var evaluator = GetEvaluator(testApp);
    var principal = CreateUserPrincipal(user.Id, tenant.Id);
    var resource = new ResourceDescriptor(PermissionScopeKind.Device, device.Id, tenant.Id, customerId);

    var result = await evaluator.Evaluate(principal, PermissionNames.DeviceRead, resource, TestContext.Current.CancellationToken);

    Assert.False(result.Allowed);
    Assert.Contains("Explicit deny", result.DenialReason);
  }

  [Fact]
  public async Task DefaultDeny_WhenNoRules_Denies()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var user = await testApp.App.Services.CreateTestUser(tenant.Id);
    var device = await testApp.App.Services.CreateTestDevice(tenant.Id);

    var evaluator = GetEvaluator(testApp);
    var principal = CreateUserPrincipal(user.Id, tenant.Id);
    var resource = new ResourceDescriptor(PermissionScopeKind.Device, device.Id, tenant.Id);

    var result = await evaluator.Evaluate(principal, PermissionNames.DeviceRead, resource, TestContext.Current.CancellationToken);

    Assert.False(result.Allowed);
    Assert.Contains("default deny", result.DenialReason);
  }

  [Fact]
  public async Task DenyOverridesAllow_WhenBothExist_Denies()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var user = await testApp.App.Services.CreateTestUser(tenant.Id);
    var device = await testApp.App.Services.CreateTestDevice(tenant.Id);

    await SeedAssignment(testApp, new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.User,
      PrincipalId = user.Id,
      PermissionName = PermissionNames.DeviceDelete,
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
      PermissionName = PermissionNames.DeviceDelete,
      Effect = PermissionEffect.Deny,
      ScopeKind = PermissionScopeKind.Device,
      ScopeId = device.Id,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });

    var evaluator = GetEvaluator(testApp);
    var principal = CreateUserPrincipal(user.Id, tenant.Id);
    var resource = new ResourceDescriptor(PermissionScopeKind.Device, device.Id, tenant.Id);

    var result = await evaluator.Evaluate(principal, PermissionNames.DeviceDelete, resource, TestContext.Current.CancellationToken);

    Assert.False(result.Allowed);
    Assert.Contains("Explicit deny", result.DenialReason);
  }

  [Fact]
  public async Task DenyViaUserGroup_OverridesDirectAllow()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var user = await testApp.App.Services.CreateTestUser(tenant.Id);
    var device = await testApp.App.Services.CreateTestDevice(tenant.Id);

    var groupId = Guid.NewGuid();
    await SeedUserGroup(testApp, groupId, tenant.Id, user.Id);

    await SeedAssignment(testApp, new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.User,
      PrincipalId = user.Id,
      PermissionName = PermissionNames.DeviceDelete,
      Effect = PermissionEffect.Allow,
      ScopeKind = PermissionScopeKind.Tenant,
      ScopeId = tenant.Id,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });

    await SeedAssignment(testApp, new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.UserGroup,
      PrincipalId = groupId,
      PermissionName = PermissionNames.DeviceDelete,
      Effect = PermissionEffect.Deny,
      ScopeKind = PermissionScopeKind.Device,
      ScopeId = device.Id,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });

    var evaluator = GetEvaluator(testApp);
    var principal = CreateUserPrincipal(user.Id, tenant.Id);
    var resource = new ResourceDescriptor(PermissionScopeKind.Device, device.Id, tenant.Id);

    var result = await evaluator.Evaluate(principal, PermissionNames.DeviceDelete, resource, TestContext.Current.CancellationToken);

    Assert.False(result.Allowed);
    Assert.Contains("Explicit deny", result.DenialReason);
  }

  [Fact]
  public async Task DeviceGroupScopeAssignment_CoversDevice()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var user = await testApp.App.Services.CreateTestUser(tenant.Id);
    var device = await testApp.App.Services.CreateTestDevice(tenant.Id);
    var deviceGroupId = Guid.NewGuid();

    await SeedAssignment(testApp, new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.User,
      PrincipalId = user.Id,
      PermissionName = PermissionNames.DeviceRead,
      Effect = PermissionEffect.Allow,
      ScopeKind = PermissionScopeKind.DeviceGroup,
      ScopeId = deviceGroupId,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });

    var evaluator = GetEvaluator(testApp);
    var principal = CreateUserPrincipal(user.Id, tenant.Id);
    var resource = new ResourceDescriptor(PermissionScopeKind.Device, device.Id, tenant.Id, DeviceGroupIds: [deviceGroupId]);

    var result = await evaluator.Evaluate(principal, PermissionNames.DeviceRead, resource, TestContext.Current.CancellationToken);

    Assert.True(result.Allowed);
    Assert.Equal("Direct", result.MatchedRuleSource);
  }

  [Fact]
  public async Task DeviceGroupScopeAssignment_DeniesDeviceNotInGroup()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var user = await testApp.App.Services.CreateTestUser(tenant.Id);
    var device = await testApp.App.Services.CreateTestDevice(tenant.Id);
    var deviceGroupId = Guid.NewGuid();

    await SeedAssignment(testApp, new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.User,
      PrincipalId = user.Id,
      PermissionName = PermissionNames.DeviceRead,
      Effect = PermissionEffect.Allow,
      ScopeKind = PermissionScopeKind.DeviceGroup,
      ScopeId = deviceGroupId,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });

    var evaluator = GetEvaluator(testApp);
    var principal = CreateUserPrincipal(user.Id, tenant.Id);
    var resource = new ResourceDescriptor(PermissionScopeKind.Device, device.Id, tenant.Id, DeviceGroupIds: [Guid.NewGuid()]);

    var result = await evaluator.Evaluate(principal, PermissionNames.DeviceRead, resource, TestContext.Current.CancellationToken);

    Assert.False(result.Allowed);
    Assert.Contains("default deny", result.DenialReason);
  }

  [Fact]
  public async Task DeviceGroupScopeAssignment_DeniesDeviceWithUnknownMembership()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var user = await testApp.App.Services.CreateTestUser(tenant.Id);
    var device = await testApp.App.Services.CreateTestDevice(tenant.Id);
    var deviceGroupId = Guid.NewGuid();

    await SeedAssignment(testApp, new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.User,
      PrincipalId = user.Id,
      PermissionName = PermissionNames.DeviceRead,
      Effect = PermissionEffect.Allow,
      ScopeKind = PermissionScopeKind.DeviceGroup,
      ScopeId = deviceGroupId,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });

    var evaluator = GetEvaluator(testApp);
    var principal = CreateUserPrincipal(user.Id, tenant.Id);
    var resource = new ResourceDescriptor(PermissionScopeKind.Device, device.Id, tenant.Id);

    var result = await evaluator.Evaluate(principal, PermissionNames.DeviceRead, resource, TestContext.Current.CancellationToken);

    Assert.False(result.Allowed);
    Assert.Contains("default deny", result.DenialReason);
  }

  [Fact]
  public async Task DeviceGroupScopeDeny_OverridesTenantAllow()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var user = await testApp.App.Services.CreateTestUser(tenant.Id);
    var device = await testApp.App.Services.CreateTestDevice(tenant.Id);
    var deviceGroupId = Guid.NewGuid();

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
      ScopeKind = PermissionScopeKind.DeviceGroup,
      ScopeId = deviceGroupId,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });

    var evaluator = GetEvaluator(testApp);
    var principal = CreateUserPrincipal(user.Id, tenant.Id);
    var resource = new ResourceDescriptor(PermissionScopeKind.Device, device.Id, tenant.Id, DeviceGroupIds: [deviceGroupId]);

    var result = await evaluator.Evaluate(principal, PermissionNames.DeviceRead, resource, TestContext.Current.CancellationToken);

    Assert.False(result.Allowed);
    Assert.Contains("Explicit deny", result.DenialReason);
  }

  [Fact]
  public async Task DirectAllow_WhenAssignmentExists_Allows()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var user = await testApp.App.Services.CreateTestUser(tenant.Id);
    var device = await testApp.App.Services.CreateTestDevice(tenant.Id);

    await SeedAssignment(testApp, new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.User,
      PrincipalId = user.Id,
      PermissionName = PermissionNames.DeviceRead,
      Effect = PermissionEffect.Allow,
      ScopeKind = PermissionScopeKind.Device,
      ScopeId = device.Id,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });

    var evaluator = GetEvaluator(testApp);
    var principal = CreateUserPrincipal(user.Id, tenant.Id);
    var resource = new ResourceDescriptor(PermissionScopeKind.Device, device.Id, tenant.Id);

    var result = await evaluator.Evaluate(principal, PermissionNames.DeviceRead, resource, TestContext.Current.CancellationToken);

    Assert.True(result.Allowed);
    Assert.Equal("Direct", result.MatchedRuleSource);
  }

  [Fact]
  public async Task DisabledAssignment_IsIgnored()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var user = await testApp.App.Services.CreateTestUser(tenant.Id);
    var device = await testApp.App.Services.CreateTestDevice(tenant.Id);

    await SeedAssignment(testApp, new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.User,
      PrincipalId = user.Id,
      PermissionName = PermissionNames.DeviceRead,
      Effect = PermissionEffect.Allow,
      ScopeKind = PermissionScopeKind.Device,
      ScopeId = device.Id,
      OwningTenantId = tenant.Id,
      IsEnabled = false
    });

    var evaluator = GetEvaluator(testApp);
    var principal = CreateUserPrincipal(user.Id, tenant.Id);
    var resource = new ResourceDescriptor(PermissionScopeKind.Device, device.Id, tenant.Id);

    var result = await evaluator.Evaluate(principal, PermissionNames.DeviceRead, resource, TestContext.Current.CancellationToken);

    Assert.False(result.Allowed);
    Assert.Contains("default deny", result.DenialReason);
  }

  [Fact]
  public async Task GetEffectivePermissionNames_DenyOverridesAllow()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var user = await testApp.App.Services.CreateTestUser(tenant.Id);

    await SeedAssignment(testApp, new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.User,
      PrincipalId = user.Id,
      PermissionName = PermissionNames.TenantCustomersRead,
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
      PermissionName = PermissionNames.TenantCustomersRead,
      Effect = PermissionEffect.Deny,
      ScopeKind = PermissionScopeKind.Tenant,
      ScopeId = tenant.Id,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });

    var evaluator = GetEvaluator(testApp);
    var principal = CreateUserPrincipal(user.Id, tenant.Id);

    var result = await evaluator.GetEffectivePermissionNames(principal, TestContext.Current.CancellationToken);

    Assert.DoesNotContain(PermissionNames.TenantCustomersRead, result);
  }

  [Fact]
  public async Task GetEffectivePermissionNames_IncludesDirectAllow()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var user = await testApp.App.Services.CreateTestUser(tenant.Id);

    await SeedAssignment(testApp, new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.User,
      PrincipalId = user.Id,
      PermissionName = PermissionNames.TenantCustomersRead,
      Effect = PermissionEffect.Allow,
      ScopeKind = PermissionScopeKind.Tenant,
      ScopeId = tenant.Id,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });

    var evaluator = GetEvaluator(testApp);
    var principal = CreateUserPrincipal(user.Id, tenant.Id);

    var result = await evaluator.GetEffectivePermissionNames(principal, TestContext.Current.CancellationToken);

    Assert.Contains(PermissionNames.TenantCustomersRead, result);
  }

  [Fact]
  public async Task GetEffectivePermissionNames_IncludesUserGroupAllow()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var user = await testApp.App.Services.CreateTestUser(tenant.Id);

    var groupId = Guid.NewGuid();
    await SeedUserGroup(testApp, groupId, tenant.Id, user.Id);

    await SeedAssignment(testApp, new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.UserGroup,
      PrincipalId = groupId,
      PermissionName = PermissionNames.TenantUserGroupsRead,
      Effect = PermissionEffect.Allow,
      ScopeKind = PermissionScopeKind.Tenant,
      ScopeId = tenant.Id,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });

    var evaluator = GetEvaluator(testApp);
    var principal = CreateUserPrincipal(user.Id, tenant.Id);

    var result = await evaluator.GetEffectivePermissionNames(principal, TestContext.Current.CancellationToken);

    Assert.Contains(PermissionNames.TenantUserGroupsRead, result);
  }

  [Fact]
  public async Task LogonTokenGrants_ForRecipientWithNoPermissions_Allows()
  {
    // The recipient (e.g., an external/transient user) has no permissions of their own.
    // The logon token's device grants are authoritative and still allow access.
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var user = await testApp.App.Services.CreateTestUser(tenant.Id);
    var device = await testApp.App.Services.CreateTestDevice(tenant.Id);
    var tokenId = Guid.NewGuid();

    await SeedAssignment(testApp, new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.LogonToken,
      PrincipalId = tokenId,
      PermissionName = PermissionNames.DeviceRemoteControlConnect,
      Effect = PermissionEffect.Allow,
      ScopeKind = PermissionScopeKind.Device,
      ScopeId = device.Id,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });

    var evaluator = GetEvaluator(testApp);
    var principal = CreateUserPrincipal(user.Id, tenant.Id,
      credentialId: tokenId,
      credentialType: PrincipalClaimTypes.LogonTokenCredentialType,
      deviceScopeId: device.Id);
    var resource = new ResourceDescriptor(PermissionScopeKind.Device, device.Id, tenant.Id);

    var result = await evaluator.Evaluate(principal, PermissionNames.DeviceRemoteControlConnect, resource, TestContext.Current.CancellationToken);

    Assert.True(result.Allowed);
    Assert.Equal("LogonTokenGrant", result.MatchedRuleSource);
  }

  [Fact]
  public async Task LogonTokenGrants_WhenDeviceScopeMismatch_Denies()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var user = await testApp.App.Services.CreateTestUser(tenant.Id);
    var deviceA = await testApp.App.Services.CreateTestDevice(tenant.Id);
    var deviceB = await testApp.App.Services.CreateTestDevice(tenant.Id);
    var tokenId = Guid.NewGuid();

    await SeedAssignment(testApp, new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.User,
      PrincipalId = user.Id,
      PermissionName = PermissionNames.DeviceRemoteControlConnect,
      Effect = PermissionEffect.Allow,
      ScopeKind = PermissionScopeKind.Tenant,
      ScopeId = tenant.Id,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });

    await SeedAssignment(testApp, new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.LogonToken,
      PrincipalId = tokenId,
      PermissionName = PermissionNames.DeviceRemoteControlConnect,
      Effect = PermissionEffect.Allow,
      ScopeKind = PermissionScopeKind.Device,
      ScopeId = deviceA.Id,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });

    var evaluator = GetEvaluator(testApp);
    var principal = CreateUserPrincipal(user.Id, tenant.Id,
      credentialId: tokenId,
      credentialType: PrincipalClaimTypes.LogonTokenCredentialType,
      deviceScopeId: deviceB.Id);
    var resource = new ResourceDescriptor(PermissionScopeKind.Device, deviceB.Id, tenant.Id);

    var result = await evaluator.Evaluate(principal, PermissionNames.DeviceRemoteControlConnect, resource, TestContext.Current.CancellationToken);

    Assert.False(result.Allowed);
    Assert.Contains("device scope", result.DenialReason);
  }

  [Fact]
  public async Task LogonTokenGrants_WhenMatchingAllow_Allows()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var user = await testApp.App.Services.CreateTestUser(tenant.Id);
    var device = await testApp.App.Services.CreateTestDevice(tenant.Id);
    var tokenId = Guid.NewGuid();

    await SeedAssignment(testApp, new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.User,
      PrincipalId = user.Id,
      PermissionName = PermissionNames.DeviceRemoteControlConnect,
      Effect = PermissionEffect.Allow,
      ScopeKind = PermissionScopeKind.Tenant,
      ScopeId = tenant.Id,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });

    await SeedAssignment(testApp, new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.LogonToken,
      PrincipalId = tokenId,
      PermissionName = PermissionNames.DeviceRemoteControlConnect,
      Effect = PermissionEffect.Allow,
      ScopeKind = PermissionScopeKind.Device,
      ScopeId = device.Id,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });

    var evaluator = GetEvaluator(testApp);
    var principal = CreateUserPrincipal(user.Id, tenant.Id,
      credentialId: tokenId,
      credentialType: PrincipalClaimTypes.LogonTokenCredentialType,
      deviceScopeId: device.Id);
    var resource = new ResourceDescriptor(PermissionScopeKind.Device, device.Id, tenant.Id);

    var result = await evaluator.Evaluate(principal, PermissionNames.DeviceRemoteControlConnect, resource, TestContext.Current.CancellationToken);

    Assert.True(result.Allowed);
    Assert.Equal("LogonTokenGrant", result.MatchedRuleSource);
  }

  [Fact]
  public async Task LogonTokenGrants_WhenOutsideUserPermissions_Allows()
  {
    // Logon tokens carry their own device grants authoritatively and are NOT bounded by
    // the recipient's permissions (the recipient may be an external user with none). The
    // grants are set by the device.logon-token.create holder at creation time.
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var user = await testApp.App.Services.CreateTestUser(tenant.Id);
    var device = await testApp.App.Services.CreateTestDevice(tenant.Id);
    var tokenId = Guid.NewGuid();

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
      PrincipalKind = PermissionPrincipalKind.LogonToken,
      PrincipalId = tokenId,
      PermissionName = PermissionNames.DeviceDelete,
      Effect = PermissionEffect.Allow,
      ScopeKind = PermissionScopeKind.Device,
      ScopeId = device.Id,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });

    var evaluator = GetEvaluator(testApp);
    var principal = CreateUserPrincipal(user.Id, tenant.Id,
      credentialId: tokenId,
      credentialType: PrincipalClaimTypes.LogonTokenCredentialType,
      deviceScopeId: device.Id);
    var resource = new ResourceDescriptor(PermissionScopeKind.Device, device.Id, tenant.Id);

    var result = await evaluator.Evaluate(principal, PermissionNames.DeviceDelete, resource, TestContext.Current.CancellationToken);

    Assert.True(result.Allowed);
    Assert.Equal("LogonTokenGrant", result.MatchedRuleSource);
  }

  [Fact]
  public async Task LogonTokenGrants_WhenTokenHasDenyAtDeviceScope_Denies()
  {
    // The logon-token path rebuilds rules solely from the token's grants; a deny among those
    // grants must still override allows (deny-overrides-allow applies to every source).
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var user = await testApp.App.Services.CreateTestUser(tenant.Id);
    var device = await testApp.App.Services.CreateTestDevice(tenant.Id);
    var tokenId = Guid.NewGuid();

    await SeedAssignment(testApp, new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.User,
      PrincipalId = user.Id,
      PermissionName = PermissionNames.DeviceRemoteControlConnect,
      Effect = PermissionEffect.Allow,
      ScopeKind = PermissionScopeKind.Tenant,
      ScopeId = tenant.Id,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });

    await SeedAssignment(testApp, new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.LogonToken,
      PrincipalId = tokenId,
      PermissionName = PermissionNames.DeviceRemoteControlConnect,
      Effect = PermissionEffect.Allow,
      ScopeKind = PermissionScopeKind.Device,
      ScopeId = device.Id,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });

    await SeedAssignment(testApp, new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.LogonToken,
      PrincipalId = tokenId,
      PermissionName = PermissionNames.DeviceRemoteControlConnect,
      Effect = PermissionEffect.Deny,
      ScopeKind = PermissionScopeKind.Device,
      ScopeId = device.Id,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });

    var evaluator = GetEvaluator(testApp);
    var principal = CreateUserPrincipal(user.Id, tenant.Id,
      credentialId: tokenId,
      credentialType: PrincipalClaimTypes.LogonTokenCredentialType,
      deviceScopeId: device.Id);
    var resource = new ResourceDescriptor(PermissionScopeKind.Device, device.Id, tenant.Id);

    var result = await evaluator.Evaluate(principal, PermissionNames.DeviceRemoteControlConnect, resource, TestContext.Current.CancellationToken);

    Assert.False(result.Allowed);
  }

  [Fact]
  public async Task LogonTokenGrants_WhenZeroRows_Denies()
  {
    // A credential with no scope rows grants nothing.
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var user = await testApp.App.Services.CreateTestUser(tenant.Id);
    var device = await testApp.App.Services.CreateTestDevice(tenant.Id);
    var tokenId = Guid.NewGuid();

    await SeedAssignment(testApp, new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.User,
      PrincipalId = user.Id,
      PermissionName = PermissionNames.DeviceRemoteControlConnect,
      Effect = PermissionEffect.Allow,
      ScopeKind = PermissionScopeKind.Tenant,
      ScopeId = tenant.Id,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });

    var evaluator = GetEvaluator(testApp);
    var principal = CreateUserPrincipal(user.Id, tenant.Id,
      credentialId: tokenId,
      credentialType: PrincipalClaimTypes.LogonTokenCredentialType,
      deviceScopeId: device.Id);
    var resource = new ResourceDescriptor(PermissionScopeKind.Device, device.Id, tenant.Id);

    var result = await evaluator.Evaluate(principal, PermissionNames.DeviceRemoteControlConnect, resource, TestContext.Current.CancellationToken);

    Assert.False(result.Allowed);
  }

  [Fact]
  public async Task PatScopes_BoundedByUserGroupPermissions()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var user = await testApp.App.Services.CreateTestUser(tenant.Id);
    var device = await testApp.App.Services.CreateTestDevice(tenant.Id);
    var patId = Guid.NewGuid();

    var groupId = Guid.NewGuid();
    await SeedUserGroup(testApp, groupId, tenant.Id, user.Id);

    await SeedAssignment(testApp, new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.UserGroup,
      PrincipalId = groupId,
      PermissionName = PermissionNames.DeviceRead,
      Effect = PermissionEffect.Allow,
      ScopeKind = PermissionScopeKind.Tenant,
      ScopeId = tenant.Id,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });

    await SeedAssignment(testApp, new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.PersonalAccessToken,
      PrincipalId = patId,
      PermissionName = PermissionNames.DeviceRead,
      Effect = PermissionEffect.Allow,
      ScopeKind = PermissionScopeKind.Device,
      ScopeId = device.Id,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });

    var evaluator = GetEvaluator(testApp);
    var principal = CreateUserPrincipal(user.Id, tenant.Id,
      credentialId: patId,
      credentialType: PrincipalClaimTypes.PersonalAccessTokenCredentialType);
    var resource = new ResourceDescriptor(PermissionScopeKind.Device, device.Id, tenant.Id);

    var result = await evaluator.Evaluate(principal, PermissionNames.DeviceRead, resource, TestContext.Current.CancellationToken);

    Assert.True(result.Allowed);
    Assert.Equal("PatGrant", result.MatchedRuleSource);
  }

  [Fact]
  public async Task PatScopes_WhenMatchingAllow_Allows()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var user = await testApp.App.Services.CreateTestUser(tenant.Id);
    var device = await testApp.App.Services.CreateTestDevice(tenant.Id);
    var patId = Guid.NewGuid();

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
      PrincipalKind = PermissionPrincipalKind.PersonalAccessToken,
      PrincipalId = patId,
      PermissionName = PermissionNames.DeviceRead,
      Effect = PermissionEffect.Allow,
      ScopeKind = PermissionScopeKind.Device,
      ScopeId = device.Id,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });

    var evaluator = GetEvaluator(testApp);
    var principal = CreateUserPrincipal(user.Id, tenant.Id,
      credentialId: patId,
      credentialType: PrincipalClaimTypes.PersonalAccessTokenCredentialType);
    var resource = new ResourceDescriptor(PermissionScopeKind.Device, device.Id, tenant.Id);

    var result = await evaluator.Evaluate(principal, PermissionNames.DeviceRead, resource, TestContext.Current.CancellationToken);

    Assert.True(result.Allowed);
    Assert.Equal("PatGrant", result.MatchedRuleSource);
  }

  [Fact]
  public async Task PatScopes_WhenOutsideUserPermissions_Denies()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var user = await testApp.App.Services.CreateTestUser(tenant.Id);
    var device = await testApp.App.Services.CreateTestDevice(tenant.Id);
    var patId = Guid.NewGuid();

    await SeedAssignment(testApp, new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.PersonalAccessToken,
      PrincipalId = patId,
      PermissionName = PermissionNames.DeviceDelete,
      Effect = PermissionEffect.Allow,
      ScopeKind = PermissionScopeKind.Device,
      ScopeId = device.Id,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });

    var evaluator = GetEvaluator(testApp);
    var principal = CreateUserPrincipal(user.Id, tenant.Id,
      credentialId: patId,
      credentialType: PrincipalClaimTypes.PersonalAccessTokenCredentialType);
    var resource = new ResourceDescriptor(PermissionScopeKind.Device, device.Id, tenant.Id);

    var result = await evaluator.Evaluate(principal, PermissionNames.DeviceDelete, resource, TestContext.Current.CancellationToken);

    Assert.False(result.Allowed);
    Assert.Contains("outside the user's effective permissions", result.DenialReason);
  }

  [Fact]
  public async Task PatScopes_WhenRowScopeBeyondUserScope_Denies()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var user = await testApp.App.Services.CreateTestUser(tenant.Id);
    var deviceA = await testApp.App.Services.CreateTestDevice(tenant.Id);
    var deviceB = await testApp.App.Services.CreateTestDevice(tenant.Id);
    var patId = Guid.NewGuid();

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

    await SeedAssignment(testApp, new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.PersonalAccessToken,
      PrincipalId = patId,
      PermissionName = PermissionNames.DeviceRead,
      Effect = PermissionEffect.Allow,
      ScopeKind = PermissionScopeKind.Device,
      ScopeId = deviceB.Id,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });

    var evaluator = GetEvaluator(testApp);
    var principal = CreateUserPrincipal(user.Id, tenant.Id,
      credentialId: patId,
      credentialType: PrincipalClaimTypes.PersonalAccessTokenCredentialType);
    var resource = new ResourceDescriptor(PermissionScopeKind.Device, deviceB.Id, tenant.Id);

    var result = await evaluator.Evaluate(principal, PermissionNames.DeviceRead, resource, TestContext.Current.CancellationToken);

    Assert.False(result.Allowed);
  }

  [Fact]
  public async Task PatScopes_WhenUserDeniedAtDeviceScope_DeniesDespiteMembershipCoverage()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var user = await testApp.App.Services.CreateTestUser(tenant.Id);
    var device = await testApp.App.Services.CreateTestDevice(tenant.Id);
    var patId = Guid.NewGuid();

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
      ScopeId = device.Id,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });

    await SeedAssignment(testApp, new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.PersonalAccessToken,
      PrincipalId = patId,
      PermissionName = PermissionNames.DeviceRead,
      Effect = PermissionEffect.Allow,
      ScopeKind = PermissionScopeKind.Device,
      ScopeId = device.Id,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });

    var evaluator = GetEvaluator(testApp);
    var principal = CreateUserPrincipal(user.Id, tenant.Id,
      credentialId: patId,
      credentialType: PrincipalClaimTypes.PersonalAccessTokenCredentialType);
    var resource = new ResourceDescriptor(PermissionScopeKind.Device, device.Id, tenant.Id);

    var result = await evaluator.Evaluate(principal, PermissionNames.DeviceRead, resource, TestContext.Current.CancellationToken);

    Assert.False(result.Allowed);
  }

  [Fact]
  public async Task PatScopes_WhenUserDeniedAtRowScope_Denies()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var user = await testApp.App.Services.CreateTestUser(tenant.Id);
    var deviceB = await testApp.App.Services.CreateTestDevice(tenant.Id);
    var patId = Guid.NewGuid();

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

    await SeedAssignment(testApp, new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.PersonalAccessToken,
      PrincipalId = patId,
      PermissionName = PermissionNames.DeviceRead,
      Effect = PermissionEffect.Allow,
      ScopeKind = PermissionScopeKind.Device,
      ScopeId = deviceB.Id,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });

    var evaluator = GetEvaluator(testApp);
    var principal = CreateUserPrincipal(user.Id, tenant.Id,
      credentialId: patId,
      credentialType: PrincipalClaimTypes.PersonalAccessTokenCredentialType);
    var resource = new ResourceDescriptor(PermissionScopeKind.Device, deviceB.Id, tenant.Id);

    var result = await evaluator.Evaluate(principal, PermissionNames.DeviceRead, resource, TestContext.Current.CancellationToken);

    Assert.False(result.Allowed);
  }

  [Fact]
  public async Task PatScopes_WhenUserHasGroupAllow_CoversDeviceRowInGroup()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var user = await testApp.App.Services.CreateTestUser(tenant.Id);
    var device = await testApp.App.Services.CreateTestDevice(tenant.Id);
    var patId = Guid.NewGuid();
    var groupId = Guid.NewGuid();

    using (var scope = testApp.App.Services.CreateScope())
    {
      await using var db = scope.ServiceProvider.GetRequiredService<AppDb>();
      db.DeviceGroups.Add(new DeviceGroup { Id = groupId, Name = $"group-{groupId:N}", TenantId = tenant.Id });
      db.DeviceGroupMembers.Add(new DeviceGroupMember { DeviceId = device.Id, DeviceGroupId = groupId });
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
      PrincipalKind = PermissionPrincipalKind.PersonalAccessToken,
      PrincipalId = patId,
      PermissionName = PermissionNames.DeviceRead,
      Effect = PermissionEffect.Allow,
      ScopeKind = PermissionScopeKind.Device,
      ScopeId = device.Id,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });

    var evaluator = GetEvaluator(testApp);
    var principal = CreateUserPrincipal(user.Id, tenant.Id,
      credentialId: patId,
      credentialType: PrincipalClaimTypes.PersonalAccessTokenCredentialType);
    var resource = new ResourceDescriptor(PermissionScopeKind.Device, device.Id, tenant.Id);

    var result = await evaluator.Evaluate(principal, PermissionNames.DeviceRead, resource, TestContext.Current.CancellationToken);

    Assert.True(result.Allowed);
    Assert.Equal("PatGrant", result.MatchedRuleSource);
  }

  [Fact]
  public async Task PatScopes_WhenZeroRows_InheritsUserPermissions()
  {
    // A PAT with no explicit scope rows acts as its owning user, inheriting the user's
    // full effective permissions.
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var user = await testApp.App.Services.CreateTestUser(tenant.Id);
    var device = await testApp.App.Services.CreateTestDevice(tenant.Id);
    var patId = Guid.NewGuid();

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

    var evaluator = GetEvaluator(testApp);
    var principal = CreateUserPrincipal(user.Id, tenant.Id,
      credentialId: patId,
      credentialType: PrincipalClaimTypes.PersonalAccessTokenCredentialType);
    var resource = new ResourceDescriptor(PermissionScopeKind.Device, device.Id, tenant.Id);

    var result = await evaluator.Evaluate(principal, PermissionNames.DeviceRead, resource, TestContext.Current.CancellationToken);

    Assert.True(result.Allowed);
  }

  [Fact]
  public async Task ServerScopedAssignment_CoversAnyTenantResource()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var user = await testApp.App.Services.CreateTestUser(tenant.Id);
    var device = await testApp.App.Services.CreateTestDevice(tenant.Id);

    await SeedAssignment(testApp, new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.User,
      PrincipalId = user.Id,
      PermissionName = PermissionNames.DeviceRead,
      Effect = PermissionEffect.Allow,
      ScopeKind = PermissionScopeKind.Server,
      ScopeId = null,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });

    var evaluator = GetEvaluator(testApp);
    var principal = CreateUserPrincipal(user.Id, tenant.Id);
    var resource = new ResourceDescriptor(PermissionScopeKind.Device, device.Id, tenant.Id);

    var result = await evaluator.Evaluate(principal, PermissionNames.DeviceRead, resource, TestContext.Current.CancellationToken);

    Assert.True(result.Allowed);
    Assert.Equal("Direct", result.MatchedRuleSource);
  }

  [Fact]
  public async Task ServerScopeDeny_OverridesTenantScopeAllow()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var user = await testApp.App.Services.CreateTestUser(tenant.Id);
    var device = await testApp.App.Services.CreateTestDevice(tenant.Id);

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
      ScopeKind = PermissionScopeKind.Server,
      ScopeId = null,
      IsEnabled = true
    });

    var evaluator = GetEvaluator(testApp);
    var principal = CreateUserPrincipal(user.Id, tenant.Id);
    var resource = new ResourceDescriptor(PermissionScopeKind.Device, device.Id, tenant.Id);

    var result = await evaluator.Evaluate(principal, PermissionNames.DeviceRead, resource, TestContext.Current.CancellationToken);

    Assert.False(result.Allowed);
  }

  [Fact]
  public async Task ServerServiceAccount_WithAllAssignmentsDisabled_DeniesInsteadOfBypass()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var device = await testApp.App.Services.CreateTestDevice(tenant.Id);
    var serviceAccountId = Guid.NewGuid();

    await SeedAssignment(testApp, new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.ServiceAccount,
      PrincipalId = serviceAccountId,
      PermissionName = PermissionNames.DeviceRead,
      Effect = PermissionEffect.Allow,
      ScopeKind = PermissionScopeKind.Device,
      ScopeId = device.Id,
      IsEnabled = false
    });

    var evaluator = GetEvaluator(testApp);
    var principal = new PrincipalDescriptor(
      PrincipalClaimTypes.ServerServiceAccount,
      serviceAccountId,
      TenantId: null,
      AuthMethod: PrincipalClaimTypes.ServiceAccountCredentialMethod);
    var resource = new ResourceDescriptor(PermissionScopeKind.Device, device.Id, tenant.Id);

    var result = await evaluator.Evaluate(principal, PermissionNames.DeviceRead, resource, TestContext.Current.CancellationToken);

    Assert.False(result.Allowed);
  }

  [Fact]
  public async Task ServerServiceAccount_WithAssignments_EvaluatesNormally()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var device = await testApp.App.Services.CreateTestDevice(tenant.Id);
    var serviceAccountId = Guid.NewGuid();

    await SeedAssignment(testApp, new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.ServiceAccount,
      PrincipalId = serviceAccountId,
      PermissionName = PermissionNames.DeviceRead,
      Effect = PermissionEffect.Allow,
      ScopeKind = PermissionScopeKind.Device,
      ScopeId = device.Id,
      IsEnabled = true
    });

    var evaluator = GetEvaluator(testApp);
    var principal = new PrincipalDescriptor(
      PrincipalClaimTypes.ServerServiceAccount,
      serviceAccountId,
      TenantId: null,
      AuthMethod: PrincipalClaimTypes.ServiceAccountCredentialMethod);

    var allowedResource = new ResourceDescriptor(PermissionScopeKind.Device, device.Id, tenant.Id);
    var allowedResult = await evaluator.Evaluate(principal, PermissionNames.DeviceRead, allowedResource, TestContext.Current.CancellationToken);
    Assert.True(allowedResult.Allowed);

    var otherDevice = await testApp.App.Services.CreateTestDevice(tenant.Id);
    var deniedResource = new ResourceDescriptor(PermissionScopeKind.Device, otherDevice.Id, tenant.Id);
    var deniedResult = await evaluator.Evaluate(principal, PermissionNames.DeviceRead, deniedResource, TestContext.Current.CancellationToken);
    Assert.False(deniedResult.Allowed);
  }

  [Fact]
  public async Task ServerServiceAccount_WithNoAssignments_Bypasses()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var serviceAccountId = Guid.NewGuid();

    var evaluator = GetEvaluator(testApp);
    var principal = new PrincipalDescriptor(
      PrincipalClaimTypes.ServerServiceAccount,
      serviceAccountId,
      TenantId: null,
      AuthMethod: PrincipalClaimTypes.ServiceAccountCredentialMethod);
    var resource = new ResourceDescriptor(PermissionScopeKind.Device, Guid.NewGuid());

    var result = await evaluator.Evaluate(principal, PermissionNames.DeviceDelete, resource, TestContext.Current.CancellationToken);

    Assert.True(result.Allowed);
    Assert.Equal("server-service-account-bypass", result.MatchedRuleSource);
  }

  [Fact]
  public async Task TenantIsolation_WhenAssignmentInDifferentTenant_Denies()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenantA = await testApp.App.Services.CreateTestTenant("Tenant A");
    var tenantB = await testApp.App.Services.CreateTestTenant("Tenant B");
    var userA = await testApp.App.Services.CreateTestUser(tenantA.Id);
    var deviceB = await testApp.App.Services.CreateTestDevice(tenantB.Id);

    await SeedAssignment(testApp, new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.User,
      PrincipalId = userA.Id,
      PermissionName = PermissionNames.DeviceRead,
      Effect = PermissionEffect.Allow,
      ScopeKind = PermissionScopeKind.Tenant,
      ScopeId = tenantA.Id,
      OwningTenantId = tenantA.Id,
      IsEnabled = true
    });

    var evaluator = GetEvaluator(testApp);
    var principal = CreateUserPrincipal(userA.Id, tenantA.Id);
    var resource = new ResourceDescriptor(PermissionScopeKind.Device, deviceB.Id, tenantB.Id);

    var result = await evaluator.Evaluate(principal, PermissionNames.DeviceRead, resource, TestContext.Current.CancellationToken);

    Assert.False(result.Allowed);
  }

  [Fact]
  public async Task TenantScopeAssignment_CoversDeviceInTenant()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var user = await testApp.App.Services.CreateTestUser(tenant.Id);
    var device = await testApp.App.Services.CreateTestDevice(tenant.Id);

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

    var evaluator = GetEvaluator(testApp);
    var principal = CreateUserPrincipal(user.Id, tenant.Id);
    var resource = new ResourceDescriptor(PermissionScopeKind.Device, device.Id, tenant.Id);

    var result = await evaluator.Evaluate(principal, PermissionNames.DeviceRead, resource, TestContext.Current.CancellationToken);

    Assert.True(result.Allowed);
    Assert.Equal("Direct", result.MatchedRuleSource);
  }

  [Fact]
  public async Task TenantServiceAccount_WithAssignment_Allows()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var device = await testApp.App.Services.CreateTestDevice(tenant.Id);
    var serviceAccountId = Guid.NewGuid();

    await SeedAssignment(testApp, new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.ServiceAccount,
      PrincipalId = serviceAccountId,
      PermissionName = PermissionNames.DeviceRead,
      Effect = PermissionEffect.Allow,
      ScopeKind = PermissionScopeKind.Tenant,
      ScopeId = tenant.Id,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });

    var evaluator = GetEvaluator(testApp);
    var principal = new PrincipalDescriptor(
      PrincipalClaimTypes.TenantServiceAccount,
      serviceAccountId,
      TenantId: tenant.Id,
      AuthMethod: PrincipalClaimTypes.ServiceAccountCredentialMethod);
    var resource = new ResourceDescriptor(PermissionScopeKind.Device, device.Id, tenant.Id);

    var result = await evaluator.Evaluate(principal, PermissionNames.DeviceRead, resource, TestContext.Current.CancellationToken);

    Assert.True(result.Allowed);
    Assert.Equal("Direct", result.MatchedRuleSource);
  }

  [Fact]
  public async Task UserGroupAllow_WhenGroupHasAssignment_Allows()
  {
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutput);
    var tenant = await testApp.App.Services.CreateTestTenant();
    var user = await testApp.App.Services.CreateTestUser(tenant.Id);
    var device = await testApp.App.Services.CreateTestDevice(tenant.Id);

    var groupId = Guid.NewGuid();
    await SeedUserGroup(testApp, groupId, tenant.Id, user.Id);

    await SeedAssignment(testApp, new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.UserGroup,
      PrincipalId = groupId,
      PermissionName = PermissionNames.DeviceRead,
      Effect = PermissionEffect.Allow,
      ScopeKind = PermissionScopeKind.Device,
      ScopeId = device.Id,
      OwningTenantId = tenant.Id,
      IsEnabled = true
    });

    var evaluator = GetEvaluator(testApp);
    var principal = CreateUserPrincipal(user.Id, tenant.Id);
    var resource = new ResourceDescriptor(PermissionScopeKind.Device, device.Id, tenant.Id);

    var result = await evaluator.Evaluate(principal, PermissionNames.DeviceRead, resource, TestContext.Current.CancellationToken);

    Assert.True(result.Allowed);
    Assert.Equal("UserGroup", result.MatchedRuleSource);
  }

  private static PrincipalDescriptor CreateUserPrincipal(
    Guid userId,
    Guid tenantId,
    Guid? credentialId = null,
    string? credentialType = null,
    Guid? deviceScopeId = null)
  {
    return new PrincipalDescriptor(
      PrincipalClaimTypes.User,
      userId,
      tenantId,
      AuthMethod: credentialType is not null
        ? (credentialType == PrincipalClaimTypes.PersonalAccessTokenCredentialType
          ? PrincipalClaimTypes.PersonalAccessTokenMethod
          : PrincipalClaimTypes.LogonTokenMethod)
        : "cookie",
      CredentialId: credentialId,
      CredentialType: credentialType,
      DeviceScopeId: deviceScopeId);
  }

  private static IPermissionEvaluator GetEvaluator(TestApp testApp)
  {
    return testApp.App.Services.GetRequiredService<IPermissionEvaluator>();
  }

  private static async Task SeedAssignment(TestApp testApp, PermissionAssignment assignment)
  {
    using var scope = testApp.App.Services.CreateScope();
    await using var db = scope.ServiceProvider.GetRequiredService<AppDb>();
    db.PermissionAssignments.Add(assignment);
    await db.SaveChangesAsync();
  }

  private static async Task SeedUserGroup(TestApp testApp, Guid groupId, Guid tenantId, Guid userId)
  {
    using var scope = testApp.App.Services.CreateScope();
    await using var db = scope.ServiceProvider.GetRequiredService<AppDb>();
    db.UserGroups.Add(new UserGroup { Id = groupId, Name = $"group-{groupId:N}", TenantId = tenantId });
    db.UserGroupMembers.Add(new UserGroupMember { UserGroupId = groupId, UserId = userId });
    await db.SaveChangesAsync();
  }
}
