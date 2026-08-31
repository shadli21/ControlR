using ControlR.Web.Server.Data;
using ControlR.Web.Server.Data.Entities;
using ControlR.Web.Server.Services.Authorization.Capabilities;
using ControlR.Web.Server.Tests.Helpers;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace ControlR.Web.Server.Tests;

public class DeviceAuthorizationServiceTests(ITestOutputHelper testOutput)
{
  private readonly ITestOutputHelper _testOutputHelper = testOutput;

  [Fact]
  public async Task DeviceAuthorizationService_CanInstallAgentOnDevice()
  {
    // Arrange
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutputHelper);
    using var scope = testApp.App.Services.CreateScope();
    var authorizationService = scope.ServiceProvider.GetRequiredService<IDeviceAuthorizationService>();
    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<AppUser>>();
    var db = scope.ServiceProvider.GetRequiredService<AppDb>();

    var tenant = await testApp.Services.CreateTestTenant();
    var otherTenant = await testApp.Services.CreateTestTenant("Other Tenant");
    var tenantId = tenant.Id;
    var otherTenantId = otherTenant.Id;

    // Create a test device
    var device = new Device
    {
      Id = Guid.NewGuid(),
      Name = "Test Device",
      TenantId = tenantId
    };
    db.Devices.Add(device);

    // Create users with different permissions
    var installerUser = new AppUser
    {
      Id = Guid.NewGuid(),
      UserName = "installer@example.com",
      NormalizedUserName = "INSTALLER@EXAMPLE.COM",
      Email = "installer@example.com",
      NormalizedEmail = "INSTALLER@EXAMPLE.COM",
      EmailConfirmed = true,
      TenantId = tenantId
    };

    var installerUserResult = await userManager.CreateAsync(installerUser);
    Assert.True(installerUserResult.Succeeded);

    var nonInstallerUser = new AppUser
    {
      Id = Guid.NewGuid(),
      UserName = "regular@example.com",
      NormalizedUserName = "REGULAR@EXAMPLE.COM",
      Email = "regular@example.com",
      NormalizedEmail = "REGULAR@EXAMPLE.COM",
      EmailConfirmed = true,
      TenantId = tenantId
    };

    var nonInstallerUserResult = await userManager.CreateAsync(nonInstallerUser);
    Assert.True(nonInstallerUserResult.Succeeded);

    var differentTenantUser = new AppUser
    {
      Id = Guid.NewGuid(),
      UserName = "different@example.com",
      NormalizedUserName = "DIFFERENT@EXAMPLE.COM",
      Email = "different@example.com",
      NormalizedEmail = "DIFFERENT@EXAMPLE.COM",
      EmailConfirmed = true,
      TenantId = otherTenantId
    };

    var differentTenantUserResult = await userManager.CreateAsync(differentTenantUser);
    Assert.True(differentTenantUserResult.Succeeded);

    await db.SaveChangesAsync(TestContext.Current.CancellationToken);

    db.PermissionAssignments.AddRange(
      new PermissionAssignment
      {
        PrincipalKind = PermissionPrincipalKind.User,
        PrincipalId = installerUser.Id,
        PermissionName = PermissionNames.AgentInstall,
        Effect = PermissionEffect.Allow,
        ScopeKind = PermissionScopeKind.Tenant,
        ScopeId = tenantId,
        IsEnabled = true,
        OwningTenantId = tenantId
      },
      new PermissionAssignment
      {
        PrincipalKind = PermissionPrincipalKind.User,
        PrincipalId = differentTenantUser.Id,
        PermissionName = PermissionNames.AgentInstall,
        Effect = PermissionEffect.Allow,
        ScopeKind = PermissionScopeKind.Tenant,
        ScopeId = otherTenantId,
        IsEnabled = true,
        OwningTenantId = otherTenantId
      });
    await db.SaveChangesAsync(TestContext.Current.CancellationToken);

    // Act & Assert

    // Installer user from same tenant should be able to install
    var canInstall = await authorizationService.CanInstallAgentOnDevice(installerUser, device);
    Assert.True(canInstall);

    // Non-installer user from same tenant should not be able to install
    var canNonInstallerInstall = await authorizationService.CanInstallAgentOnDevice(nonInstallerUser, device);
    Assert.False(canNonInstallerInstall);

    // User from different tenant should not be able to install
    var canDifferentTenantInstall = await authorizationService.CanInstallAgentOnDevice(differentTenantUser, device);
    Assert.False(canDifferentTenantInstall);

    // A device-scoped deny must override a tenant-scoped allow on the specific device
    db.PermissionAssignments.Add(new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.User,
      PrincipalId = installerUser.Id,
      PermissionName = PermissionNames.AgentInstall,
      Effect = PermissionEffect.Deny,
      ScopeKind = PermissionScopeKind.Device,
      ScopeId = device.Id,
      IsEnabled = true,
      OwningTenantId = tenantId
    });
    await db.SaveChangesAsync(TestContext.Current.CancellationToken);

    var canInstallAfterDeviceDeny = await authorizationService.CanInstallAgentOnDevice(installerUser, device);
    Assert.False(canInstallAfterDeviceDeny);
  }

  [Fact]
  public async Task DeviceAuthorizationService_CanInstallAgentOnDevice_ServiceAccount()
  {
    // Arrange
    await using var testApp = await TestAppBuilder.CreateTestApp(_testOutputHelper);
    using var scope = testApp.App.Services.CreateScope();
    var authorizationService = scope.ServiceProvider.GetRequiredService<IDeviceAuthorizationService>();
    var db = scope.ServiceProvider.GetRequiredService<AppDb>();

    var tenant = await testApp.Services.CreateTestTenant();
    var otherTenant = await testApp.Services.CreateTestTenant("Other Tenant");
    var tenantId = tenant.Id;
    var otherTenantId = otherTenant.Id;

    var serviceAccount = new ServiceAccount
    {
      Id = Guid.NewGuid(),
      Name = "installer-account",
      Kind = ServiceAccountKind.Tenant,
      TenantId = tenantId,
      IsEnabled = true
    };

    var device = new Device
    {
      Id = Guid.NewGuid(),
      Name = "Test Device",
      TenantId = tenantId
    };

    db.ServiceAccounts.Add(serviceAccount);
    db.Devices.Add(device);
    db.PermissionAssignments.Add(new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.ServiceAccount,
      PrincipalId = serviceAccount.Id,
      PermissionName = PermissionNames.AgentInstall,
      Effect = PermissionEffect.Allow,
      ScopeKind = PermissionScopeKind.Tenant,
      ScopeId = tenantId,
      IsEnabled = true,
      OwningTenantId = tenantId
    });
    await db.SaveChangesAsync(TestContext.Current.CancellationToken);

    // Act & Assert

    // Tenant service account with tenant-scoped agent install should be able to install
    var canInstall = await authorizationService.CanInstallAgentOnDevice(serviceAccount, device);
    Assert.True(canInstall);

    // A device-scoped deny must block the install on that specific device
    db.PermissionAssignments.Add(new PermissionAssignment
    {
      PrincipalKind = PermissionPrincipalKind.ServiceAccount,
      PrincipalId = serviceAccount.Id,
      PermissionName = PermissionNames.AgentInstall,
      Effect = PermissionEffect.Deny,
      ScopeKind = PermissionScopeKind.Device,
      ScopeId = device.Id,
      IsEnabled = true,
      OwningTenantId = tenantId
    });
    await db.SaveChangesAsync(TestContext.Current.CancellationToken);

    var canInstallAfterDeny = await authorizationService.CanInstallAgentOnDevice(serviceAccount, device);
    Assert.False(canInstallAfterDeny);

    // Unrestricted server accounts follow the central cross-tenant bypass.
    var serverAccount = new ServiceAccount
    {
      Id = Guid.NewGuid(),
      Name = "server-account",
      Kind = ServiceAccountKind.Server,
      TenantId = null,
      IsEnabled = true,
      AccessMode = ServiceAccountAccessMode.Unrestricted
    };
    db.ServiceAccounts.Add(serverAccount);
    await db.SaveChangesAsync(TestContext.Current.CancellationToken);

    var canServerInstall = await authorizationService.CanInstallAgentOnDevice(serverAccount, device);
    Assert.True(canServerInstall);

    // A restricted account is constrained to its explicit scopes, even outside its grants.
    serverAccount.AccessMode = ServiceAccountAccessMode.Restricted;
    db.PermissionAssignments.Add(PermissionAssignment.CreateGrant(
      PermissionPrincipalKind.ServiceAccount,
      serverAccount.Id,
      PermissionNames.AgentInstall,
      PermissionScopeKind.Device,
      Guid.NewGuid(),
      tenantId,
      "test",
      serverAccount.Id.ToString()));
    await db.SaveChangesAsync(TestContext.Current.CancellationToken);

    var canScopedServerInstall = await authorizationService.CanInstallAgentOnDevice(serverAccount, device);
    Assert.False(canScopedServerInstall);

    // Accounts from another tenant cannot reach this device
    var otherTenantAccount = new ServiceAccount
    {
      Id = Guid.NewGuid(),
      Name = "other-tenant-account",
      Kind = ServiceAccountKind.Tenant,
      TenantId = otherTenantId,
      IsEnabled = true
    };
    db.ServiceAccounts.Add(otherTenantAccount);
    await db.SaveChangesAsync(TestContext.Current.CancellationToken);

    var canOtherInstall = await authorizationService.CanInstallAgentOnDevice(otherTenantAccount, device);
    Assert.False(canOtherInstall);
  }
}
