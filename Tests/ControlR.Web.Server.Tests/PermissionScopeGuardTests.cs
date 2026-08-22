using System.Net;
using System.Net.Http.Json;
using ControlR.Web.Server.Authn;
using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Authz.Policies;
using ControlR.Web.Server.Services;
using ControlR.Web.Server.Tests.Helpers;
using Microsoft.Extensions.DependencyInjection;

namespace ControlR.Web.Server.Tests;

public class PermissionScopeGuardTests(ITestOutputHelper testOutput)
{
  [Theory]
  [InlineData(PermissionNames.ServerAdmin, PermissionScopeKind.Server)]
  [InlineData(PermissionNames.TenantPermissionsWrite, PermissionScopeKind.Tenant)]
  [InlineData(PermissionNames.DeviceRead, PermissionScopeKind.Tenant)]
  [InlineData(PermissionNames.UserGroupAssignUsers, PermissionScopeKind.Tenant)]
  [InlineData(PermissionNames.DeviceGroupAssignDevices, PermissionScopeKind.Tenant)]
  [InlineData(PermissionNames.DeviceLogonTokenCreate, PermissionScopeKind.Tenant)]
  public void Catalog_GetBroadestLegalScope_ResolvesToExpectedScope(string permissionName, PermissionScopeKind expected)
  {
    Assert.Equal(expected, PermissionCatalog.GetBroadestLegalScope(permissionName));
  }

  [Fact]
  public async Task Create_DeviceReadAtTenantScope_ReturnsOk()
  {
    var (testServer, client, tenantId, userId) = await CreateAuthenticatedAdmin();
    using var _ = testServer;

    var response = await client.PostAsJsonAsync(
      HttpConstants.Internal.PermissionAssignmentsEndpoint,
      new InternalDtos.CreatePermissionAssignmentRequestDto(
        PermissionPrincipalKind.User,
        userId,
        PermissionNames.DeviceRead,
        PermissionEffect.Allow,
        PermissionScopeKind.Tenant,
        tenantId,
        null),
      TestContext.Current.CancellationToken);

    Assert.Equal(HttpStatusCode.OK, response.StatusCode);
  }

  [Fact]
  public async Task Create_ServerAdminAtTenantScope_ReturnsBadRequest()
  {
    var (testServer, client, tenantId, userId) = await CreateAuthenticatedAdmin();
    using var _ = testServer;

    var response = await client.PostAsJsonAsync(
      HttpConstants.Internal.PermissionAssignmentsEndpoint,
      new InternalDtos.CreatePermissionAssignmentRequestDto(
        PermissionPrincipalKind.User,
        userId,
        PermissionNames.ServerAdmin,
        PermissionEffect.Allow,
        PermissionScopeKind.Tenant,
        tenantId,
        null),
      TestContext.Current.CancellationToken);

    Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
  }

  [Fact]
  public async Task Delete_AnotherPrincipalsProtectedPermission_ReturnsOk()
  {
    var (testServer, client, tenantId, _) = await CreateAuthenticatedAdmin();
    using var _ = testServer;

    var otherAdmin = await testServer.Services.CreateTestUser(
      tenantId, $"admin-{Guid.NewGuid():N}@t.local", PermissionPresets.TenantAdministrator);

    var otherAssignment = await GetAssignment(client, otherAdmin.Id, PermissionNames.TenantPermissionsWrite);

    var response = await client.DeleteAsync(
      $"{HttpConstants.Internal.PermissionAssignmentsEndpoint}/{otherAssignment.Id}",
      TestContext.Current.CancellationToken);

    Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
  }

  [Fact]
  public async Task Delete_AnotherUser_ReturnsNoContent()
  {
    var (testServer, client, tenantId, _) = await CreateAuthenticatedAdmin();
    using var _ = testServer;

    var otherUser = await testServer.Services.CreateTestUser(
      tenantId, $"user-{Guid.NewGuid():N}@t.local");

    var response = await client.DeleteAsync(
      $"{HttpConstants.Internal.UsersEndpoint}/{otherUser.Id}",
      TestContext.Current.CancellationToken);

    Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
  }

  [Fact]
  public async Task Delete_OwnLastProtectedPermission_ReturnsBadRequest()
  {
    var (testServer, client, _, userId) = await CreateAuthenticatedAdmin();
    using var _ = testServer;

    var assignment = await GetAssignment(client, userId, PermissionNames.TenantPermissionsWrite);

    var response = await client.DeleteAsync(
      $"{HttpConstants.Internal.PermissionAssignmentsEndpoint}/{assignment.Id}",
      TestContext.Current.CancellationToken);

    Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

    var stillHeld = await GetAssignment(client, userId, PermissionNames.TenantPermissionsWrite);
    Assert.NotNull(stillHeld);
  }

  [Fact]
  public async Task Delete_OwnUser_ReturnsBadRequest()
  {
    var (testServer, client, _, userId) = await CreateAuthenticatedAdmin();
    using var _ = testServer;

    var response = await client.DeleteAsync(
      $"{HttpConstants.Internal.UsersEndpoint}/{userId}",
      TestContext.Current.CancellationToken);

    Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
  }

  [Fact]
  public void DeviceResourcePolicies_AllPermissionsExistInCatalog()
  {
    foreach (var (policyName, permissionName) in DeviceResourcePolicies.PolicyToPermission)
    {
      Assert.True(
        PermissionCatalog.Exists(permissionName),
        $"Device resource policy '{policyName}' references permission '{permissionName}', which does not exist in the permission catalog.");
    }
  }

  [Fact]
  public async Task Disable_OwnLastProtectedPermission_ReturnsBadRequest()
  {
    var (testServer, client, _, userId) = await CreateAuthenticatedAdmin();
    using var _ = testServer;

    var assignment = await GetAssignment(client, userId, PermissionNames.TenantPermissionsWrite);

    var response = await client.PutAsJsonAsync(
      $"{HttpConstants.Internal.PermissionAssignmentsEndpoint}/{assignment.Id}",
      new InternalDtos.UpdatePermissionAssignmentRequestDto(
        assignment.PermissionName,
        assignment.Effect,
        assignment.ScopeKind,
        assignment.ScopeId,
        assignment.Notes,
        IsEnabled: false),
      TestContext.Current.CancellationToken);

    Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
  }

  [Fact]
  public async Task Edit_OwnLastProtectedPermissionAway_ReturnsBadRequest()
  {
    var (testServer, client, tenantId, userId) = await CreateAuthenticatedAdmin();
    using var _ = testServer;

    var assignment = await GetAssignment(client, userId, PermissionNames.TenantPermissionsWrite);

    var response = await client.PutAsJsonAsync(
      $"{HttpConstants.Internal.PermissionAssignmentsEndpoint}/{assignment.Id}",
      new InternalDtos.UpdatePermissionAssignmentRequestDto(
        PermissionNames.TenantRead,
        PermissionEffect.Allow,
        PermissionScopeKind.Tenant,
        tenantId,
        null,
        IsEnabled: true),
      TestContext.Current.CancellationToken);

    Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
  }

  [Fact]
  public void PermissionCatalog_AllPermissionsHaveLegalPresetScope()
  {
    foreach (var (permissionName, metadata) in PermissionCatalog.All)
    {
      var broadest = PermissionCatalog.GetBroadestLegalScope(permissionName);
      Assert.NotNull(broadest);
      Assert.True(
        broadest is PermissionScopeKind.Server or PermissionScopeKind.Tenant,
        $"Permission '{permissionName}' has broadest legal scope '{broadest}', which cannot be emitted by a preset.");
      Assert.Contains(broadest.Value, metadata.AllowedScopeKinds);
    }
  }

  [Fact]
  public void PermissionMetadata_AllCatalogEntriesHaveExplicitScopeKinds()
  {
    Assert.All(PermissionCatalog.All, entry =>
    {
      Assert.False(entry.Key is null or "");
      Assert.Equal(entry.Key, entry.Value.Name);
      Assert.NotEmpty(entry.Value.AllowedScopeKinds);
      Assert.Equal(
        entry.Value.AllowedScopeKinds.Length,
        entry.Value.AllowedScopeKinds.Distinct().Count());
      Assert.All(entry.Value.AllowedScopeKinds, scopeKind =>
        Assert.True(Enum.IsDefined(scopeKind)));
    });
  }

  [Fact]
  public void DevicePermissions_NeverAllowServerScope()
  {
    var devicePermissions = PermissionCatalog.All.Values
      .Where(metadata => metadata.AllowedScopeKinds.Contains(PermissionScopeKind.Device))
      .ToArray();

    Assert.NotEmpty(devicePermissions);
    Assert.All(devicePermissions, metadata =>
      Assert.DoesNotContain(PermissionScopeKind.Server, metadata.AllowedScopeKinds));
  }

  [Fact]
  public void PermissionScopeKind_AllValuesAreHandledByScopeBreadth()
  {
    var expectedKinds = Enum.GetValues<PermissionScopeKind>()
      .Except([PermissionScopeKind.Unknown, PermissionScopeKind.Server, PermissionScopeKind.Tenant,
        PermissionScopeKind.Device, PermissionScopeKind.DeviceGroup,
        PermissionScopeKind.CustomerTenant, PermissionScopeKind.UserGroup])
      .ToArray();

    Assert.Empty(expectedKinds);

    foreach (var scopeKind in Enum.GetValues<PermissionScopeKind>())
    {
      if (scopeKind == PermissionScopeKind.Unknown)
      {
        continue;
      }

      var result = PermissionScopeKinds.GetBroadestLegalScope([scopeKind]);
      Assert.Equal(scopeKind, result);
    }
  }

  [Fact]
  public void Presets_AllPermissionsResolveToBroadestSeedableScope()
  {
    // Presets must be seedable without a concrete resource target, so every preset permission
    // must resolve to a Server or Tenant scope (never a device/group/customer-specific kind).
    foreach (var (presetName, permissions) in PermissionPresets.All)
    {
      foreach (var permission in permissions)
      {
        var broadest = PermissionCatalog.GetBroadestLegalScope(permission);
        Assert.True(
          broadest is PermissionScopeKind.Server or PermissionScopeKind.Tenant,
          $"Preset '{presetName}' permission '{permission}' resolves to broadest scope '{broadest}', which is not seedable without a resource target.");
      }
    }
  }

  [Fact]
  public async Task Replace_OwnOmittingProtectedPermission_ReturnsBadRequest()
  {
    var (testServer, client, tenantId, userId) = await CreateAuthenticatedAdmin();
    using var _ = testServer;

    var response = await client.PostAsJsonAsync(
      $"{HttpConstants.Internal.PermissionAssignmentsEndpoint}/replace",
      new InternalDtos.ReplacePermissionAssignmentsRequestDto(
        PermissionPrincipalKind.User,
        userId,
        [
          new InternalDtos.CreatePermissionAssignmentRequestDto(
            PermissionPrincipalKind.User, userId, PermissionNames.TenantRead,
            PermissionEffect.Allow, PermissionScopeKind.Tenant, tenantId, null)
        ]),
      TestContext.Current.CancellationToken);

    Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
  }

  private async Task<(TestWebServer server, HttpClient client, Guid tenantId, Guid userId)> CreateAuthenticatedAdmin()
  {
    var testServer = await TestWebServerBuilder.CreateTestServer(testOutput);
    var httpClient = testServer.Factory.CreateClient();

    var tenant = await testServer.Services.CreateTestTenant();
    var user = await testServer.Services.CreateTestUser(
      tenant.Id,
      $"admin-{Guid.NewGuid():N}@t.local",
      PermissionPresets.TenantAdministrator);

    var patManager = testServer.Services.GetRequiredService<IPersonalAccessTokenManager>();
    var patResult = await patManager.CreateToken(
      new InternalDtos.CreatePersonalAccessTokenRequestDto("Scope Guard Test PAT"),
      user.Id);
    Assert.True(patResult.IsSuccess, $"PAT creation failed: {patResult.Reason}");

    httpClient.DefaultRequestHeaders.Add(
      PersonalAccessTokenAuthenticationSchemeOptions.DefaultHeaderName,
      patResult.Value.PlainTextToken);

    return (testServer, httpClient, tenant.Id, user.Id);
  }

  private async Task<InternalDtos.PermissionAssignmentDto> GetAssignment(
    HttpClient client,
    Guid principalId,
    string permissionName)
  {
    var response = await client.GetAsync(
      $"{HttpConstants.Internal.PermissionAssignmentsEndpoint}?principalKind=User&principalId={principalId}",
      TestContext.Current.CancellationToken);
    response.EnsureSuccessStatusCode();

    var assignments = await response.Content.ReadFromJsonAsync<InternalDtos.PermissionAssignmentDto[]>(
      TestContext.Current.CancellationToken);
    Assert.NotNull(assignments);

    return Assert.Single(assignments, a => a.PermissionName == permissionName);
  }
}
