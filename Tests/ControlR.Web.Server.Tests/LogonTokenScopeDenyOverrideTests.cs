using System.Net;
using System.Net.Http.Json;
using ControlR.Web.Server.Authn;
using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Data;
using ControlR.Web.Server.Data.Entities;
using ControlR.Web.Server.Services;
using ControlR.Web.Server.Tests.Helpers;
using Microsoft.Extensions.DependencyInjection;

namespace ControlR.Web.Server.Tests;

public class LogonTokenScopeDenyOverrideTests(ITestOutputHelper testOutput)
{
  private readonly ITestOutputHelper _testOutput = testOutput;

  [Fact]
  public async Task CreateLogonToken_ScopeGrantingDeniedPermission_ReturnsBadRequest()
  {
    using var testServer = await TestWebServerBuilder.CreateTestServer(_testOutput);
    using var httpClient = testServer.Factory.CreateClient();

    var tenant = await testServer.Services.CreateTestTenant();
    await testServer.Services.CreateTestUser(tenant.Id, email: $"seed-{Guid.NewGuid():N}@t.local");
    var user = await testServer.Services.CreateTestUser(
      tenant.Id, $"denied-{Guid.NewGuid():N}@t.local", PermissionPresets.DeviceSuperUser);
    var device = await testServer.Services.CreateTestDevice(tenant.Id);

    using (var scope = testServer.Services.CreateScope())
    {
      await using var db = scope.ServiceProvider.GetRequiredService<AppDb>();
      db.PermissionAssignments.Add(new PermissionAssignment
      {
        PrincipalKind = PermissionPrincipalKind.User,
        PrincipalId = user.Id,
        PermissionName = PermissionNames.DeviceRead,
        Effect = PermissionEffect.Deny,
        ScopeKind = PermissionScopeKind.Tenant,
        ScopeId = tenant.Id,
        IsEnabled = true,
        OwningTenantId = tenant.Id,
        CreatedByPrincipalType = "user",
        CreatedByPrincipalId = user.Id.ToString()
      });
      await db.SaveChangesAsync(TestContext.Current.CancellationToken);
    }

    var patManager = testServer.Services.GetRequiredService<IPersonalAccessTokenManager>();
    var patResult = await patManager.CreateToken(
      new InternalDtos.CreatePersonalAccessTokenRequestDto("Deny Override Test PAT"), user.Id);
    Assert.True(patResult.IsSuccess, $"PAT creation failed: {patResult.Reason}");

    httpClient.DefaultRequestHeaders.Add(
      PersonalAccessTokenAuthenticationSchemeOptions.DefaultHeaderName,
      patResult.Value.PlainTextToken);

    var request = new InternalDtos.LogonTokenRequestDto(
      device.Id,
      ExpirationMinutes: 15,
      Scopes: [new InternalDtos.CredentialScopeDto(PermissionNames.DeviceRead, PermissionScopeKind.Device, device.Id)]);

    var response = await httpClient.PostAsJsonAsync(
      HttpConstants.Internal.LogonTokensEndpoint, request, TestContext.Current.CancellationToken);

    Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
  }
}
