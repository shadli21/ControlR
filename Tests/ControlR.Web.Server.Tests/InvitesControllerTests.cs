using System.Net;
using System.Net.Http.Json;
using ControlR.Web.Server.Authn;
using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Data.Entities;
using ControlR.Web.Server.Services;
using ControlR.Web.Server.Tests.Helpers;
using Microsoft.Extensions.DependencyInjection;

namespace ControlR.Web.Server.Tests;

public class InvitesControllerTests(ITestOutputHelper testOutput)
{
  private readonly ITestOutputHelper _testOutput = testOutput;

  [Fact]
  public async Task GetAll_ReadOnlyUser_DoesNotExposeActivationCode()
  {
    using var testServer = await TestWebServerBuilder.CreateTestServer(_testOutput);
    var services = testServer.Services;

    var tenant = await services.CreateTestTenant();
    await services.CreateTestUser(tenant.Id, email: $"seed-{Guid.NewGuid():N}@t.local");

    var invitesProvider = services.GetRequiredService<ITenantInvitesProvider>();
    var origin = new Uri("https://test.example.com");
    var createResult = await invitesProvider.CreateInvite(
      "invitee@t.local", tenant.Id, origin, TestContext.Current.CancellationToken);
    Assert.True(createResult.IsSuccess);
    var activationCode = createResult.Value.InviteUrl.Segments[^1];

    var readOnlyUser = await services.CreateTestUser(tenant.Id, $"reader-{Guid.NewGuid():N}@t.local");
    await SeedAssignment(testServer, PermissionAssignment.CreateGrant(
      PermissionPrincipalKind.User,
      readOnlyUser.Id,
      PermissionNames.TenantUsersRead,
      PermissionScopeKind.Tenant,
      tenant.Id,
      tenant.Id,
      "test",
      readOnlyUser.Id.ToString()));

    using var readerClient = await CreatePatClient(testServer, readOnlyUser.Id);
    var readerResponse = await readerClient.GetAsync(
      HttpConstants.Internal.InvitesEndpoint, TestContext.Current.CancellationToken);
    Assert.Equal(HttpStatusCode.OK, readerResponse.StatusCode);

    var readerInvites = await readerResponse.Content.ReadFromJsonAsync<InternalDtos.TenantInviteResponseDto[]>(
      TestContext.Current.CancellationToken);
    Assert.NotNull(readerInvites);
    Assert.NotEmpty(readerInvites);
    Assert.DoesNotContain(readerInvites, x => x.InviteUrl.ToString().Contains(activationCode));

    var writeUser = await services.CreateTestUser(
      tenant.Id, $"writer-{Guid.NewGuid():N}@t.local", PermissionPresets.TenantAdministrator);

    using var writerClient = await CreatePatClient(testServer, writeUser.Id);
    var writerResponse = await writerClient.GetAsync(
      HttpConstants.Internal.InvitesEndpoint, TestContext.Current.CancellationToken);
    Assert.Equal(HttpStatusCode.OK, writerResponse.StatusCode);

    var writerInvites = await writerResponse.Content.ReadFromJsonAsync<InternalDtos.TenantInviteResponseDto[]>(
      TestContext.Current.CancellationToken);
    Assert.NotNull(writerInvites);
    Assert.Contains(writerInvites, x => x.InviteUrl.ToString().Contains(activationCode));
  }

  private static async Task<HttpClient> CreatePatClient(TestWebServer testServer, Guid userId)
  {
    var patManager = testServer.Services.GetRequiredService<IPersonalAccessTokenManager>();
    var patResult = await patManager.CreateToken(
      new InternalDtos.CreatePersonalAccessTokenRequestDto("Invites Test PAT"), userId);
    Assert.True(patResult.IsSuccess);

    var client = testServer.Factory.CreateClient();
    client.DefaultRequestHeaders.Add(
      PersonalAccessTokenAuthenticationSchemeOptions.DefaultHeaderName,
      patResult.Value.PlainTextToken);
    return client;
  }

  private static async Task SeedAssignment(TestWebServer testServer, PermissionAssignment assignment)
  {
    using var scope = testServer.Services.CreateScope();
    await using var db = scope.ServiceProvider.GetRequiredService<ControlR.Web.Server.Data.AppDb>();
    db.PermissionAssignments.Add(assignment);
    await db.SaveChangesAsync(TestContext.Current.CancellationToken);
  }
}
