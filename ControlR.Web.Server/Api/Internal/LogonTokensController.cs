using ControlR.Libraries.Api.Contracts.Constants;
using ControlR.Web.Server.Services.LogonTokens;
using Microsoft.AspNetCore.Mvc;

namespace ControlR.Web.Server.Api.Internal;

[Route(HttpConstants.Internal.LogonTokensEndpoint)]
[ApiController]
[Authorize]
[EndpointGroupName(OpenApiConstants.InternalGroupName)]
public class LogonTokensController : ControllerBase
{
  [HttpPost]
  [ProducesResponseType<InternalDtos.LogonTokenResponseDto>(StatusCodes.Status200OK)]
  [ProducesResponseType(StatusCodes.Status404NotFound)]
  public async Task<ActionResult<InternalDtos.LogonTokenResponseDto>> CreateLogonToken(
    [FromServices] AppDb appDb,
    [FromServices] ILogonTokenProvider logonTokenProvider,
    [FromServices] IAuthorizationService authorizationService,
    [FromBody] InternalDtos.LogonTokenRequestDto request)
  {
    if (!User.TryGetTenantId(out var tenantId))
    {
      return BadRequest("User tenant not found.");
    }

    if (!User.TryGetUserId(out var userId))
    {
      return BadRequest("User ID not found.");
    }

    var device = await appDb.Devices.FindAsync(request.DeviceId);
    if (device is null)
    {
      return BadRequest("Device not found.");
    }

    if (device.TenantId != tenantId)
    {
      return BadRequest("Device not found.");
    }

    var authResult = await authorizationService.AuthorizeAsync(User, device, DeviceResourcePolicies.LogonTokenCreate);
    if (!authResult.Succeeded)
    {
      return Forbid();
    }

    if (request.Scopes is { Count: > 0 })
    {
      var invalidScopes = await GetInvalidScopes(appDb, userId, request.Scopes);
      if (invalidScopes.Count > 0)
      {
        return BadRequest(
          $"The following permissions are outside your effective permissions: {string.Join(", ", invalidScopes)}");
      }
    }

    var result = await logonTokenProvider.CreateToken(
      request.DeviceId,
      tenantId,
      userId,
      request.ExpirationMinutes);

    if (!result.IsSuccess)
    {
      return result.ToHttpResult().ToActionResult();
    }

    if (request.Scopes is { Count: > 0 })
    {
      await WriteScopes(appDb, result.Value.TokenId, request.DeviceId, tenantId, userId, request.Scopes);
    }

    var deviceAccessUrl = new Uri(
      Request.ToOrigin(),
      $"/device-access?deviceId={request.DeviceId}&logonToken={result.Value.Token}");

    var response = new InternalDtos.LogonTokenResponseDto(
      DeviceAccessUrl: deviceAccessUrl,
      ExpiresAt: result.Value.ExpiresAt,
      Token: result.Value.Token);

    return Ok(response);
  }

  private static async Task<List<string>> GetInvalidScopes(
    AppDb appDb, Guid creatorUserId, List<InternalDtos.CredentialScopeDto> scopes)
  {
    var effectivePermissions = await ResolveUserEffectivePermissions(appDb, creatorUserId);
    return scopes
      .Where(scope => !effectivePermissions.Contains(scope.PermissionName))
      .Select(scope => scope.PermissionName)
      .Distinct()
      .ToList();
  }

  private static async Task<HashSet<string>> ResolveUserEffectivePermissions(AppDb appDb, Guid userId)
  {
    var permissions = new HashSet<string>();

    var directAssignments = await appDb.PermissionAssignments
      .IgnoreQueryFilters()
      .Where(x => x.PrincipalKind == PermissionPrincipalKind.User &&
                  x.PrincipalId == userId &&
                  x.IsEnabled &&
                  x.Effect == PermissionEffect.Allow)
      .Select(x => x.PermissionName)
      .ToListAsync();

    permissions.UnionWith(directAssignments);

    var userGroupIds = await appDb.UserGroupMembers
      .IgnoreQueryFilters()
      .Where(x => x.UserId == userId)
      .Select(x => x.UserGroupId)
      .ToListAsync();

    if (userGroupIds.Count > 0)
    {
      var groupPermissions = await appDb.PermissionAssignments
        .IgnoreQueryFilters()
        .Where(x => x.PrincipalKind == PermissionPrincipalKind.UserGroup &&
                    userGroupIds.Contains(x.PrincipalId) &&
                    x.IsEnabled &&
                    x.Effect == PermissionEffect.Allow)
        .Select(x => x.PermissionName)
        .ToListAsync();

      permissions.UnionWith(groupPermissions);
    }

    return permissions;
  }

  private static async Task WriteScopes(
    AppDb appDb,
    Guid tokenId,
    Guid deviceId,
    Guid tenantId,
    Guid userId,
    List<InternalDtos.CredentialScopeDto> scopes)
  {
    foreach (var scope in scopes)
    {
      appDb.PermissionAssignments.Add(new PermissionAssignment
      {
        PrincipalKind = PermissionPrincipalKind.LogonToken,
        PrincipalId = tokenId,
        PermissionName = scope.PermissionName,
        Effect = PermissionEffect.Allow,
        ScopeKind = scope.ScopeKind,
        ScopeId = scope.ScopeId ?? deviceId,
        IsEnabled = true,
        OwningTenantId = tenantId,
        CreatedByPrincipalType = "user",
        CreatedByPrincipalId = userId.ToString()
      });
    }

    appDb.AuthorizationChangeLogs.Add(new AuthorizationChangeLog
    {
      ActionType = "credential-scope-set",
      ActorPrincipalType = "user",
      ActorPrincipalId = userId.ToString(),
      TargetType = "LogonToken",
      TargetId = tokenId.ToString(),
      OwningTenantId = tenantId,
      AfterJson = $"{{\"scopeCount\":{scopes.Count}}}"
    });

    await appDb.SaveChangesAsync();
  }
}
