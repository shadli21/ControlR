using ControlR.Libraries.Api.Contracts.Constants;
using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Services.Authorization;
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
    [FromServices] IPermissionEvaluator permissionEvaluator,
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
      var creatorPrincipal = PrincipalDescriptorBuilder.FromClaims(User);
      if (creatorPrincipal is null)
      {
        return BadRequest("User principal not found.");
      }

      var effectivePermissions = await permissionEvaluator.GetEffectivePermissionNames(
        creatorPrincipal, HttpContext.RequestAborted);

      var invalidScopes = request.Scopes
        .Where(scope => !effectivePermissions.Contains(scope.PermissionName))
        .Select(scope => scope.PermissionName)
        .Distinct()
        .ToList();

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

    appDb.AuthorizationChangeLogs.Add(AuthorizationChangeLogEntry.Create(
      AuthorizationChangeLogActions.CredentialScopeSet,
      AuthorizationChangeLogActorTypes.User,
      userId.ToString(),
      AuthorizationChangeLogTargetTypes.LogonToken,
      tokenId.ToString(),
      tenantId,
      after: new CredentialScopeSetSummary(scopes.Count)));

    await appDb.SaveChangesAsync();
  }
}
