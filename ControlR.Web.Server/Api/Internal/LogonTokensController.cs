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
    [FromServices] ICredentialScopeService credentialScopeService,
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

      var scopeValidation = await credentialScopeService.ValidateLogonTokenScopes(
        creatorPrincipal, tenantId, request.Scopes, HttpContext.RequestAborted);
      if (!scopeValidation.IsSuccess)
      {
        return scopeValidation.ToActionResult();
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
      await credentialScopeService.WriteLogonTokenScopes(
        result.Value.TokenId, request.DeviceId, tenantId, userId, request.Scopes, HttpContext.RequestAborted);
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
}
