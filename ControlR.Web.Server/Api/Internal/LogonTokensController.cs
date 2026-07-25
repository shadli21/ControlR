using ControlR.Libraries.Api.Contracts.Constants;
using ControlR.Web.Server.Data.Enums;
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

    var authResult = await authorizationService.AuthorizeAsync(User, device, DeviceAccessByDeviceResourcePolicy.PolicyName);
    if (!authResult.Succeeded)
    {
      return Forbid();
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

  [HttpGet("{tokenId:guid}/scopes")]
  public async Task<ActionResult<IReadOnlyList<InternalDtos.CredentialScopeDto>>> GetScopes(
    [FromServices] AppDb appDb,
    [FromRoute] Guid tokenId)
  {
    if (!User.TryGetTenantId(out var tenantId))
    {
      return BadRequest("User tenant not found.");
    }

    var tokenExists = await appDb.LogonTokens
      .AnyAsync(x => x.Id == tokenId && x.TenantId == tenantId);

    if (!tokenExists)
    {
      return NotFound();
    }

    var rows = await appDb.PermissionAssignments
      .IgnoreQueryFilters()
      .Where(x => x.PrincipalKind == PermissionPrincipalKind.LogonToken &&
                  x.PrincipalId == tokenId &&
                  x.IsEnabled)
      .ToListAsync();

    var dtos = rows
      .Select(x => new InternalDtos.CredentialScopeDto(
        x.PermissionName, x.ScopeKind.ToString(), x.ScopeId))
      .ToList();

    return Ok(dtos);
  }

  [HttpPut("{tokenId:guid}/scopes")]
  public async Task<ActionResult> SetScopes(
    [FromServices] AppDb appDb,
    [FromRoute] Guid tokenId,
    [FromBody] InternalDtos.SetCredentialScopesRequestDto request)
  {
    if (!User.TryGetTenantId(out var tenantId))
    {
      return BadRequest("User tenant not found.");
    }

    if (!User.TryGetUserId(out var userId))
    {
      return BadRequest("User ID not found.");
    }

    var logonToken = await appDb.LogonTokens
      .FirstOrDefaultAsync(x => x.Id == tokenId && x.TenantId == tenantId);

    if (logonToken is null)
    {
      return NotFound();
    }

    var existingRows = await appDb.PermissionAssignments
      .IgnoreQueryFilters()
      .Where(x => x.PrincipalKind == PermissionPrincipalKind.LogonToken &&
                  x.PrincipalId == tokenId)
      .ToListAsync();

    foreach (var row in existingRows)
    {
      appDb.AuthorizationChangeLogs.Add(new AuthorizationChangeLog
      {
        ActionType = "credential-scope-removed",
        ActorPrincipalType = "user",
        ActorPrincipalId = userId.ToString(),
        TargetType = "PermissionAssignment",
        TargetId = row.Id.ToString(),
        OwningTenantId = tenantId,
        BeforeJson = $"{{\"permission\":\"{row.PermissionName}\",\"scope\":\"{row.ScopeKind}\",\"scopeId\":\"{row.ScopeId}\"}}"
      });
    }

    appDb.PermissionAssignments.RemoveRange(existingRows);

    foreach (var scope in request.Scopes)
    {
      if (!Enum.TryParse<PermissionScopeKind>(scope.ScopeKind, out var scopeKind))
      {
        return BadRequest($"Invalid scope kind: {scope.ScopeKind}");
      }

      appDb.PermissionAssignments.Add(new PermissionAssignment
      {
        PrincipalKind = PermissionPrincipalKind.LogonToken,
        PrincipalId = tokenId,
        PermissionName = scope.PermissionName,
        Effect = PermissionEffect.Allow,
        ScopeKind = scopeKind,
        ScopeId = scope.ScopeId ?? logonToken.DeviceId,
        IsEnabled = true,
        OwningTenantId = tenantId,
        CreatedByPrincipalType = "user",
        CreatedByPrincipalId = userId.ToString()
      });
    }

    if (request.Scopes.Count > 0)
    {
      appDb.AuthorizationChangeLogs.Add(new AuthorizationChangeLog
      {
        ActionType = "credential-scope-set",
        ActorPrincipalType = "user",
        ActorPrincipalId = userId.ToString(),
        TargetType = "LogonToken",
        TargetId = tokenId.ToString(),
        OwningTenantId = tenantId,
        AfterJson = $"{{\"scopeCount\":{request.Scopes.Count}}}"
      });
    }

    await appDb.SaveChangesAsync();
    return NoContent();
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
      if (!Enum.TryParse<PermissionScopeKind>(scope.ScopeKind, out var scopeKind))
      {
        continue;
      }

      appDb.PermissionAssignments.Add(new PermissionAssignment
      {
        PrincipalKind = PermissionPrincipalKind.LogonToken,
        PrincipalId = tokenId,
        PermissionName = scope.PermissionName,
        Effect = PermissionEffect.Allow,
        ScopeKind = scopeKind,
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
