using ControlR.Libraries.Api.Contracts.Constants;
using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Services.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ControlR.Web.Server.Api.Internal;

/// <summary>
/// Authorization change log inspection. Holders of server.authorization-logs.read see all
/// entries (optionally filtered by tenant); holders of tenant.authorization-logs.read see
/// only their own tenant's entries. Entries with no owning tenant (server-scoped changes)
/// are visible to server.authorization-logs.read holders only.
/// </summary>
[Route(HttpConstants.Internal.AuthorizationChangeLogsEndpoint)]
[ApiController]
[Authorize]
[EndpointGroupName(OpenApiConstants.InternalGroupName)]
public class AuthorizationChangeLogsController : ControllerBase
{
  private const int MaxPageSize = 200;

  [HttpGet]
  public async Task<ActionResult<InternalDtos.AuthorizationChangeLogSearchResponseDto>> Get(
    [FromServices] AppDb appDb,
    [FromServices] IPermissionEvaluator permissionEvaluator,
    [FromQuery] int page = 0,
    [FromQuery] int pageSize = 50,
    [FromQuery] string? actionType = null,
    [FromQuery] string? targetType = null,
    [FromQuery] string? searchText = null,
    [FromQuery] Guid? tenantId = null,
    [FromQuery] DateTimeOffset? from = null,
    [FromQuery] DateTimeOffset? to = null,
    CancellationToken cancellationToken = default)
  {
    var principal = PrincipalDescriptorBuilder.FromClaims(User);
    if (principal is null)
    {
      return BadRequest("User principal not found.");
    }

    var effectivePermissions = await permissionEvaluator.GetEffectivePermissionNames(principal, cancellationToken);
    var canReadServer = effectivePermissions.Contains(PermissionNames.ServerAuthorizationLogsRead);
    var canReadTenant = effectivePermissions.Contains(PermissionNames.TenantAuthorizationLogsRead);

    if (!canReadServer && !canReadTenant)
    {
      return Forbid();
    }

    Guid? scopedTenantId;
    if (canReadServer)
    {
      scopedTenantId = tenantId;
    }
    else
    {
      if (!User.TryGetTenantId(out var callerTenantId))
      {
        return BadRequest("User tenant not found.");
      }

      if (tenantId.HasValue && tenantId.Value != callerTenantId)
      {
        return Forbid();
      }

      scopedTenantId = callerTenantId;
    }

    var query = appDb.AuthorizationChangeLogs.AsNoTracking();

    if (scopedTenantId is { } scopeTenant)
    {
      query = query.Where(x => x.OwningTenantId == scopeTenant);
    }

    if (!string.IsNullOrWhiteSpace(actionType))
    {
      query = query.Where(x => x.ActionType == actionType);
    }

    if (!string.IsNullOrWhiteSpace(targetType))
    {
      query = query.Where(x => x.TargetType == targetType);
    }

    if (!string.IsNullOrWhiteSpace(searchText))
    {
      var trimmed = searchText.Trim();

      // Exact GUID lookup when the query parses as a full UUID.
      if (Guid.TryParse(trimmed, out var parsedGuid))
      {
        query = query.Where(x =>
          x.ActorPrincipalId == parsedGuid ||
          x.TargetId == parsedGuid);
      }
      else
      {
        // Partial ID query: match against the canonical text form of the UUID.
        query = query.Where(x =>
          (x.ActorPrincipalId != null && x.ActorPrincipalId.Value.ToString().Contains(trimmed)) ||
          (x.TargetId != null && x.TargetId.Value.ToString().Contains(trimmed)));
      }
    }

    if (from.HasValue)
    {
      query = query.Where(x => x.CreatedAt >= from.Value);
    }

    if (to.HasValue)
    {
      query = query.Where(x => x.CreatedAt <= to.Value);
    }

    var totalItems = await query.CountAsync(cancellationToken);

    var clampedPageSize = Math.Clamp(pageSize, 1, MaxPageSize);
    var items = await query
      .OrderByDescending(x => x.CreatedAt)
      .Skip(Math.Max(0, page) * clampedPageSize)
      .Take(clampedPageSize)
      .Select(x => new InternalDtos.AuthorizationChangeLogDto(
        x.Id,
        x.ActionType,
        x.ActorPrincipalType,
        x.ActorPrincipalId,
        x.TargetType,
        x.TargetId,
        x.OwningTenantId,
        x.IpAddress,
        x.CreatedAt,
        x.BeforeJson,
        x.AfterJson))
      .ToListAsync(cancellationToken);

    return Ok(new InternalDtos.AuthorizationChangeLogSearchResponseDto(items, totalItems));
  }
}
