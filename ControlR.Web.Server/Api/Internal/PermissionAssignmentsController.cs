using ControlR.Libraries.Api.Contracts.Constants;
using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Services.PermissionAssignments;
using Microsoft.AspNetCore.Mvc;

namespace ControlR.Web.Server.Api.Internal;

[Route(HttpConstants.Internal.PermissionAssignmentsEndpoint)]
[ApiController]
[Authorize]
[EndpointGroupName(OpenApiConstants.InternalGroupName)]
public class PermissionAssignmentsController(IPermissionAssignmentManager permissionAssignmentManager) : ControllerBase
{
  private readonly IPermissionAssignmentManager _permissionAssignmentManager = permissionAssignmentManager;

  [HttpPost]
  [Authorize(Policy = PolicyNames.RequirePermissionAssignmentsWrite)]
  public async Task<ActionResult<InternalDtos.PermissionAssignmentDto>> Create(
    [FromBody] InternalDtos.CreatePermissionAssignmentRequestDto request,
    CancellationToken cancellationToken)
  {
    if (!User.TryGetTenantId(out var tenantId))
    {
      return BadRequest("User tenant not found.");
    }

    if (!User.TryGetUserId(out var userId))
    {
      return BadRequest("User ID not found.");
    }

    var result = await _permissionAssignmentManager.Create(request, tenantId, userId, cancellationToken);
    if (!result.IsSuccess)
    {
      return result.ToHttpResult().ToActionResult();
    }

    return Ok(result.Value);
  }

  [HttpDelete("{assignmentId:guid}")]
  [Authorize(Policy = PolicyNames.RequirePermissionAssignmentsWrite)]
  public async Task<IActionResult> Delete(
    [FromRoute] Guid assignmentId,
    CancellationToken cancellationToken)
  {
    if (!User.TryGetTenantId(out var tenantId))
    {
      return BadRequest("User tenant not found.");
    }

    if (!User.TryGetUserId(out var userId))
    {
      return BadRequest("User ID not found.");
    }

    var result = await _permissionAssignmentManager.Delete(assignmentId, tenantId, userId, cancellationToken);
    if (!result.IsSuccess)
    {
      return result.ToActionResult();
    }

    return NoContent();
  }

  [HttpGet]
  [Authorize(Policy = PolicyNames.RequirePermissionAssignmentsRead)]
  public async Task<ActionResult<IReadOnlyList<InternalDtos.PermissionAssignmentDto>>> GetByPrincipal(
    [FromQuery] PermissionPrincipalKind principalKind,
    [FromQuery] Guid principalId,
    CancellationToken cancellationToken)
  {
    if (!User.TryGetTenantId(out var tenantId))
    {
      return BadRequest("User tenant not found.");
    }

    var assignments = await _permissionAssignmentManager.GetByPrincipal(
      principalKind, principalId, tenantId, cancellationToken);

    return Ok(assignments);
  }

  [HttpGet("catalog")]
  [Authorize(Policy = PolicyNames.RequirePermissionAssignmentsRead)]
  public ActionResult<IReadOnlyList<InternalDtos.PermissionCatalogEntryDto>> GetCatalog()
  {
    var entries = PermissionCatalog.All.Values
      .Select(x => new InternalDtos.PermissionCatalogEntryDto(
        x.Name, x.DisplayName, x.Description, x.DefaultScopeKinds, x.IsAssignable))
      .OrderBy(x => x.DisplayName)
      .ToList();

    return Ok(entries);
  }

  [HttpGet("presets")]
  [Authorize(Policy = PolicyNames.RequirePermissionAssignmentsRead)]
  public ActionResult<IReadOnlyList<InternalDtos.PermissionPresetDto>> GetPresets()
  {
    var presets = PermissionPresets.All
      .Select(p => new InternalDtos.PermissionPresetDto(p.Key, [.. p.Value]))
      .OrderBy(p => p.Name)
      .ToList();

    return Ok(presets);
  }

  [HttpPut("{assignmentId:guid}")]
  [Authorize(Policy = PolicyNames.RequirePermissionAssignmentsWrite)]
  public async Task<ActionResult<InternalDtos.PermissionAssignmentDto>> Update(
    [FromRoute] Guid assignmentId,
    [FromBody] InternalDtos.UpdatePermissionAssignmentRequestDto request,
    CancellationToken cancellationToken)
  {
    if (!User.TryGetTenantId(out var tenantId))
    {
      return BadRequest("User tenant not found.");
    }

    if (!User.TryGetUserId(out var userId))
    {
      return BadRequest("User ID not found.");
    }

    var result = await _permissionAssignmentManager.Update(assignmentId, request, tenantId, userId, cancellationToken);
    if (!result.IsSuccess)
    {
      return result.ToHttpResult().ToActionResult();
    }

    return Ok(result.Value);
  }
}
