using System.Diagnostics.CodeAnalysis;
using ControlR.Web.Server.Authz.Permissions;
using Microsoft.AspNetCore.Mvc;

namespace ControlR.Web.Server.Api.Internal;

[Route(HttpConstants.Internal.PermissionAssignmentsEndpoint)]
[ApiController]
[Authorize]
[EndpointGroupName(OpenApiConstants.InternalGroupName)]
public class PermissionAssignmentsController(
  IPermissionAssignmentManager permissionAssignmentManager) : ControllerBase
{
  private readonly IPermissionAssignmentManager _permissionAssignmentManager = permissionAssignmentManager;

  [HttpPost("presets/apply")]
  [Authorize(Policy = PolicyNames.RequirePermissionAssignmentsWrite)]
  public async Task<ActionResult<int>> ApplyPresets(
    [FromBody] InternalDtos.ApplyPermissionPresetsRequestDto request,
    CancellationToken cancellationToken)
  {
    if (!TryGetContext(out var tenantId, out var actor))
    {
      return BadRequest("Permission assignment context not found.");
    }

    var result = await _permissionAssignmentManager.ApplyPresets(request, tenantId, actor, cancellationToken);
    if (!result.IsSuccess)
    {
      return result.ToHttpResult().ToActionResult();
    }

    return Ok(result.Value);
  }

  [HttpPost]
  [Authorize(Policy = PolicyNames.RequirePermissionAssignmentsWrite)]
  public async Task<ActionResult<InternalDtos.PermissionAssignmentDto>> Create(
    [FromBody] InternalDtos.CreatePermissionAssignmentRequestDto request,
    CancellationToken cancellationToken)
  {
    if (!TryGetContext(out var tenantId, out var actor))
    {
      return BadRequest("Permission assignment context not found.");
    }

    var result = await _permissionAssignmentManager.Create(
      request, tenantId, actor, cancellationToken);
    if (!result.IsSuccess)
    {
      return result.ToHttpResult().ToActionResult();
    }

    return Ok(result.Value);
  }

  [HttpPost("create-many")]
  [Authorize(Policy = PolicyNames.RequirePermissionAssignmentsWrite)]
  public async Task<IActionResult> CreateMany(
    [FromBody] InternalDtos.CreateManyPermissionAssignmentsRequestDto request,
    CancellationToken cancellationToken)
  {
    if (!TryGetContext(out var tenantId, out var actor))
    {
      return BadRequest("Permission assignment context not found.");
    }

    var result = await _permissionAssignmentManager.CreateMany(
      request.Assignments, tenantId, actor, cancellationToken);
    if (!result.IsSuccess)
    {
      return result.ToActionResult();
    }

    return NoContent();
  }

  [HttpDelete("{assignmentId:guid}")]
  [Authorize(Policy = PolicyNames.RequirePermissionAssignmentsWrite)]
  public async Task<IActionResult> Delete(
    [FromRoute] Guid assignmentId,
    CancellationToken cancellationToken)
  {
    if (!TryGetContext(out var tenantId, out var actor))
    {
      return BadRequest("Permission assignment context not found.");
    }

    var result = await _permissionAssignmentManager.Delete(
      assignmentId, tenantId, actor, cancellationToken);
    if (!result.IsSuccess)
    {
      return result.ToActionResult();
    }

    return NoContent();
  }

  [HttpPost("delete-many")]
  [Authorize(Policy = PolicyNames.RequirePermissionAssignmentsWrite)]
  public async Task<ActionResult<InternalDtos.DeleteManyPermissionAssignmentsResponseDto>> DeleteMany(
    [FromBody] InternalDtos.DeleteManyPermissionAssignmentsRequestDto request,
    CancellationToken cancellationToken)
  {
    if (!TryGetContext(out var tenantId, out var actor))
    {
      return BadRequest("Permission assignment context not found.");
    }

    var result = await _permissionAssignmentManager.DeleteMany(
      request.AssignmentIds, tenantId, actor, cancellationToken);
    if (!result.IsSuccess)
    {
      return result.ToHttpResult().ToActionResult();
    }

    return Ok(result.Value);
  }

  [HttpGet]
  [Authorize(Policy = PolicyNames.RequirePermissionAssignmentsRead)]
  public async Task<ActionResult<IReadOnlyList<InternalDtos.PermissionAssignmentDto>>> GetByPrincipal(
    [FromQuery] PermissionPrincipalKind principalKind,
    [FromQuery] Guid principalId,
    CancellationToken cancellationToken)
  {
    if (!TryGetContext(out var tenantId, out var actor))
    {
      return BadRequest("Permission assignment context not found.");
    }

    var assignments = await _permissionAssignmentManager.GetByPrincipal(
      principalKind, principalId, tenantId, actor, cancellationToken);

    return Ok(assignments);
  }

  [HttpGet("catalog")]
  [Authorize(Policy = PolicyNames.RequirePermissionAssignmentsRead)]
  public async Task<ActionResult<IReadOnlyList<InternalDtos.PermissionCatalogEntryDto>>> GetCatalog(
    CancellationToken cancellationToken)
  {
    if (!TryGetContext(out _, out var actor))
    {
      return BadRequest("Permission assignment context not found.");
    }

    var entries = PermissionCatalog.All.Values
      .Select(x => new InternalDtos.PermissionCatalogEntryDto(
        x.Name, x.DisplayName, x.Description, x.AllowedScopeKinds, x.SelfRemovable))
      .OrderBy(x => x.DisplayName)
      .ToList();

    return Ok(entries);
  }

  [HttpGet("presets")]
  [Authorize(Policy = PolicyNames.RequirePermissionAssignmentsRead)]
  public async Task<ActionResult<IReadOnlyList<InternalDtos.PermissionPresetDto>>> GetPresets(
    CancellationToken cancellationToken)
  {
    if (!TryGetContext(out _, out var actor))
    {
      return BadRequest("Permission assignment context not found.");
    }

    var presets = PermissionPresets.All
      .Select(p => new InternalDtos.PermissionPresetDto(p.Key, [.. p.Value]))
      .OrderBy(p => p.Name)
      .ToList();

    return Ok(presets);
  }

  [HttpPost("replace")]
  [Authorize(Policy = PolicyNames.RequirePermissionAssignmentsWrite)]
  public async Task<IActionResult> Replace(
    [FromBody] InternalDtos.ReplacePermissionAssignmentsRequestDto request,
    CancellationToken cancellationToken)
  {
    if (!TryGetContext(out var tenantId, out var actor))
    {
      return BadRequest("Permission assignment context not found.");
    }

    var result = await _permissionAssignmentManager.ReplaceForPrincipal(
      request.PrincipalKind,
      request.PrincipalId,
      tenantId,
      actor,
      request.Assignments,
      cancellationToken);
    if (!result.IsSuccess)
    {
      return result.ToActionResult();
    }

    return NoContent();
  }

  [HttpPut("{assignmentId:guid}")]
  [Authorize(Policy = PolicyNames.RequirePermissionAssignmentsWrite)]
  public async Task<ActionResult<InternalDtos.PermissionAssignmentDto>> Update(
    [FromRoute] Guid assignmentId,
    [FromBody] InternalDtos.UpdatePermissionAssignmentRequestDto request,
    CancellationToken cancellationToken)
  {
    if (!TryGetContext(out var tenantId, out var actor))
    {
      return BadRequest("Permission assignment context not found.");
    }

    var result = await _permissionAssignmentManager.Update(
      assignmentId, request, tenantId, actor, cancellationToken);
    if (!result.IsSuccess)
    {
      return result.ToHttpResult().ToActionResult();
    }

    return Ok(result.Value);
  }

  private bool TryGetContext(
    out Guid tenantId,
    [NotNullWhen(true)] out PrincipalDescriptor? actor)
  {
    var principal = User.ToPrincipalDescriptor();
    if (principal is null)
    {
      actor = null;
      tenantId = Guid.Empty;
      return false;
    }

    actor = principal;
    if (User.TryGetTenantId(out tenantId))
    {
      return true;
    }

    if (principal.PrincipalType == PrincipalType.ServerServiceAccount)
    {
      tenantId = Guid.Empty;
      return true;
    }

    tenantId = Guid.Empty;
    return false;
  }
}
