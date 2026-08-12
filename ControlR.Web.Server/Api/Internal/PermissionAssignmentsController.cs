using ControlR.Libraries.Api.Contracts.Constants;
using ControlR.Web.Server.Authn;
using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Services.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ControlR.Web.Server.Api.Internal;

[Route(HttpConstants.Internal.PermissionAssignmentsEndpoint)]
[ApiController]
[Authorize]
[EndpointGroupName(OpenApiConstants.InternalGroupName)]
public class PermissionAssignmentsController(
  IPermissionAssignmentManager permissionAssignmentManager,
  IPermissionEvaluator permissionEvaluator) : ControllerBase
{
  private readonly IPermissionAssignmentManager _permissionAssignmentManager = permissionAssignmentManager;
  private readonly IPermissionEvaluator _permissionEvaluator = permissionEvaluator;

  [HttpPost("presets/apply")]
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
  public async Task<ActionResult<IReadOnlyList<InternalDtos.PermissionAssignmentDto>>> GetByPrincipal(
    [FromQuery] PermissionPrincipalKind principalKind,
    [FromQuery] Guid principalId,
    CancellationToken cancellationToken)
  {
    if (!TryGetContext(out var tenantId, out var actor))
    {
      return BadRequest("Permission assignment context not found.");
    }

    if (!await CanReadAssignments(actor, cancellationToken))
    {
      return Forbid();
    }

    var assignments = await _permissionAssignmentManager.GetByPrincipal(
      principalKind, principalId, tenantId, actor, cancellationToken);

    return Ok(assignments);
  }

  [HttpGet("catalog")]
  public async Task<ActionResult<IReadOnlyList<InternalDtos.PermissionCatalogEntryDto>>> GetCatalog(
    CancellationToken cancellationToken)
  {
    if (!TryGetContext(out _, out var actor))
    {
      return BadRequest("Permission assignment context not found.");
    }

    if (!await CanReadAssignments(actor, cancellationToken))
    {
      return Forbid();
    }

    var entries = PermissionCatalog.All.Values
      .Select(x => new InternalDtos.PermissionCatalogEntryDto(
        x.Name, x.DisplayName, x.Description, x.AllowedScopeKinds, x.SelfRemovable))
      .OrderBy(x => x.DisplayName)
      .ToList();

    return Ok(entries);
  }

  [HttpGet("presets")]
  public async Task<ActionResult<IReadOnlyList<InternalDtos.PermissionPresetDto>>> GetPresets(
    CancellationToken cancellationToken)
  {
    if (!TryGetContext(out _, out var actor))
    {
      return BadRequest("Permission assignment context not found.");
    }

    if (!await CanReadAssignments(actor, cancellationToken))
    {
      return Forbid();
    }

    var presets = PermissionPresets.All
      .Select(p => new InternalDtos.PermissionPresetDto(p.Key, [.. p.Value]))
      .OrderBy(p => p.Name)
      .ToList();

    return Ok(presets);
  }

  [HttpPost("replace")]
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

  private async Task<bool> CanReadAssignments(PrincipalDescriptor actor, CancellationToken cancellationToken)
  {
    var permissions = await _permissionEvaluator.GetEffectivePermissionNames(actor, cancellationToken);
    return permissions.Contains(PermissionNames.TenantPermissionsRead) ||
          permissions.Contains(PermissionNames.TenantPermissionsWrite) ||
          permissions.Contains(PermissionNames.ServerPermissionsRead) ||
          permissions.Contains(PermissionNames.ServerPermissionsWrite);
  }

  private bool TryGetContext(out Guid tenantId, out PrincipalDescriptor actor)
  {
    var principal = PrincipalDescriptorBuilder.FromClaims(User);
    if (principal is null)
    {
      actor = new PrincipalDescriptor(string.Empty, Guid.Empty, null, "unknown");
      tenantId = Guid.Empty;
      return false;
    }

    actor = principal;
    if (User.TryGetTenantId(out tenantId))
    {
      return true;
    }

    if (principal.PrincipalType == PrincipalClaimTypes.ServerServiceAccount)
    {
      tenantId = Guid.Empty;
      return true;
    }

    tenantId = Guid.Empty;
    return false;
  }
}
