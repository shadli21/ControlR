using ControlR.Libraries.Api.Contracts.Constants;
using ControlR.Web.Server.Authz.Permissions;
using Microsoft.AspNetCore.Mvc;

namespace ControlR.Web.Server.Api.Internal;

[Route(HttpConstants.Internal.ServerPermissionAssignmentsEndpoint)]
[ApiController]
[Authorize]
[EndpointGroupName(OpenApiConstants.InternalGroupName)]
public class ServerPermissionAssignmentsController(IPermissionAssignmentManager permissionAssignmentManager) : ControllerBase
{
  private readonly IPermissionAssignmentManager _permissionAssignmentManager = permissionAssignmentManager;

  [HttpPost]
  [Authorize(Policy = PolicyNames.RequireServerPermissionsWrite)]
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

    var result = await _permissionAssignmentManager.Create(
      request, tenantId, userId, cancellationToken, PermissionAssignmentAuthority.Server);
    if (!result.IsSuccess)
    {
      return result.ToHttpResult().ToActionResult();
    }

    return Ok(result.Value);
  }

  [HttpPost("create-many")]
  [Authorize(Policy = PolicyNames.RequireServerPermissionsWrite)]
  public async Task<IActionResult> CreateMany(
    [FromBody] InternalDtos.CreateManyPermissionAssignmentsRequestDto request,
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

    var result = await _permissionAssignmentManager.CreateMany(
      request.Assignments, tenantId, userId, cancellationToken, PermissionAssignmentAuthority.Server);
    if (!result.IsSuccess)
    {
      return result.ToActionResult();
    }

    return NoContent();
  }

  [HttpDelete("{assignmentId:guid}")]
  [Authorize(Policy = PolicyNames.RequireServerPermissionsWrite)]
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

    var result = await _permissionAssignmentManager.Delete(
      assignmentId, tenantId, userId, cancellationToken, PermissionAssignmentAuthority.Server);
    if (!result.IsSuccess)
    {
      return result.ToActionResult();
    }

    return NoContent();
  }

  [HttpPost("delete-many")]
  [Authorize(Policy = PolicyNames.RequireServerPermissionsWrite)]
  public async Task<ActionResult<InternalDtos.DeleteManyPermissionAssignmentsResponseDto>> DeleteMany(
    [FromBody] InternalDtos.DeleteManyPermissionAssignmentsRequestDto request,
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

    var result = await _permissionAssignmentManager.DeleteMany(
      request.AssignmentIds, tenantId, userId, cancellationToken, PermissionAssignmentAuthority.Server);
    if (!result.IsSuccess)
    {
      return result.ToHttpResult().ToActionResult();
    }

    return Ok(result.Value);
  }

  [HttpGet]
  [Authorize(Policy = PolicyNames.RequireServerPermissionsRead)]
  public async Task<ActionResult<IReadOnlyList<InternalDtos.PermissionAssignmentDto>>> GetByPrincipal(
    [FromQuery] PermissionPrincipalKind principalKind,
    [FromQuery] Guid principalId,
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

    var assignments = await _permissionAssignmentManager.GetByPrincipal(
      principalKind, principalId, tenantId, userId, cancellationToken, PermissionAssignmentAuthority.Server);

    return Ok(assignments);
  }

  [HttpPost("replace")]
  [Authorize(Policy = PolicyNames.RequireServerPermissionsWrite)]
  public async Task<IActionResult> Replace(
    [FromBody] InternalDtos.ReplacePermissionAssignmentsRequestDto request,
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

    var result = await _permissionAssignmentManager.ReplaceForPrincipal(
      request.PrincipalKind,
      request.PrincipalId,
      tenantId,
      userId,
      request.Assignments,
      cancellationToken,
      PermissionAssignmentAuthority.Server);
    if (!result.IsSuccess)
    {
      return result.ToActionResult();
    }

    return NoContent();
  }

  [HttpPut("{assignmentId:guid}")]
  [Authorize(Policy = PolicyNames.RequireServerPermissionsWrite)]
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

    var result = await _permissionAssignmentManager.Update(
      assignmentId, request, tenantId, userId, cancellationToken, PermissionAssignmentAuthority.Server);
    if (!result.IsSuccess)
    {
      return result.ToHttpResult().ToActionResult();
    }

    return Ok(result.Value);
  }
}
