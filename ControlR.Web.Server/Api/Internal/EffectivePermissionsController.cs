using ControlR.Libraries.Api.Contracts.Constants;
using ControlR.Web.Server.Services.PermissionAssignments;
using Microsoft.AspNetCore.Mvc;

namespace ControlR.Web.Server.Api.Internal;

[Route(HttpConstants.Internal.EffectivePermissionsEndpoint)]
[ApiController]
[Authorize]
[EndpointGroupName(OpenApiConstants.InternalGroupName)]
public class EffectivePermissionsController(IPermissionAssignmentManager permissionAssignmentManager) : ControllerBase
{
  private readonly IPermissionAssignmentManager _permissionAssignmentManager = permissionAssignmentManager;

  [HttpPost("query")]
  [Authorize(Policy = PolicyNames.RequirePermissionAssignmentsRead)]
  public async Task<ActionResult<InternalDtos.EffectivePermissionQueryResponseDto>> Query(
    [FromBody] InternalDtos.EffectivePermissionQueryRequestDto request,
    CancellationToken cancellationToken)
  {
    if (!User.TryGetTenantId(out var tenantId))
    {
      return BadRequest("User tenant not found.");
    }

    var result = await _permissionAssignmentManager.QueryEffectivePermission(
      request, tenantId, cancellationToken);

    return Ok(result);
  }
}
