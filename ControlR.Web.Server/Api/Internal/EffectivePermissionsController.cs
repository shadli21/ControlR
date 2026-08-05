using ControlR.Libraries.Api.Contracts.Constants;
using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Services.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ControlR.Web.Server.Api.Internal;

[Route(HttpConstants.Internal.EffectivePermissionsEndpoint)]
[ApiController]
[Authorize]
[EndpointGroupName(OpenApiConstants.InternalGroupName)]
public class EffectivePermissionsController(IPermissionEvaluator permissionEvaluator) : ControllerBase
{
  private readonly IPermissionEvaluator _permissionEvaluator = permissionEvaluator;

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

    var principal = new PrincipalDescriptor(
      PrincipalType: request.PrincipalKind.ToString(),
      PrincipalId: request.PrincipalId,
      TenantId: tenantId,
      AuthMethod: "effective-permission-query");

    var resource = new ResourceDescriptor(request.ScopeKind, request.ScopeId, tenantId);

    var result = await _permissionEvaluator.Evaluate(
      principal, request.PermissionName, resource, cancellationToken);

    return Ok(new InternalDtos.EffectivePermissionQueryResponseDto(
      result.Allowed,
      result.Allowed ? null : result.DenialReason ?? "Permission denied by policy evaluation."));
  }
}
