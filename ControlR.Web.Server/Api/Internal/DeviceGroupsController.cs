using ControlR.Libraries.Api.Contracts.Constants;
using Microsoft.AspNetCore.Mvc;

namespace ControlR.Web.Server.Api.Internal;

[Route(HttpConstants.Internal.DeviceGroupsEndpoint)]
[ApiController]
[Authorize]
[EndpointGroupName(OpenApiConstants.InternalGroupName)]
public class DeviceGroupsController(IDeviceGroupManager deviceGroupManager) : ControllerBase
{
  private readonly IDeviceGroupManager _deviceGroupManager = deviceGroupManager;

  [HttpPost("{deviceGroupId:guid}/members")]
  [Authorize(Policy = PolicyNames.RequireDeviceGroupAssignDevices)]
  public async Task<IActionResult> AddMembers(
    [FromRoute] Guid deviceGroupId,
    [FromBody] InternalDtos.AddDeviceGroupMembersRequestDto request,
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

    var result = await _deviceGroupManager.AddMembers(
      deviceGroupId, request.DeviceIds, tenantId, userId, cancellationToken);

    if (!result.IsSuccess)
    {
      return result.ToActionResult();
    }

    return NoContent();
  }

  [HttpPost]
  [Authorize(Policy = PolicyNames.RequireDeviceGroupsWrite)]
  public async Task<ActionResult<InternalDtos.DeviceGroupDetailDto>> Create(
    [FromBody] InternalDtos.CreateDeviceGroupRequestDto request,
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

    var result = await _deviceGroupManager.Create(
      request.Name, request.Description, tenantId, userId, cancellationToken);

    if (!result.IsSuccess)
    {
      return result.ToHttpResult().ToActionResult();
    }

    return Ok(result.Value);
  }

  [HttpDelete("{deviceGroupId:guid}")]
  [Authorize(Policy = PolicyNames.RequireDeviceGroupsWrite)]
  public async Task<IActionResult> Delete(
    [FromRoute] Guid deviceGroupId,
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

    var result = await _deviceGroupManager.Delete(deviceGroupId, tenantId, userId, cancellationToken);
    if (!result.IsSuccess)
    {
      return result.ToActionResult();
    }

    return NoContent();
  }

  [HttpGet("{deviceGroupId:guid}")]
  [Authorize(Policy = PolicyNames.RequireDeviceGroupsRead)]
  public async Task<ActionResult<InternalDtos.DeviceGroupDetailDto>> Get(
    [FromRoute] Guid deviceGroupId,
    CancellationToken cancellationToken)
  {
    if (!User.TryGetTenantId(out var tenantId))
    {
      return BadRequest("User tenant not found.");
    }

    var result = await _deviceGroupManager.Get(deviceGroupId, tenantId, cancellationToken);
    if (!result.IsSuccess)
    {
      return result.ToHttpResult().ToActionResult();
    }

    return Ok(result.Value);
  }

  [HttpGet]
  [Authorize(Policy = PolicyNames.RequireDeviceGroupsRead)]
  public async Task<ActionResult<List<InternalDtos.DeviceGroupDto>>> GetAll(
    CancellationToken cancellationToken)
  {
    if (!User.TryGetTenantId(out var tenantId))
    {
      return BadRequest("User tenant not found.");
    }

    var groups = await _deviceGroupManager.GetAll(tenantId, cancellationToken);
    return Ok(groups);
  }

  [HttpDelete("{deviceGroupId:guid}/members")]
  [Authorize(Policy = PolicyNames.RequireDeviceGroupAssignDevices)]
  public async Task<IActionResult> RemoveMembers(
    [FromRoute] Guid deviceGroupId,
    [FromBody] InternalDtos.RemoveDeviceGroupMembersRequestDto request,
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

    var result = await _deviceGroupManager.RemoveMembers(
      deviceGroupId, request.DeviceIds, tenantId, userId, cancellationToken);

    if (!result.IsSuccess)
    {
      return result.ToActionResult();
    }

    return NoContent();
  }

  [HttpPut("{deviceGroupId:guid}")]
  [Authorize(Policy = PolicyNames.RequireDeviceGroupsWrite)]
  public async Task<ActionResult<InternalDtos.DeviceGroupDetailDto>> Update(
    [FromRoute] Guid deviceGroupId,
    [FromBody] InternalDtos.UpdateDeviceGroupRequestDto request,
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

    var result = await _deviceGroupManager.Update(
      deviceGroupId, request.Name, request.Description, tenantId, userId, cancellationToken);

    if (!result.IsSuccess)
    {
      return result.ToHttpResult().ToActionResult();
    }

    return Ok(result.Value);
  }
}
