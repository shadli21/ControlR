using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Services.DeviceManagement;
using ControlR.Web.Server.Services.Settings;
using Microsoft.AspNetCore.Mvc;

namespace ControlR.Web.Server.Api.Internal;

[Route(HttpConstants.Internal.DeploymentOptionsEndpoint)]
[ApiController]
[Authorize(Policy = PolicyNames.RequireAgentInstall)]
[EndpointGroupName(OpenApiConstants.InternalGroupName)]
public class DeploymentOptionsController(
  ITenantSettingsManager tenantSettingsManager,
  IDeviceManager deviceManager,
  UserManager<AppUser> userManager) : ControllerBase
{
  private readonly IDeviceManager _deviceManager = deviceManager;
  private readonly ITenantSettingsManager _tenantSettingsManager = tenantSettingsManager;
  private readonly UserManager<AppUser> _userManager = userManager;

  [HttpGet]
  public async Task<ActionResult<InternalDtos.DeploymentOptionsDto>> Get(
    CancellationToken cancellationToken)
  {
    if (!User.TryGetTenantId(out var tenantId))
    {
      return Unauthorized();
    }

    var settings = await _tenantSettingsManager.GetAllSettings(
      tenantId,
      cancellationToken);

    return Ok(new InternalDtos.DeploymentOptionsDto(
      settings.AppendInstanceId ?? false,
      settings.InstanceId));
  }

  /// <summary>
  /// Returns whether the current principal may assign tags to a prospective deployment target.
  /// The UI uses this to decide whether to offer tag selection; the agent registration endpoint
  /// remains the final enforcement boundary.
  /// </summary>
  [HttpPost("tag-capability")]
  public async Task<ActionResult<InternalDtos.DeploymentTagCapabilityResponseDto>> GetTagCapability(
    [FromBody] InternalDtos.DeploymentTagCapabilityRequestDto request,
    CancellationToken cancellationToken)
  {
    if (!User.TryGetTenantId(out var tenantId))
    {
      return Unauthorized();
    }

    if (User.IsServerPrincipal())
    {
      // Server service accounts act as trusted server-wide principals.
      return Ok(new InternalDtos.DeploymentTagCapabilityResponseDto(true));
    }

    if (!User.TryGetUserId(out var userId))
    {
      return BadRequest("User ID not found.");
    }

    var user = await _userManager.FindByIdAsync($"{userId}");
    if (user is null || user.TenantId != tenantId)
    {
      return Forbid();
    }

    var principal = new PrincipalDescriptor(
      PrincipalType.User,
      user.Id,
      user.TenantId,
      AuthMethod: "cookie");

    var allowed = await _deviceManager.CanAssignTagOnProspectiveDevice(
      principal,
      request.DeviceId,
      request.CustomerId,
      tenantId,
      cancellationToken);

    return Ok(new InternalDtos.DeploymentTagCapabilityResponseDto(allowed));
  }
}
