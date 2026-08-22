using ControlR.Libraries.Api.Contracts.Constants;
using ControlR.Web.Server.Services.Settings;
using Microsoft.AspNetCore.Mvc;

namespace ControlR.Web.Server.Api.Internal;

[Route(HttpConstants.Internal.DeploymentOptionsEndpoint)]
[ApiController]
[Authorize(Policy = PolicyNames.RequireAgentInstall)]
[EndpointGroupName(OpenApiConstants.InternalGroupName)]
public class DeploymentOptionsController(
  ITenantSettingsManager tenantSettingsManager) : ControllerBase
{
  private readonly ITenantSettingsManager _tenantSettingsManager = tenantSettingsManager;

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
}
