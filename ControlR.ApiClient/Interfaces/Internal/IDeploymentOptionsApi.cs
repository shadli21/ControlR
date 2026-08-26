using ControlR.Libraries.Api.Contracts.Constants;
using ControlR.Libraries.Api.Contracts.Dtos;
using InternalDtos = ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

namespace ControlR.ApiClient.Interfaces.Internal;

public interface IDeploymentOptionsApi
{
  [ApiRoute(HttpConstants.Internal.DeploymentOptionsEndpoint, "GET")]
  Task<ApiResult<InternalDtos.DeploymentOptionsDto>> GetDeploymentOptions(
    CancellationToken cancellationToken = default);

  [ApiRoute(HttpConstants.Internal.DeploymentOptionsEndpoint + "/tag-capability", "POST")]
  Task<ApiResult<InternalDtos.DeploymentTagCapabilityResponseDto>> GetTagCapability(
    InternalDtos.DeploymentTagCapabilityRequestDto request,
    CancellationToken cancellationToken = default);
}
