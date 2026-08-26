using System.Net.Http.Json;
using ControlR.ApiClient.Interfaces.Internal;
using ControlR.Libraries.Api.Contracts.Constants;
using ControlR.Libraries.Api.Contracts.Dtos;
using InternalDtos = ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

namespace ControlR.ApiClient;

internal partial class InternalApi
{
  async Task<ApiResult<InternalDtos.DeploymentOptionsDto>> IDeploymentOptionsApi.GetDeploymentOptions(
    CancellationToken cancellationToken)
  {
    return await _client.ExecuteApiCall(async () =>
      await _client.HttpClient.GetFromJsonAsync<InternalDtos.DeploymentOptionsDto>(
        HttpConstants.Internal.DeploymentOptionsEndpoint,
        cancellationToken));
  }

  async Task<ApiResult<InternalDtos.DeploymentTagCapabilityResponseDto>> IDeploymentOptionsApi.GetTagCapability(
    InternalDtos.DeploymentTagCapabilityRequestDto request,
    CancellationToken cancellationToken)
  {
    return await _client.ExecuteApiCall(async () =>
    {
      var response = await _client.HttpClient.PostAsJsonAsync(
        HttpConstants.Internal.DeploymentOptionsEndpoint + "/tag-capability",
        request,
        cancellationToken);
      response.EnsureSuccessStatusCode();
      return await response.Content.ReadFromJsonAsync<InternalDtos.DeploymentTagCapabilityResponseDto>(cancellationToken);
    });
  }
}
