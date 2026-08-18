using System.Net.Http.Json;
using ControlR.ApiClient.Interfaces.Internal;
using ControlR.Libraries.Api.Contracts.Constants;
using ControlR.Libraries.Api.Contracts.Dtos;
using InternalDtos = ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

namespace ControlR.ApiClient;

internal partial class InternalApi
{
  async Task<ApiResult<InternalDtos.TenantSummaryDto[]>> ITenantsApi.Get(CancellationToken cancellationToken)
  {
    return await _client.ExecuteApiCall(async () =>
      await _client.HttpClient.GetFromJsonAsync<InternalDtos.TenantSummaryDto[]>(
        HttpConstants.Internal.TenantsEndpoint, cancellationToken)
      ?? []);
  }
}
