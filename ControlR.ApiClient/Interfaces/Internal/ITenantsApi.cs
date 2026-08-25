using ControlR.Libraries.Api.Contracts.Constants;
using ControlR.Libraries.Api.Contracts.Dtos;
using ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

namespace ControlR.ApiClient.Interfaces.Internal;

public interface ITenantsApi
{
  [ApiRoute(HttpConstants.Internal.TenantsEndpoint, "GET")]
  Task<ApiResult<TenantSummaryDto[]>> Get(CancellationToken cancellationToken = default);
}
