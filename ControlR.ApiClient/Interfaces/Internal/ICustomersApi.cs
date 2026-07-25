using ControlR.Libraries.Api.Contracts.Constants;
using ControlR.Libraries.Api.Contracts.Dtos;
using InternalDtos = ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

namespace ControlR.ApiClient.Interfaces.Internal;

public interface ICustomersApi
{
  [ApiRoute($"{HttpConstants.Internal.CustomersEndpoint}", "POST")]
  Task<ApiResult<InternalDtos.CustomerDto>> Create(InternalDtos.CreateCustomerRequestDto request, CancellationToken cancellationToken = default);

  [ApiRoute($"{HttpConstants.Internal.CustomersEndpoint}/{{customerId}}", "DELETE")]
  Task<ApiResult> Delete(Guid customerId, CancellationToken cancellationToken = default);

  [ApiRoute($"{HttpConstants.Internal.CustomersEndpoint}/{{customerId}}", "GET")]
  Task<ApiResult<InternalDtos.CustomerDto>> Get(Guid customerId, CancellationToken cancellationToken = default);

  [ApiRoute($"{HttpConstants.Internal.CustomersEndpoint}", "GET")]
  Task<ApiResult<InternalDtos.CustomerDto[]>> GetAll(CancellationToken cancellationToken = default);

  [ApiRoute($"{HttpConstants.Internal.CustomersEndpoint}/{{customerId}}", "PUT")]
  Task<ApiResult<InternalDtos.CustomerDto>> Update(Guid customerId, InternalDtos.UpdateCustomerRequestDto request, CancellationToken cancellationToken = default);
}
