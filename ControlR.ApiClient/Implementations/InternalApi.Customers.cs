using System.Net.Http.Json;
using ControlR.ApiClient.Interfaces.Internal;
using ControlR.Libraries.Api.Contracts.Constants;
using ControlR.Libraries.Api.Contracts.Dtos;
using InternalDtos = ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

namespace ControlR.ApiClient;

internal partial class InternalApi
{
  async Task<ApiResult<InternalDtos.CustomerDto>> ICustomersApi.Create(InternalDtos.CreateCustomerRequestDto request, CancellationToken cancellationToken)
  {
    return await _client.ExecuteApiCall(async () =>
    {
      using var response = await _client.HttpClient.PostAsJsonAsync(HttpConstants.Internal.CustomersEndpoint, request, cancellationToken);
      await response.EnsureSuccessStatusCodeWithDetails();
      return await response.Content.ReadFromJsonAsync<InternalDtos.CustomerDto>(cancellationToken);
    });
  }

  async Task<ApiResult> ICustomersApi.Delete(Guid customerId, CancellationToken cancellationToken)
  {
    return await _client.ExecuteApiCall(async () =>
    {
      using var response = await _client.HttpClient.DeleteAsync(
        $"{HttpConstants.Internal.CustomersEndpoint}/{customerId}", cancellationToken);
      await response.EnsureSuccessStatusCodeWithDetails();
    });
  }

  async Task<ApiResult<InternalDtos.CustomerDto>> ICustomersApi.Get(Guid customerId, CancellationToken cancellationToken)
  {
    return await _client.ExecuteApiCall(async () =>
      await _client.HttpClient.GetFromJsonAsync<InternalDtos.CustomerDto>(
        $"{HttpConstants.Internal.CustomersEndpoint}/{customerId}", cancellationToken));
  }

  async Task<ApiResult<InternalDtos.CustomerDto[]>> ICustomersApi.GetAll(CancellationToken cancellationToken)
  {
    return await _client.ExecuteApiCall(async () =>
      await _client.HttpClient.GetFromJsonAsync<InternalDtos.CustomerDto[]>(HttpConstants.Internal.CustomersEndpoint, cancellationToken));
  }

  async Task<ApiResult<InternalDtos.CustomerDto>> ICustomersApi.Update(Guid customerId, InternalDtos.UpdateCustomerRequestDto request, CancellationToken cancellationToken)
  {
    return await _client.ExecuteApiCall(async () =>
    {
      using var response = await _client.HttpClient.PutAsJsonAsync(
        $"{HttpConstants.Internal.CustomersEndpoint}/{customerId}", request, cancellationToken);
      await response.EnsureSuccessStatusCodeWithDetails();
      return await response.Content.ReadFromJsonAsync<InternalDtos.CustomerDto>(cancellationToken);
    });
  }
}
