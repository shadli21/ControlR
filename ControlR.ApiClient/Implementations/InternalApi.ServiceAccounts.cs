using System.Net.Http.Json;
using ControlR.ApiClient.Interfaces.Internal;
using ControlR.Libraries.Api.Contracts.Constants;
using ControlR.Libraries.Api.Contracts.Dtos;
using InternalDtos = ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

namespace ControlR.ApiClient;

internal partial class InternalApi
{
  async Task<ApiResult<InternalDtos.CreateTenantServiceAccountCredentialResponseDto>> IServiceAccountsApi.AddCredential(Guid serviceAccountId, InternalDtos.CreateTenantServiceAccountCredentialRequestDto request, CancellationToken cancellationToken)
  {
    return await _client.ExecuteApiCall(async () =>
    {
      using var response = await _client.HttpClient.PostAsJsonAsync(
        $"{HttpConstants.Internal.ServiceAccountsEndpoint}/{serviceAccountId}/credentials", request, cancellationToken);
      await response.EnsureSuccessStatusCodeWithDetails();
      return await response.Content.ReadFromJsonAsync<InternalDtos.CreateTenantServiceAccountCredentialResponseDto>(cancellationToken);
    });
  }

  async Task<ApiResult<InternalDtos.TenantServiceAccountDto>> IServiceAccountsApi.Create(InternalDtos.CreateTenantServiceAccountRequestDto request, CancellationToken cancellationToken)
  {
    return await _client.ExecuteApiCall(async () =>
    {
      using var response = await _client.HttpClient.PostAsJsonAsync(HttpConstants.Internal.ServiceAccountsEndpoint, request, cancellationToken);
      await response.EnsureSuccessStatusCodeWithDetails();
      return await response.Content.ReadFromJsonAsync<InternalDtos.TenantServiceAccountDto>(cancellationToken);
    });
  }

  async Task<ApiResult> IServiceAccountsApi.Delete(Guid serviceAccountId, CancellationToken cancellationToken)
  {
    return await _client.ExecuteApiCall(async () =>
    {
      using var response = await _client.HttpClient.DeleteAsync(
        $"{HttpConstants.Internal.ServiceAccountsEndpoint}/{serviceAccountId}", cancellationToken);
      await response.EnsureSuccessStatusCodeWithDetails();
    });
  }

  async Task<ApiResult<InternalDtos.TenantServiceAccountDto>> IServiceAccountsApi.Get(Guid serviceAccountId, CancellationToken cancellationToken)
  {
    return await _client.ExecuteApiCall(async () =>
      await _client.HttpClient.GetFromJsonAsync<InternalDtos.TenantServiceAccountDto>(
        $"{HttpConstants.Internal.ServiceAccountsEndpoint}/{serviceAccountId}", cancellationToken));
  }

  async Task<ApiResult<InternalDtos.TenantServiceAccountDto[]>> IServiceAccountsApi.GetAll(CancellationToken cancellationToken)
  {
    return await _client.ExecuteApiCall(async () =>
      await _client.HttpClient.GetFromJsonAsync<InternalDtos.TenantServiceAccountDto[]>(HttpConstants.Internal.ServiceAccountsEndpoint, cancellationToken));
  }

  async Task<ApiResult> IServiceAccountsApi.RevokeCredential(Guid serviceAccountId, Guid credentialId, CancellationToken cancellationToken)
  {
    return await _client.ExecuteApiCall(async () =>
    {
      using var response = await _client.HttpClient.DeleteAsync(
        $"{HttpConstants.Internal.ServiceAccountsEndpoint}/{serviceAccountId}/credentials/{credentialId}", cancellationToken);
      await response.EnsureSuccessStatusCodeWithDetails();
    });
  }

  async Task<ApiResult<InternalDtos.TenantServiceAccountDto>> IServiceAccountsApi.Update(Guid serviceAccountId, InternalDtos.UpdateTenantServiceAccountRequestDto request, CancellationToken cancellationToken)
  {
    return await _client.ExecuteApiCall(async () =>
    {
      using var response = await _client.HttpClient.PutAsJsonAsync(
        $"{HttpConstants.Internal.ServiceAccountsEndpoint}/{serviceAccountId}", request, cancellationToken);
      await response.EnsureSuccessStatusCodeWithDetails();
      return await response.Content.ReadFromJsonAsync<InternalDtos.TenantServiceAccountDto>(cancellationToken);
    });
  }
}
