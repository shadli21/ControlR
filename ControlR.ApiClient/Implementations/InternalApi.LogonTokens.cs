using System.Net.Http.Json;
using ControlR.ApiClient.Interfaces.Internal;
using ControlR.Libraries.Api.Contracts.Constants;
using ControlR.Libraries.Api.Contracts.Dtos;
using InternalDtos = ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

namespace ControlR.ApiClient;

internal partial class InternalApi
{
  async Task<ApiResult<InternalDtos.LogonTokenResponseDto>> ILogonTokensApi.CreateLogonToken(InternalDtos.LogonTokenRequestDto request, CancellationToken cancellationToken)
  {
    return await _client.ExecuteApiCall(async () =>
    {
      using var response = await _client.HttpClient.PostAsJsonAsync(HttpConstants.Internal.LogonTokensEndpoint, request, cancellationToken);
      await response.EnsureSuccessStatusCodeWithDetails();
      return await response.Content.ReadFromJsonAsync<InternalDtos.LogonTokenResponseDto>(cancellationToken);
    });
  }

  async Task<ApiResult<InternalDtos.CredentialScopeDto[]>> ILogonTokensApi.GetScopes(Guid tokenId, CancellationToken cancellationToken)
  {
    return await _client.ExecuteApiCall(async () =>
      await _client.HttpClient.GetFromJsonAsync<InternalDtos.CredentialScopeDto[]>(
        $"{HttpConstants.Internal.LogonTokensEndpoint}/{tokenId}/scopes", cancellationToken));
  }

  async Task<ApiResult> ILogonTokensApi.SetScopes(Guid tokenId, InternalDtos.SetCredentialScopesRequestDto request, CancellationToken cancellationToken)
  {
    return await _client.ExecuteApiCall(async () =>
    {
      using var response = await _client.HttpClient.PutAsJsonAsync(
        $"{HttpConstants.Internal.LogonTokensEndpoint}/{tokenId}/scopes", request, cancellationToken);
      await response.EnsureSuccessStatusCodeWithDetails();
    });
  }
}
