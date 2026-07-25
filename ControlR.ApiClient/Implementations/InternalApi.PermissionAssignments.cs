using System.Net.Http.Json;
using ControlR.ApiClient.Interfaces.Internal;
using ControlR.Libraries.Api.Contracts.Constants;
using ControlR.Libraries.Api.Contracts.Dtos;
using InternalDtos = ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

namespace ControlR.ApiClient;

internal partial class InternalApi
{
  async Task<ApiResult<InternalDtos.PermissionAssignmentDto>> IPermissionAssignmentsApi.Create(InternalDtos.CreatePermissionAssignmentRequestDto request, CancellationToken cancellationToken)
  {
    return await _client.ExecuteApiCall(async () =>
    {
      using var response = await _client.HttpClient.PostAsJsonAsync(HttpConstants.Internal.PermissionAssignmentsEndpoint, request, cancellationToken);
      await response.EnsureSuccessStatusCodeWithDetails();
      return await response.Content.ReadFromJsonAsync<InternalDtos.PermissionAssignmentDto>(cancellationToken);
    });
  }

  async Task<ApiResult<InternalDtos.PermissionAssignmentDto[]>> IPermissionAssignmentsApi.GetByPrincipal(string principalKind, Guid principalId, CancellationToken cancellationToken)
  {
    return await _client.ExecuteApiCall(async () =>
      await _client.HttpClient.GetFromJsonAsync<InternalDtos.PermissionAssignmentDto[]>(
        $"{HttpConstants.Internal.PermissionAssignmentsEndpoint}?principalKind={principalKind}&principalId={principalId}", cancellationToken));
  }

  async Task<ApiResult> IPermissionAssignmentsApi.Delete(Guid assignmentId, CancellationToken cancellationToken)
  {
    return await _client.ExecuteApiCall(async () =>
    {
      using var response = await _client.HttpClient.DeleteAsync(
        $"{HttpConstants.Internal.PermissionAssignmentsEndpoint}/{assignmentId}", cancellationToken);
      await response.EnsureSuccessStatusCodeWithDetails();
    });
  }

  async Task<ApiResult<InternalDtos.EffectivePermissionQueryResponseDto>> IEffectivePermissionsApi.Query(InternalDtos.EffectivePermissionQueryRequestDto request, CancellationToken cancellationToken)
  {
    return await _client.ExecuteApiCall(async () =>
    {
      using var response = await _client.HttpClient.PostAsJsonAsync(
        $"{HttpConstants.Internal.EffectivePermissionsEndpoint}/query", request, cancellationToken);
      await response.EnsureSuccessStatusCodeWithDetails();
      return await response.Content.ReadFromJsonAsync<InternalDtos.EffectivePermissionQueryResponseDto>(cancellationToken);
    });
  }
}
