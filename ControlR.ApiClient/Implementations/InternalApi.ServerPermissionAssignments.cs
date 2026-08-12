using System.Net.Http.Json;
using ControlR.ApiClient.Interfaces.Internal;
using ControlR.Libraries.Api.Contracts.Constants;
using ControlR.Libraries.Api.Contracts.Dtos;
using InternalDtos = ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

namespace ControlR.ApiClient;

internal partial class InternalApi
{
  async Task<ApiResult<InternalDtos.PermissionAssignmentDto>> IServerPermissionAssignmentsApi.Create(InternalDtos.CreatePermissionAssignmentRequestDto request, CancellationToken cancellationToken)
  {
    return await _client.ExecuteApiCall(async () =>
    {
      using var response = await _client.HttpClient.PostAsJsonAsync(HttpConstants.Internal.ServerPermissionAssignmentsEndpoint, request, cancellationToken);
      await response.EnsureSuccessStatusCodeWithDetails();
      return await response.Content.ReadFromJsonAsync<InternalDtos.PermissionAssignmentDto>(cancellationToken);
    });
  }

  async Task<ApiResult> IServerPermissionAssignmentsApi.CreateMany(InternalDtos.CreateManyPermissionAssignmentsRequestDto request, CancellationToken cancellationToken)
  {
    return await _client.ExecuteApiCall(async () =>
    {
      using var response = await _client.HttpClient.PostAsJsonAsync(
        $"{HttpConstants.Internal.ServerPermissionAssignmentsEndpoint}/create-many", request, cancellationToken);
      await response.EnsureSuccessStatusCodeWithDetails();
    });
  }

  async Task<ApiResult> IServerPermissionAssignmentsApi.Delete(Guid assignmentId, CancellationToken cancellationToken)
  {
    return await _client.ExecuteApiCall(async () =>
    {
      using var response = await _client.HttpClient.DeleteAsync(
        $"{HttpConstants.Internal.ServerPermissionAssignmentsEndpoint}/{assignmentId}", cancellationToken);
      await response.EnsureSuccessStatusCodeWithDetails();
    });
  }

  async Task<ApiResult<InternalDtos.DeleteManyPermissionAssignmentsResponseDto>> IServerPermissionAssignmentsApi.DeleteMany(InternalDtos.DeleteManyPermissionAssignmentsRequestDto request, CancellationToken cancellationToken)
  {
    return await _client.ExecuteApiCall(async () =>
    {
      using var response = await _client.HttpClient.PostAsJsonAsync(
        $"{HttpConstants.Internal.ServerPermissionAssignmentsEndpoint}/delete-many", request, cancellationToken);
      await response.EnsureSuccessStatusCodeWithDetails();
      return await response.Content.ReadFromJsonAsync<InternalDtos.DeleteManyPermissionAssignmentsResponseDto>(cancellationToken);
    });
  }

  async Task<ApiResult<InternalDtos.PermissionAssignmentDto[]>> IServerPermissionAssignmentsApi.GetByPrincipal(string principalKind, Guid principalId, CancellationToken cancellationToken)
  {
    return await _client.ExecuteApiCall(async () =>
      await _client.HttpClient.GetFromJsonAsync<InternalDtos.PermissionAssignmentDto[]>(
        $"{HttpConstants.Internal.ServerPermissionAssignmentsEndpoint}?principalKind={principalKind}&principalId={principalId}", cancellationToken));
  }

  async Task<ApiResult> IServerPermissionAssignmentsApi.Replace(InternalDtos.ReplacePermissionAssignmentsRequestDto request, CancellationToken cancellationToken)
  {
    return await _client.ExecuteApiCall(async () =>
    {
      using var response = await _client.HttpClient.PostAsJsonAsync(
        $"{HttpConstants.Internal.ServerPermissionAssignmentsEndpoint}/replace", request, cancellationToken);
      await response.EnsureSuccessStatusCodeWithDetails();
    });
  }

  async Task<ApiResult<InternalDtos.PermissionAssignmentDto>> IServerPermissionAssignmentsApi.Update(Guid assignmentId, InternalDtos.UpdatePermissionAssignmentRequestDto request, CancellationToken cancellationToken)
  {
    return await _client.ExecuteApiCall(async () =>
    {
      using var response = await _client.HttpClient.PutAsJsonAsync(
        $"{HttpConstants.Internal.ServerPermissionAssignmentsEndpoint}/{assignmentId}", request, cancellationToken);
      await response.EnsureSuccessStatusCodeWithDetails();
      return await response.Content.ReadFromJsonAsync<InternalDtos.PermissionAssignmentDto>(cancellationToken);
    });
  }
}
