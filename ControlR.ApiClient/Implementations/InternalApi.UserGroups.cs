using System.Net.Http.Json;
using ControlR.ApiClient.Interfaces.Internal;
using ControlR.Libraries.Api.Contracts.Constants;
using ControlR.Libraries.Api.Contracts.Dtos;
using InternalDtos = ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

namespace ControlR.ApiClient;

internal partial class InternalApi
{
  async Task<ApiResult> IUserGroupsApi.AddMembers(Guid userGroupId, InternalDtos.AddUserGroupMembersRequestDto request, CancellationToken cancellationToken)
  {
    return await _client.ExecuteApiCall(async () =>
    {
      using var response = await _client.HttpClient.PostAsJsonAsync(
        $"{HttpConstants.Internal.UserGroupsEndpoint}/{userGroupId}/members", request, cancellationToken);
      await response.EnsureSuccessStatusCodeWithDetails();
    });
  }

  async Task<ApiResult<InternalDtos.UserGroupDetailDto>> IUserGroupsApi.Create(InternalDtos.CreateUserGroupRequestDto request, CancellationToken cancellationToken)
  {
    return await _client.ExecuteApiCall(async () =>
    {
      using var response = await _client.HttpClient.PostAsJsonAsync(HttpConstants.Internal.UserGroupsEndpoint, request, cancellationToken);
      await response.EnsureSuccessStatusCodeWithDetails();
      return await response.Content.ReadFromJsonAsync<InternalDtos.UserGroupDetailDto>(cancellationToken);
    });
  }

  async Task<ApiResult> IUserGroupsApi.Delete(Guid userGroupId, CancellationToken cancellationToken)
  {
    return await _client.ExecuteApiCall(async () =>
    {
      using var response = await _client.HttpClient.DeleteAsync(
        $"{HttpConstants.Internal.UserGroupsEndpoint}/{userGroupId}", cancellationToken);
      await response.EnsureSuccessStatusCodeWithDetails();
    });
  }

  async Task<ApiResult<InternalDtos.UserGroupDetailDto>> IUserGroupsApi.Get(Guid userGroupId, CancellationToken cancellationToken)
  {
    return await _client.ExecuteApiCall(async () =>
      await _client.HttpClient.GetFromJsonAsync<InternalDtos.UserGroupDetailDto>(
        $"{HttpConstants.Internal.UserGroupsEndpoint}/{userGroupId}", cancellationToken));
  }

  async Task<ApiResult<InternalDtos.UserGroupDto[]>> IUserGroupsApi.GetAll(CancellationToken cancellationToken)
  {
    return await _client.ExecuteApiCall(async () =>
      await _client.HttpClient.GetFromJsonAsync<InternalDtos.UserGroupDto[]>(HttpConstants.Internal.UserGroupsEndpoint, cancellationToken));
  }

  async Task<ApiResult> IUserGroupsApi.RemoveMembers(Guid userGroupId, InternalDtos.RemoveUserGroupMembersRequestDto request, CancellationToken cancellationToken)
  {
    return await _client.ExecuteApiCall(async () =>
    {
      using var response = await _client.HttpClient.SendAsync(new HttpRequestMessage(HttpMethod.Delete,
        $"{HttpConstants.Internal.UserGroupsEndpoint}/{userGroupId}/members")
      {
        Content = JsonContent.Create(request)
      }, cancellationToken);
      await response.EnsureSuccessStatusCodeWithDetails();
    });
  }

  async Task<ApiResult<InternalDtos.UserGroupDetailDto>> IUserGroupsApi.Update(Guid userGroupId, InternalDtos.UpdateUserGroupRequestDto request, CancellationToken cancellationToken)
  {
    return await _client.ExecuteApiCall(async () =>
    {
      using var response = await _client.HttpClient.PutAsJsonAsync(
        $"{HttpConstants.Internal.UserGroupsEndpoint}/{userGroupId}", request, cancellationToken);
      await response.EnsureSuccessStatusCodeWithDetails();
      return await response.Content.ReadFromJsonAsync<InternalDtos.UserGroupDetailDto>(cancellationToken);
    });
  }
}
