using System.Net.Http.Json;
using ControlR.ApiClient.Interfaces.Internal;
using ControlR.Libraries.Api.Contracts.Constants;
using ControlR.Libraries.Api.Contracts.Dtos;
using InternalDtos = ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

namespace ControlR.ApiClient;

internal partial class InternalApi
{
  async Task<ApiResult> IDeviceGroupsApi.AddMembers(Guid deviceGroupId, InternalDtos.AddDeviceGroupMembersRequestDto request, CancellationToken cancellationToken)
  {
    return await _client.ExecuteApiCall(async () =>
    {
      using var response = await _client.HttpClient.PostAsJsonAsync(
        $"{HttpConstants.Internal.DeviceGroupsEndpoint}/{deviceGroupId}/members", request, cancellationToken);
      await response.EnsureSuccessStatusCodeWithDetails();
    });
  }

  async Task<ApiResult<InternalDtos.DeviceGroupDetailDto>> IDeviceGroupsApi.Create(InternalDtos.CreateDeviceGroupRequestDto request, CancellationToken cancellationToken)
  {
    return await _client.ExecuteApiCall(async () =>
    {
      using var response = await _client.HttpClient.PostAsJsonAsync(HttpConstants.Internal.DeviceGroupsEndpoint, request, cancellationToken);
      await response.EnsureSuccessStatusCodeWithDetails();
      return await response.Content.ReadFromJsonAsync<InternalDtos.DeviceGroupDetailDto>(cancellationToken);
    });
  }

  async Task<ApiResult> IDeviceGroupsApi.Delete(Guid deviceGroupId, CancellationToken cancellationToken)
  {
    return await _client.ExecuteApiCall(async () =>
    {
      using var response = await _client.HttpClient.DeleteAsync(
        $"{HttpConstants.Internal.DeviceGroupsEndpoint}/{deviceGroupId}", cancellationToken);
      await response.EnsureSuccessStatusCodeWithDetails();
    });
  }

  async Task<ApiResult<InternalDtos.DeviceGroupDetailDto>> IDeviceGroupsApi.Get(Guid deviceGroupId, CancellationToken cancellationToken)
  {
    return await _client.ExecuteApiCall(async () =>
      await _client.HttpClient.GetFromJsonAsync<InternalDtos.DeviceGroupDetailDto>(
        $"{HttpConstants.Internal.DeviceGroupsEndpoint}/{deviceGroupId}", cancellationToken));
  }

  async Task<ApiResult<InternalDtos.DeviceGroupDto[]>> IDeviceGroupsApi.GetAll(CancellationToken cancellationToken)
  {
    return await _client.ExecuteApiCall(async () =>
      await _client.HttpClient.GetFromJsonAsync<InternalDtos.DeviceGroupDto[]>(HttpConstants.Internal.DeviceGroupsEndpoint, cancellationToken));
  }

  async Task<ApiResult> IDeviceGroupsApi.RemoveMembers(Guid deviceGroupId, InternalDtos.RemoveDeviceGroupMembersRequestDto request, CancellationToken cancellationToken)
  {
    return await _client.ExecuteApiCall(async () =>
    {
      using var response = await _client.HttpClient.SendAsync(new HttpRequestMessage(HttpMethod.Delete,
        $"{HttpConstants.Internal.DeviceGroupsEndpoint}/{deviceGroupId}/members")
      {
        Content = JsonContent.Create(request)
      }, cancellationToken);
      await response.EnsureSuccessStatusCodeWithDetails();
    });
  }

  async Task<ApiResult<InternalDtos.DeviceGroupDetailDto>> IDeviceGroupsApi.Update(Guid deviceGroupId, InternalDtos.UpdateDeviceGroupRequestDto request, CancellationToken cancellationToken)
  {
    return await _client.ExecuteApiCall(async () =>
    {
      using var response = await _client.HttpClient.PutAsJsonAsync(
        $"{HttpConstants.Internal.DeviceGroupsEndpoint}/{deviceGroupId}", request, cancellationToken);
      await response.EnsureSuccessStatusCodeWithDetails();
      return await response.Content.ReadFromJsonAsync<InternalDtos.DeviceGroupDetailDto>(cancellationToken);
    });
  }
}
