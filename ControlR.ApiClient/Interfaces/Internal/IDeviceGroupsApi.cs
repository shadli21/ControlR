using ControlR.Libraries.Api.Contracts.Constants;
using ControlR.Libraries.Api.Contracts.Dtos;
using InternalDtos = ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

namespace ControlR.ApiClient.Interfaces.Internal;

public interface IDeviceGroupsApi
{
  [ApiRoute($"{HttpConstants.Internal.DeviceGroupsEndpoint}/{{deviceGroupId}}/members", "POST")]
  Task<ApiResult> AddMembers(Guid deviceGroupId, InternalDtos.AddDeviceGroupMembersRequestDto request, CancellationToken cancellationToken = default);

  [ApiRoute($"{HttpConstants.Internal.DeviceGroupsEndpoint}", "POST")]
  Task<ApiResult<InternalDtos.DeviceGroupDetailDto>> Create(InternalDtos.CreateDeviceGroupRequestDto request, CancellationToken cancellationToken = default);

  [ApiRoute($"{HttpConstants.Internal.DeviceGroupsEndpoint}/{{deviceGroupId}}", "DELETE")]
  Task<ApiResult> Delete(Guid deviceGroupId, CancellationToken cancellationToken = default);

  [ApiRoute($"{HttpConstants.Internal.DeviceGroupsEndpoint}/{{deviceGroupId}}", "GET")]
  Task<ApiResult<InternalDtos.DeviceGroupDetailDto>> Get(Guid deviceGroupId, CancellationToken cancellationToken = default);

  [ApiRoute($"{HttpConstants.Internal.DeviceGroupsEndpoint}", "GET")]
  Task<ApiResult<InternalDtos.DeviceGroupDto[]>> GetAll(CancellationToken cancellationToken = default);

  [ApiRoute($"{HttpConstants.Internal.DeviceGroupsEndpoint}/{{deviceGroupId}}/members", "DELETE")]
  Task<ApiResult> RemoveMembers(Guid deviceGroupId, InternalDtos.RemoveDeviceGroupMembersRequestDto request, CancellationToken cancellationToken = default);

  [ApiRoute($"{HttpConstants.Internal.DeviceGroupsEndpoint}/{{deviceGroupId}}", "PUT")]
  Task<ApiResult<InternalDtos.DeviceGroupDetailDto>> Update(Guid deviceGroupId, InternalDtos.UpdateDeviceGroupRequestDto request, CancellationToken cancellationToken = default);
}
