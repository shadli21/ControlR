using ControlR.Libraries.Api.Contracts.Constants;
using ControlR.Libraries.Api.Contracts.Dtos;
using InternalDtos = ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

namespace ControlR.ApiClient.Interfaces.Internal;

public interface IUserGroupsApi
{
  [ApiRoute($"{HttpConstants.Internal.UserGroupsEndpoint}/{{userGroupId}}/members", "POST")]
  Task<ApiResult> AddMembers(Guid userGroupId, InternalDtos.AddUserGroupMembersRequestDto request, CancellationToken cancellationToken = default);

  [ApiRoute($"{HttpConstants.Internal.UserGroupsEndpoint}", "POST")]
  Task<ApiResult<InternalDtos.UserGroupDetailDto>> Create(InternalDtos.CreateUserGroupRequestDto request, CancellationToken cancellationToken = default);

  [ApiRoute($"{HttpConstants.Internal.UserGroupsEndpoint}/{{userGroupId}}", "DELETE")]
  Task<ApiResult> Delete(Guid userGroupId, CancellationToken cancellationToken = default);

  [ApiRoute($"{HttpConstants.Internal.UserGroupsEndpoint}/{{userGroupId}}", "GET")]
  Task<ApiResult<InternalDtos.UserGroupDetailDto>> Get(Guid userGroupId, CancellationToken cancellationToken = default);

  [ApiRoute($"{HttpConstants.Internal.UserGroupsEndpoint}", "GET")]
  Task<ApiResult<InternalDtos.UserGroupDto[]>> GetAll(CancellationToken cancellationToken = default);

  [ApiRoute($"{HttpConstants.Internal.UserGroupsEndpoint}/{{userGroupId}}/members", "DELETE")]
  Task<ApiResult> RemoveMembers(Guid userGroupId, InternalDtos.RemoveUserGroupMembersRequestDto request, CancellationToken cancellationToken = default);

  [ApiRoute($"{HttpConstants.Internal.UserGroupsEndpoint}/{{userGroupId}}", "PUT")]
  Task<ApiResult<InternalDtos.UserGroupDetailDto>> Update(Guid userGroupId, InternalDtos.UpdateUserGroupRequestDto request, CancellationToken cancellationToken = default);
}
