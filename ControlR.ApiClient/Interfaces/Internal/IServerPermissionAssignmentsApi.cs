using ControlR.Libraries.Api.Contracts.Constants;
using ControlR.Libraries.Api.Contracts.Dtos;
using InternalDtos = ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

namespace ControlR.ApiClient.Interfaces.Internal;

public interface IServerPermissionAssignmentsApi
{
  [ApiRoute($"{HttpConstants.Internal.ServerPermissionAssignmentsEndpoint}", "POST")]
  Task<ApiResult<InternalDtos.PermissionAssignmentDto>> Create(InternalDtos.CreatePermissionAssignmentRequestDto request, CancellationToken cancellationToken = default);

  [ApiRoute($"{HttpConstants.Internal.ServerPermissionAssignmentsEndpoint}/create-many", "POST")]
  Task<ApiResult> CreateMany(InternalDtos.CreateManyPermissionAssignmentsRequestDto request, CancellationToken cancellationToken = default);

  [ApiRoute($"{HttpConstants.Internal.ServerPermissionAssignmentsEndpoint}/{{assignmentId}}", "DELETE")]
  Task<ApiResult> Delete(Guid assignmentId, CancellationToken cancellationToken = default);

  [ApiRoute($"{HttpConstants.Internal.ServerPermissionAssignmentsEndpoint}/delete-many", "POST")]
  Task<ApiResult<InternalDtos.DeleteManyPermissionAssignmentsResponseDto>> DeleteMany(InternalDtos.DeleteManyPermissionAssignmentsRequestDto request, CancellationToken cancellationToken = default);

  [ApiRoute($"{HttpConstants.Internal.ServerPermissionAssignmentsEndpoint}", "GET")]
  Task<ApiResult<InternalDtos.PermissionAssignmentDto[]>> GetByPrincipal(string principalKind, Guid principalId, CancellationToken cancellationToken = default);

  [ApiRoute($"{HttpConstants.Internal.ServerPermissionAssignmentsEndpoint}/replace", "POST")]
  Task<ApiResult> Replace(InternalDtos.ReplacePermissionAssignmentsRequestDto request, CancellationToken cancellationToken = default);

  [ApiRoute($"{HttpConstants.Internal.ServerPermissionAssignmentsEndpoint}/{{assignmentId}}", "PUT")]
  Task<ApiResult<InternalDtos.PermissionAssignmentDto>> Update(Guid assignmentId, InternalDtos.UpdatePermissionAssignmentRequestDto request, CancellationToken cancellationToken = default);
}
