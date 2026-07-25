using ControlR.Libraries.Api.Contracts.Constants;
using ControlR.Libraries.Api.Contracts.Dtos;
using InternalDtos = ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

namespace ControlR.ApiClient.Interfaces.Internal;

public interface IPermissionAssignmentsApi
{
  [ApiRoute($"{HttpConstants.Internal.PermissionAssignmentsEndpoint}", "POST")]
  Task<ApiResult<InternalDtos.PermissionAssignmentDto>> Create(InternalDtos.CreatePermissionAssignmentRequestDto request, CancellationToken cancellationToken = default);
  [ApiRoute($"{HttpConstants.Internal.PermissionAssignmentsEndpoint}", "GET")]
  Task<ApiResult<InternalDtos.PermissionAssignmentDto[]>> GetByPrincipal(string principalKind, Guid principalId, CancellationToken cancellationToken = default);
  [ApiRoute($"{HttpConstants.Internal.PermissionAssignmentsEndpoint}/{{assignmentId}}", "DELETE")]
  Task<ApiResult> Delete(Guid assignmentId, CancellationToken cancellationToken = default);
}

public interface IEffectivePermissionsApi
{
  [ApiRoute($"{HttpConstants.Internal.EffectivePermissionsEndpoint}/query", "POST")]
  Task<ApiResult<InternalDtos.EffectivePermissionQueryResponseDto>> Query(InternalDtos.EffectivePermissionQueryRequestDto request, CancellationToken cancellationToken = default);
}
