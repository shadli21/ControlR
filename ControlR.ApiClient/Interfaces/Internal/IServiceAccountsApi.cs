using ControlR.Libraries.Api.Contracts.Constants;
using ControlR.Libraries.Api.Contracts.Dtos;
using InternalDtos = ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

namespace ControlR.ApiClient.Interfaces.Internal;

public interface IServiceAccountsApi
{
  [ApiRoute($"{HttpConstants.Internal.ServiceAccountsEndpoint}/{{serviceAccountId}}/credentials", "POST")]
  Task<ApiResult<InternalDtos.CreateTenantServiceAccountCredentialResponseDto>> AddCredential(Guid serviceAccountId, InternalDtos.CreateTenantServiceAccountCredentialRequestDto request, CancellationToken cancellationToken = default);

  [ApiRoute($"{HttpConstants.Internal.ServiceAccountsEndpoint}", "POST")]
  Task<ApiResult<InternalDtos.CreateTenantServiceAccountResponseDto>> Create(InternalDtos.CreateTenantServiceAccountRequestDto request, CancellationToken cancellationToken = default);

  [ApiRoute($"{HttpConstants.Internal.ServiceAccountsEndpoint}/{{serviceAccountId}}", "DELETE")]
  Task<ApiResult> Delete(Guid serviceAccountId, CancellationToken cancellationToken = default);

  [ApiRoute($"{HttpConstants.Internal.ServiceAccountsEndpoint}/{{serviceAccountId}}", "GET")]
  Task<ApiResult<InternalDtos.TenantServiceAccountDto>> Get(Guid serviceAccountId, CancellationToken cancellationToken = default);

  [ApiRoute($"{HttpConstants.Internal.ServiceAccountsEndpoint}", "GET")]
  Task<ApiResult<InternalDtos.TenantServiceAccountDto[]>> GetAll(CancellationToken cancellationToken = default);

  [ApiRoute($"{HttpConstants.Internal.ServiceAccountsEndpoint}/{{serviceAccountId}}/credentials/{{credentialId}}", "DELETE")]
  Task<ApiResult> RevokeCredential(Guid serviceAccountId, Guid credentialId, CancellationToken cancellationToken = default);

  [ApiRoute($"{HttpConstants.Internal.ServiceAccountsEndpoint}/{{serviceAccountId}}", "PUT")]
  Task<ApiResult<InternalDtos.TenantServiceAccountDto>> Update(Guid serviceAccountId, InternalDtos.UpdateTenantServiceAccountRequestDto request, CancellationToken cancellationToken = default);
}
