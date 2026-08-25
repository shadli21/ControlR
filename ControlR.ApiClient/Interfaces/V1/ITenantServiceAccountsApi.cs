using ControlR.Libraries.Api.Contracts.Constants;
using ControlR.Libraries.Api.Contracts.Dtos;
using ControlR.Libraries.Api.Contracts.Dtos.ServerApi.V1.ServiceAccounts;

namespace ControlR.ApiClient.Interfaces.V1;

public interface ITenantServiceAccountsApi
{
  [ApiRoute($"{HttpConstants.V1.TenantServiceAccountsEndpoint}/{{tenantId}}/{{serviceAccountId}}/credentials", "POST")]
  Task<ApiResult<CreateServiceAccountCredentialResponseDto>> AddCredential(Guid tenantId, Guid serviceAccountId, CreateServiceAccountCredentialRequestDto request, CancellationToken cancellationToken = default);

  [ApiRoute($"{HttpConstants.V1.TenantServiceAccountsEndpoint}/{{tenantId}}", "POST")]
  Task<ApiResult<ServiceAccountDto>> Create(Guid tenantId, CreateServiceAccountRequestDto request, CancellationToken cancellationToken = default);

  [ApiRoute($"{HttpConstants.V1.TenantServiceAccountsEndpoint}/{{tenantId}}/{{serviceAccountId}}", "DELETE")]
  Task<ApiResult> Delete(Guid tenantId, Guid serviceAccountId, CancellationToken cancellationToken = default);

  [ApiRoute($"{HttpConstants.V1.TenantServiceAccountsEndpoint}/{{tenantId}}/{{serviceAccountId}}", "GET")]
  Task<ApiResult<ServiceAccountDto>> Get(Guid tenantId, Guid serviceAccountId, CancellationToken cancellationToken = default);

  [ApiRoute($"{HttpConstants.V1.TenantServiceAccountsEndpoint}/{{tenantId}}", "GET")]
  Task<ApiResult<ServiceAccountsResponseDto>> GetAll(Guid tenantId, CancellationToken cancellationToken = default);

  [ApiRoute($"{HttpConstants.V1.TenantServiceAccountsEndpoint}/{{tenantId}}/{{serviceAccountId}}/credentials/{{credentialId}}", "DELETE")]
  Task<ApiResult> RevokeCredential(Guid tenantId, Guid serviceAccountId, Guid credentialId, CancellationToken cancellationToken = default);

  [ApiRoute($"{HttpConstants.V1.TenantServiceAccountsEndpoint}/{{tenantId}}/{{serviceAccountId}}", "PUT")]
  Task<ApiResult<ServiceAccountDto>> Update(Guid tenantId, Guid serviceAccountId, UpdateServiceAccountRequestDto request, CancellationToken cancellationToken = default);
}
