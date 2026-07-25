using ControlR.Libraries.Api.Contracts.Constants;
using ControlR.Libraries.Api.Contracts.Dtos;
using InternalDtos = ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

namespace ControlR.ApiClient.Interfaces.Internal;

public interface ILogonTokensApi
{
  [ApiRoute($"{HttpConstants.Internal.LogonTokensEndpoint}", "POST")]
  Task<ApiResult<InternalDtos.LogonTokenResponseDto>> CreateLogonToken(InternalDtos.LogonTokenRequestDto request, CancellationToken cancellationToken = default);
  [ApiRoute($"{HttpConstants.Internal.LogonTokensEndpoint}/{{tokenId}}/scopes", "GET")]
  Task<ApiResult<InternalDtos.CredentialScopeDto[]>> GetScopes(Guid tokenId, CancellationToken cancellationToken = default);
  [ApiRoute($"{HttpConstants.Internal.LogonTokensEndpoint}/{{tokenId}}/scopes", "PUT")]
  Task<ApiResult> SetScopes(Guid tokenId, InternalDtos.SetCredentialScopesRequestDto request, CancellationToken cancellationToken = default);
}
