using ControlR.Libraries.Api.Contracts.Constants;
using ControlR.Libraries.Api.Contracts.Dtos;
using ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

namespace ControlR.ApiClient.Interfaces.Internal;

public interface IPersonalAccessTokensApi
{
  [ApiRoute($"{HttpConstants.Internal.PersonalAccessTokensEndpoint}", "POST")]
  Task<ApiResult<CreatePersonalAccessTokenResponseDto>> CreatePersonalAccessToken(CreatePersonalAccessTokenRequestDto request, CancellationToken cancellationToken = default);
  [ApiRoute($"{HttpConstants.Internal.PersonalAccessTokensEndpoint}/{{personalAccessTokenId}}", "DELETE")]
  Task<ApiResult> DeletePersonalAccessToken(Guid personalAccessTokenId, CancellationToken cancellationToken = default);
  [ApiRoute($"{HttpConstants.Internal.PersonalAccessTokensEndpoint}", "GET")]
  Task<ApiResult<PersonalAccessTokenResponseDto[]>> GetPersonalAccessTokens(CancellationToken cancellationToken = default);
  [ApiRoute($"{HttpConstants.Internal.PersonalAccessTokensEndpoint}/{{id}}/scopes", "GET")]
  Task<ApiResult<CredentialScopeDto[]>> GetScopes(Guid id, CancellationToken cancellationToken = default);
  [ApiRoute($"{HttpConstants.Internal.PersonalAccessTokensEndpoint}/{{id}}/scopes", "PUT")]
  Task<ApiResult> SetScopes(Guid id, SetCredentialScopesRequestDto request, CancellationToken cancellationToken = default);
  [ApiRoute($"{HttpConstants.Internal.PersonalAccessTokensEndpoint}/{{personalAccessTokenId}}", "PUT")]
  Task<ApiResult<PersonalAccessTokenResponseDto>> UpdatePersonalAccessToken(Guid personalAccessTokenId, UpdatePersonalAccessTokenRequestDto request, CancellationToken cancellationToken = default);
}
