namespace ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

/// <summary>
/// Request to set (replace) the scopes on a credential (PAT or logon token).
/// An empty list clears all scope rows.
/// </summary>
public record SetCredentialScopesRequestDto(
  List<CredentialScopeDto> Scopes);
