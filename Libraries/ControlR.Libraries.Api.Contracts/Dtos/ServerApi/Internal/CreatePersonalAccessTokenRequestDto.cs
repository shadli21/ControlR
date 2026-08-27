using System.ComponentModel.DataAnnotations;

using ControlR.Libraries.Api.Contracts.Enums;

namespace ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

public record CreatePersonalAccessTokenRequestDto(
  [property: Required]
  [property: StringLength(256, MinimumLength = 1)]
  string Name,
  PersonalAccessTokenPermissionMode PermissionMode,
  IReadOnlyList<CredentialScopeDto>? Scopes = null);
