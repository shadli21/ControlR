using System.ComponentModel.DataAnnotations;

namespace ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

public record CreateServerServiceAccountRequestDto(
  [property: Required]
  [property: StringLength(100, MinimumLength = 1)]
  string Name,

  [property: StringLength(500)]
  string? Description);

public record UpdateServerServiceAccountRequestDto(
  [property: Required]
  [property: StringLength(100, MinimumLength = 1)]
  string Name,

  [property: StringLength(500)]
  string? Description,

  bool IsEnabled);

public record CreateServerServiceAccountCredentialRequestDto(
  [property: Required]
  [property: StringLength(100, MinimumLength = 1)]
  string Name);

public record ServerServiceAccountCredentialDto(
  Guid Id,
  string Name,
  DateTimeOffset CreatedAt,
  DateTimeOffset? ExpiresAt,
  DateTimeOffset? RevokedAt,
  DateTimeOffset? LastUsedAt);

public record ServerServiceAccountDto(
  Guid Id,
  string Name,
  string? Description,
  bool IsEnabled,
  DateTimeOffset CreatedAt,
  IReadOnlyList<ServerServiceAccountCredentialDto> Credentials);

public record CreateServerServiceAccountResponseDto(
  ServerServiceAccountDto ServiceAccount,
  string PlainTextSecretKey);

public record CreateServerServiceAccountCredentialResponseDto(
  ServerServiceAccountCredentialDto Credential,
  string PlainTextSecretKey);
