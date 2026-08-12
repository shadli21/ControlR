using System.ComponentModel.DataAnnotations;

namespace ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

public record CreateTenantServiceAccountRequestDto(
  [property: Required]
  [property: StringLength(100, MinimumLength = 1)]
  string Name,

  [property: StringLength(500)]
  string? Description);

public record UpdateTenantServiceAccountRequestDto(
  [property: Required]
  [property: StringLength(100, MinimumLength = 1)]
  string Name,

  [property: StringLength(500)]
  string? Description,

  bool IsEnabled);

public record CreateTenantServiceAccountCredentialRequestDto(
  [property: Required]
  [property: StringLength(100, MinimumLength = 1)]
  string Name,

  DateTimeOffset? ExpiresAt = null);

public record TenantServiceAccountCredentialDto(
  Guid Id,
  string Name,
  DateTimeOffset CreatedAt,
  DateTimeOffset? ExpiresAt,
  DateTimeOffset? RevokedAt,
  DateTimeOffset? LastUsedAt);

public record TenantServiceAccountDto(
  Guid Id,
  string Name,
  string? Description,
  bool IsEnabled,
  DateTimeOffset CreatedAt,
  IReadOnlyList<TenantServiceAccountCredentialDto> Credentials);

public record CreateTenantServiceAccountCredentialResponseDto(
  TenantServiceAccountCredentialDto Credential,
  string PlainTextSecretKey);
