using ControlR.Libraries.Api.Contracts.Enums;

namespace ControlR.Libraries.Api.Contracts.Dtos.ServerApi.V1.ServiceAccounts;

public record ServiceAccountDto(
  Guid Id,
  string Name,
  string? Description,
  ServiceAccountKind Kind,
  bool IsEnabled,
  /// <summary>
  /// The access mode for server-scoped accounts. Null for tenant-scoped accounts,
  /// which are not governed by the mode and never bypass.
  /// </summary>
  ServiceAccountAccessMode? AccessMode,
  DateTimeOffset CreatedAt,
  IReadOnlyList<ServiceAccountCredentialDto> Credentials);

