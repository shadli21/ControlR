using ControlR.Libraries.Api.Contracts.Enums;

namespace ControlR.Libraries.Api.Contracts.Dtos.ServerApi.V1.ServiceAccounts;

public record ServiceAccountDto(
  Guid Id,
  string Name,
  string? Description,
  ServiceAccountKind Kind,
  bool IsEnabled,
  /// <summary>
  /// The access mode for server-scoped accounts. Non-null when <see cref="Kind"/>
  /// is <see cref="ServiceAccountKind.Server"/> (server accounts always carry an
  /// explicit mode set by <c>ServiceAccountManager.CreateForServer</c>).
  /// Null for tenant-scoped accounts, which are not governed by the mode and never bypass.
  /// </summary>
  ServiceAccountAccessMode? AccessMode,
  DateTimeOffset CreatedAt,
  IReadOnlyList<ServiceAccountCredentialDto> Credentials);

