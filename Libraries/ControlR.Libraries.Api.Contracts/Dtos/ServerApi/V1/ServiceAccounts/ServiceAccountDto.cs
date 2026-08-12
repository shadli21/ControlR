using ControlR.Libraries.Api.Contracts.Enums;

namespace ControlR.Libraries.Api.Contracts.Dtos.ServerApi.V1.ServiceAccounts;

public record ServiceAccountDto(
  Guid Id,
  string Name,
  string? Description,
  ServiceAccountKind Kind,
  bool IsEnabled,
  DateTimeOffset CreatedAt,
  IReadOnlyList<ServiceAccountCredentialDto> Credentials);

