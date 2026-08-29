namespace ControlR.Libraries.Api.Contracts.Dtos.ServerApi.V1.ServiceAccounts;

/// <summary>
/// V1 response for a tenant-scoped service account. Tenant-scoped accounts are
/// not governed by an access mode and never bypass permission evaluation,
/// so this DTO intentionally omits <see cref="ServiceAccountAccessMode"/>.
/// </summary>
public record TenantServiceAccountDto(
  Guid Id,
  string Name,
  string? Description,
  bool IsEnabled,
  DateTimeOffset CreatedAt,
  IReadOnlyList<ServiceAccountCredentialDto> Credentials);
