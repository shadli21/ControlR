using ControlR.Libraries.Api.Contracts.Dtos.ServerApi.V1;
using ControlR.Libraries.Api.Contracts.Dtos.ServerApi.V1.ServiceAccounts;
using ControlR.Web.Server.Services.Tenants;

namespace ControlR.Web.Server.Extensions.Dtos.V1;

/// <summary>
/// Maps business-layer service account results to V1 API DTOs.
/// Keeps the stable public contract decoupled from internal service models.
/// </summary>
internal static class ModelToV1DtoExtensions
{
  public static ServiceAccountDto ToDto(this ServiceAccountResult result)
  {
    return new ServiceAccountDto(
      result.Id,
      result.Name,
      result.Description,
      result.Kind,
      result.IsEnabled,
      result.AccessMode,
      result.CreatedAt,
      [.. result.Credentials.Select(c => c.ToDto())]);
  }

  public static ServiceAccountCredentialDto ToDto(this ServiceAccountCredentialResult result)
  {
    return new ServiceAccountCredentialDto(
      result.Id,
      result.Name,
      result.CreatedAt,
      result.ExpiresAt,
      result.RevokedAt,
      result.LastUsedAt);
  }

  public static CreateServiceAccountCredentialResponseDto ToDto(this CreateServiceAccountCredentialResult result)
  {
    return new CreateServiceAccountCredentialResponseDto(result.Credential.ToDto(), result.PlainTextSecretKey);
  }

  public static CreateTenantResponseDto ToV1CreateTenantDto(this TenantResult result)
  {
    return new CreateTenantResponseDto(
      result.Id,
      result.Name);
  }

  public static GetTenantResponseDto ToV1GetTenantDto(this TenantResult result)
  {
    return new GetTenantResponseDto(
      result.Id,
      result.Name);
  }
}
