using System.ComponentModel.DataAnnotations;

using ControlR.Libraries.Api.Contracts.Constants;

namespace ControlR.Libraries.Api.Contracts.Dtos.ServerApi.V1.ServiceAccounts;

/// <summary>
/// Request to create a server-scoped service account. The access mode is required explicitly;
/// it is never inferred from assignment rows.
/// </summary>
public record CreateServerServiceAccountRequestDto(
  [property: Required]
  [property: StringLength(DtoLimits.ServiceAccountNameMaxLength, MinimumLength = DtoLimits.ServiceAccountNameMinLength)]
  string Name,
  [property: StringLength(DtoLimits.ServiceAccountDescriptionMaxLength)]
  string? Description,
  [property: Required]
  ServiceAccountAccessMode AccessMode);
