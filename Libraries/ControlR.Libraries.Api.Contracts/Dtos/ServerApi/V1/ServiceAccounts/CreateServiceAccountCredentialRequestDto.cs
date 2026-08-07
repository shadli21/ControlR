using System.ComponentModel.DataAnnotations;

using ControlR.Libraries.Api.Contracts.Constants;

namespace ControlR.Libraries.Api.Contracts.Dtos.ServerApi.V1.ServiceAccounts;

public record CreateServiceAccountCredentialRequestDto(
  [property: Required]
  [property: StringLength(DtoLimits.ServiceAccountNameMaxLength, MinimumLength = DtoLimits.ServiceAccountNameMinLength)]
  string Name);
