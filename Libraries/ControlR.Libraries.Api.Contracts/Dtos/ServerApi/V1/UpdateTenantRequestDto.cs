using System.ComponentModel.DataAnnotations;

using ControlR.Libraries.Api.Contracts.Constants;

namespace ControlR.Libraries.Api.Contracts.Dtos.ServerApi.V1;

public record UpdateTenantRequestDto(
  [property: Required]
  [property: StringLength(DtoLimits.TenantNameMaxLength)]
  string Name);
