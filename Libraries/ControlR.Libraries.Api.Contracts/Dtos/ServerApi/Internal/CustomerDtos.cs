using System.ComponentModel.DataAnnotations;

namespace ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

public record CreateCustomerRequestDto(
  [property: Required]
  [property: StringLength(100, MinimumLength = 1)]
  string Name,

  [property: StringLength(500)]
  string? Description,

  [property: StringLength(500)]
  string? Notes);

public record UpdateCustomerRequestDto(
  [property: Required]
  [property: StringLength(100, MinimumLength = 1)]
  string Name,

  [property: StringLength(500)]
  string? Description,

  [property: StringLength(500)]
  string? Notes);

public record CustomerDto(
  Guid Id,
  string Name,
  string? Description,
  string? Notes,
  DateTimeOffset CreatedAt,
  int DeviceCount);
