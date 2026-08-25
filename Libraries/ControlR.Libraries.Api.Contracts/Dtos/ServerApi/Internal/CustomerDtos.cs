using System.ComponentModel.DataAnnotations;

using ControlR.Libraries.Api.Contracts.Constants;

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

public record AssignCustomerDevicesRequestDto(
  [property: Required]
  [property: MaxLength(DtoLimits.DeviceIdsMaxCount)]
  IReadOnlyList<Guid> DeviceIds,

  [property: Required]
  [property: MaxLength(DtoLimits.DeviceIdsMaxCount)]
  IReadOnlyList<Guid> RemoveDeviceIds);
