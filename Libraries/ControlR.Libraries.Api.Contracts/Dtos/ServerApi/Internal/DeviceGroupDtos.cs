using System.ComponentModel.DataAnnotations;

namespace ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

public record CreateDeviceGroupRequestDto(
  [property: Required]
  [property: StringLength(100, MinimumLength = 1)]
  string Name,

  [property: StringLength(500)]
  string? Description);

public record UpdateDeviceGroupRequestDto(
  [property: Required]
  [property: StringLength(100, MinimumLength = 1)]
  string Name,

  [property: StringLength(500)]
  string? Description);

public record DeviceGroupMemberDto(
  Guid DeviceId,
  string DeviceName,
  string? Alias,
  string? CustomerName);

public record DeviceGroupDto(
  Guid Id,
  string Name,
  string? Description,
  DateTimeOffset CreatedAt,
  int MemberCount);

public record DeviceGroupDetailDto(
  Guid Id,
  string Name,
  string? Description,
  DateTimeOffset CreatedAt,
  IReadOnlyList<DeviceGroupMemberDto> Members);

public record AddDeviceGroupMembersRequestDto(
  [property: Required]
  IReadOnlyList<Guid> DeviceIds);

public record RemoveDeviceGroupMembersRequestDto(
  [property: Required]
  IReadOnlyList<Guid> DeviceIds);
