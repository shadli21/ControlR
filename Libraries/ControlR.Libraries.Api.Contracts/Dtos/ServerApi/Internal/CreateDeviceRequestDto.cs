using System.ComponentModel.DataAnnotations;

using ControlR.Libraries.Api.Contracts.Dtos.HubDtos;

namespace ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

[MessagePackObject(keyAsPropertyName: true)]
public record CreateDeviceRequestDto(
  [property: Required]
  DeviceUpdateRequestDto Device,
  Guid InstallerKeyId,

  [property: Required]
  string InstallerKeySecret,
  IReadOnlyList<Guid>? TagIds = null,
  string? PublicKey = null,
  Guid? CustomerId = null);
