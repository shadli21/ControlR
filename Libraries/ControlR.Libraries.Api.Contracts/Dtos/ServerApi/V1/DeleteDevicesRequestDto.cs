using System.ComponentModel.DataAnnotations;

using ControlR.Libraries.Api.Contracts.Constants;

namespace ControlR.Libraries.Api.Contracts.Dtos.ServerApi.V1;

[MessagePackObject(keyAsPropertyName: true)]
public record DeleteDevicesRequestDto(
  [property: Required]
  [property: MaxLength(DtoLimits.DeviceIdsMaxCount)] IReadOnlyList<Guid> DeviceIds);
