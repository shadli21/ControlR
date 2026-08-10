using System.ComponentModel.DataAnnotations;

using ControlR.Libraries.Api.Contracts.Constants;

namespace ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

[MessagePackObject(keyAsPropertyName: true)]
public record DeleteDevicesRequestDto(IReadOnlyList<Guid> DeviceIds)
{
  [MaxLength(DtoLimits.DeviceIdsMaxCount)]
  public IReadOnlyList<Guid> DeviceIds { get; init; } = DeviceIds;
}
