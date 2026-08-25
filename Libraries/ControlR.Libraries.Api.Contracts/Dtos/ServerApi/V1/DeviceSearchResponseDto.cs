namespace ControlR.Libraries.Api.Contracts.Dtos.ServerApi.V1;

public class DeviceSearchResponseDto
{
  public IReadOnlyList<DeviceResponseDto>? Items { get; set; }
  public int TotalItems { get; set; }
}
