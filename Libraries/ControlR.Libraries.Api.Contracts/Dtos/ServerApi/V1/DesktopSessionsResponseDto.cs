namespace ControlR.Libraries.Api.Contracts.Dtos.ServerApi.V1;

public class DesktopSessionsResponseDto
{
  public IReadOnlyList<DesktopSessionResponseDto> Items { get; set; } = [];
}