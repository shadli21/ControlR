namespace ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

[MessagePackObject(keyAsPropertyName: true)]
public record LogFileGroupDto(
  string GroupName,
  IReadOnlyList<LogFileEntryDto> LogFiles);
