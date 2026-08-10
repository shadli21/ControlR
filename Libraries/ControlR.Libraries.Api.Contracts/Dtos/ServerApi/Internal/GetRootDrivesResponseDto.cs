namespace ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

[MessagePackObject(keyAsPropertyName: true)]
public record GetRootDrivesResponseDto(
  IReadOnlyList<FileSystemEntryDto> Drives);
