namespace ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

public record AuthorizationChangeLogSearchResponseDto(
  IReadOnlyList<AuthorizationChangeLogDto> Items,
  int TotalItems);
