namespace ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

public record AuthorizationChangeLogDto(
  Guid Id,
  string ActionType,
  string ActorPrincipalType,
  string? ActorPrincipalId,
  string TargetType,
  string? TargetId,
  Guid? OwningTenantId,
  string? IpAddress,
  DateTimeOffset CreatedAt,
  string? BeforeJson,
  string? AfterJson);
