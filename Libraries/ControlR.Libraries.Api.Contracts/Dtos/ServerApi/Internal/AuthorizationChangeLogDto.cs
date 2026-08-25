namespace ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

public record AuthorizationChangeLogDto(
  Guid Id,
  string ActionType,
  string ActorPrincipalType,
  Guid? ActorPrincipalId,
  string TargetType,
  Guid? TargetId,
  Guid? OwningTenantId,
  string? IpAddress,
  DateTimeOffset CreatedAt,
  string? BeforeJson,
  string? AfterJson);
