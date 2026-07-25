namespace ControlR.Web.Server.Services.LogonTokens;

public sealed record LogonTokenResult(
  string Token,
  Guid TokenId,
  Guid DeviceId,
  Guid TenantId,
  Guid UserId,
  DateTimeOffset ExpiresAt,
  string? SessionCorrelationId = null,
  string? UserCorrelationId = null);
