namespace ControlR.Web.Server.Services.LogonTokens;

public sealed record LogonTokenCreationRequest(
  Guid DeviceId,
  Guid TenantId,
  Guid? UserId,
  string? UserCorrelationId,
  string? UserDisplayName,
  string? SessionCorrelationId,
  int ExpirationMinutes,
  IReadOnlyList<InternalDtos.CredentialScopeDto>? Scopes)
{
  public static LogonTokenCreationRequest From(V1Dtos.CreateLogonTokenForExternalRequestDto request)
  {
    return new LogonTokenCreationRequest(
      DeviceId: request.DeviceId,
      TenantId: request.TenantId,
      UserId: null,
      UserCorrelationId: request.UserCorrelationId,
      UserDisplayName: request.UserDisplayName,
      SessionCorrelationId: request.SessionCorrelationId,
      ExpirationMinutes: request.ExpirationMinutes,
      Scopes: ToDeviceScopes(request.Permissions, request.DeviceId));
  }

  public static LogonTokenCreationRequest From(V1Dtos.CreateLogonTokenForUserRequestDto request)
  {
    return new LogonTokenCreationRequest(
      DeviceId: request.DeviceId,
      TenantId: request.TenantId,
      UserId: request.UserId,
      UserCorrelationId: null,
      UserDisplayName: null,
      SessionCorrelationId: request.SessionCorrelationId,
      ExpirationMinutes: request.ExpirationMinutes,
      Scopes: ToDeviceScopes(request.Permissions, request.DeviceId));
  }

  public static LogonTokenCreationRequest From(
    InternalDtos.LogonTokenRequestDto request,
    Guid tenantId,
    Guid userId)
  {
    return new LogonTokenCreationRequest(
      DeviceId: request.DeviceId,
      TenantId: tenantId,
      UserId: userId,
      UserCorrelationId: null,
      UserDisplayName: null,
      SessionCorrelationId: null,
      ExpirationMinutes: request.ExpirationMinutes,
      Scopes: request.Scopes is { Count: > 0 } ? [.. request.Scopes] : null);
  }

  private static IReadOnlyList<InternalDtos.CredentialScopeDto>? ToDeviceScopes(
    IReadOnlyList<string>? permissionNames,
    Guid deviceId)
  {
    if (permissionNames is not { Count: > 0 })
    {
      return null;
    }

    return [.. permissionNames.Select(p =>
      new InternalDtos.CredentialScopeDto(p, PermissionScopeKind.Device, deviceId))];
  }
}
