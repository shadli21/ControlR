using ControlR.Web.Server.Authn;
using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Primitives;
using ControlR.Web.Server.Services.Authorization;

namespace ControlR.Web.Server.Services.LogonTokens;

public interface ILogonTokenScopeService
{
  Task<HttpResult<LogonTokenResult>> CreateTokenWithScopes(
    LogonTokenCreationRequest request,
    PrincipalDescriptor creator,
    CancellationToken cancellationToken);
}

public class LogonTokenScopeService(
  AppDb appDb,
  ICredentialScopeService credentialScopeService,
  ILogonTokenProvider logonTokenProvider,
  ILogger<LogonTokenScopeService> logger) : ILogonTokenScopeService
{
  private readonly AppDb _appDb = appDb;
  private readonly ICredentialScopeService _credentialScopeService = credentialScopeService;
  private readonly ILogger<LogonTokenScopeService> _logger = logger;
  private readonly ILogonTokenProvider _logonTokenProvider = logonTokenProvider;

  public async Task<HttpResult<LogonTokenResult>> CreateTokenWithScopes(
    LogonTokenCreationRequest request,
    PrincipalDescriptor creator,
    CancellationToken cancellationToken)
  {
    var preparation = await PrepareScopes(
      request.Scopes, request.DeviceId, request.TenantId, creator, cancellationToken);
    if (!preparation.IsSuccess)
    {
      return HttpResult.Fail<LogonTokenResult>(preparation.ErrorCode, preparation.Reason);
    }

    return await CreateTokenAndWriteScopes(
      preparation.Value,
      request,
      cancellationToken);
  }

  /// <summary>
  /// Best-effort removal of a token whose explicit-scope write failed. The token was created
  /// without grants (baseline grants are suppressed when explicit scopes are supplied), so only the
  /// token row needs removal. If this cleanup itself fails, the token is left for the expired-token
  /// cleanup service.
  /// </summary>
  private async Task CleanupOrphanedToken(Guid tokenId, int attemptedScopeCount, CancellationToken cancellationToken)
  {
    try
    {
      var orphaned = await _appDb.LogonTokens.FirstOrDefaultAsync(x => x.Id == tokenId, cancellationToken);
      if (orphaned is null)
      {
        return;
      }

      _appDb.AuthorizationChangeLogs.Add(AuthorizationChangeLogFactory.Create(
        AuthorizationChangeLogActions.CredentialScopeSetFailed,
        AuthorizationChangeLogActorTypes.System,
        actorPrincipalId: null,
        AuthorizationChangeLogTargetTypes.LogonToken,
        tokenId.ToString(),
        orphaned.TenantId,
        after: new CredentialScopeSetFailureSummary(attemptedScopeCount, "scope-write-failed")));

      _appDb.LogonTokens.Remove(orphaned);
      await _appDb.SaveChangesAsync(cancellationToken);

      _logger.LogInformation("Removed orphaned logon token {TokenId} after failed credential scope write.", tokenId);
    }
    catch (Exception ex)
    {
      _logger.LogError(
        ex,
        "Failed to remove orphaned logon token {TokenId} after a failed credential scope write. It will be removed by the expired-token cleanup.",
        tokenId);
    }
  }

  private Task<HttpResult<LogonTokenResult>> CreateToken(
    LogonTokenCreationRequest request,
    bool writeBaselineGrants,
    CancellationToken cancellationToken)
  {
    if (request.UserCorrelationId is not null)
    {
      return _logonTokenProvider.CreateTokenForExternal(
        request.DeviceId,
        request.TenantId,
        request.UserCorrelationId,
        request.ExpirationMinutes,
        userDisplayName: request.UserDisplayName,
        sessionCorrelationId: request.SessionCorrelationId,
        writeBaselineGrants: writeBaselineGrants,
        cancellationToken: cancellationToken);
    }

    var userId = request.UserId
      ?? throw new InvalidOperationException("LogonTokenCreationRequest must have either UserId or UserCorrelationId.");

    return _logonTokenProvider.CreateToken(
      request.DeviceId,
      request.TenantId,
      userId,
      request.ExpirationMinutes,
      sessionCorrelationId: request.SessionCorrelationId,
      writeBaselineGrants: writeBaselineGrants,
      cancellationToken: cancellationToken);
  }

  /// <summary>
  /// Creates the token, then writes the explicit scopes when supplied. When explicit scopes are
  /// present the token is created without the baseline grants and the explicit scopes are written
  /// as a follow-up step; if that step fails the token is removed. The token secret is only ever
  /// returned after both steps succeed, so no usable token exists until the grants are in place.
  /// </summary>
  private async Task<HttpResult<LogonTokenResult>> CreateTokenAndWriteScopes(
    ScopePreparation preparation,
    LogonTokenCreationRequest request,
    CancellationToken cancellationToken)
  {
    var result = await CreateToken(request, preparation.ExplicitScopes is null, cancellationToken);
    if (!result.IsSuccess || preparation.ExplicitScopes is null)
    {
      return result;
    }

    try
    {
      await _credentialScopeService.WriteLogonTokenScopes(
        result.Value.TokenId,
        request.DeviceId,
        request.TenantId,
        preparation.ActorType,
        preparation.Creator.PrincipalId,
        preparation.ExplicitScopes,
        cancellationToken);

      return result;
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "Failed to write credential scopes for logon token {TokenId}.", result.Value.TokenId);
      await CleanupOrphanedToken(result.Value.TokenId, preparation.ExplicitScopes.Count, cancellationToken);
      return HttpResult.Fail<LogonTokenResult>(
        HttpResultErrorCode.InternalServerError,
        "Failed to write credential scopes.");
    }
  }

  private string MapActorType(string principalType) => principalType switch
  {
    PrincipalClaimTypes.User => AuthorizationChangeLogActorTypes.User,
    PrincipalClaimTypes.ServerServiceAccount or PrincipalClaimTypes.TenantServiceAccount =>
      AuthorizationChangeLogActorTypes.ServiceAccount,
    _ => MapUnmappedActorType(principalType)
  };

  private string MapUnmappedActorType(string principalType)
  {
    _logger.LogWarning("Unmapped principal type for authorization change log actor: {PrincipalType}", principalType);
    return AuthorizationChangeLogActorTypes.System;
  }

  /// <summary>
  /// Builds and validates the explicit scope list. Explicit scopes replace the baseline defaults
  /// (with <c>device.read</c> unioned in, since the device-access page requires it), and the
  /// creator must hold every requested permission at the target device. Unlike the baseline path —
  /// where <c>DeviceLogonTokenCreate</c> alone conveys authority to grant the fixed standard
  /// device-access set — the explicit path can request arbitrary permissions, so each one is
  /// validated against the creator to prevent escalation.
  /// </summary>
  private async Task<HttpResult<ScopePreparation>> PrepareScopes(
    IReadOnlyList<InternalDtos.CredentialScopeDto>? requestedScopes,
    Guid deviceId,
    Guid tenantId,
    PrincipalDescriptor creator,
    CancellationToken cancellationToken)
  {
    var actorType = MapActorType(creator.PrincipalType);
    if (requestedScopes is not { Count: > 0 })
    {
      return HttpResult.Ok(new ScopePreparation(null, creator, actorType));
    }

    var scopes = new List<InternalDtos.CredentialScopeDto>();
    var seen = new HashSet<(string PermissionName, PermissionScopeKind ScopeKind, Guid? ScopeId)>();
    foreach (var scope in requestedScopes)
    {
      if (!PermissionCatalog.Exists(scope.PermissionName))
      {
        return HttpResult.Fail<ScopePreparation>(
          HttpResultErrorCode.BadRequest,
          $"Unknown permission name: {scope.PermissionName}");
      }

      if (seen.Add((scope.PermissionName, scope.ScopeKind, scope.ScopeId)))
      {
        scopes.Add(scope);
      }
    }

    var hasDeviceRead = scopes.Any(x =>
      x.PermissionName == PermissionNames.DeviceRead &&
      x.ScopeKind == PermissionScopeKind.Device &&
      (x.ScopeId is null || x.ScopeId == deviceId));
    if (!hasDeviceRead)
    {
      scopes.Add(new InternalDtos.CredentialScopeDto(PermissionNames.DeviceRead, PermissionScopeKind.Device, deviceId));
    }

    return await ValidateScopes(scopes, tenantId, creator, actorType, cancellationToken);
  }

  private async Task<HttpResult<ScopePreparation>> ValidateScopes(
    IReadOnlyList<InternalDtos.CredentialScopeDto> scopes,
    Guid tenantId,
    PrincipalDescriptor creator,
    string actorType,
    CancellationToken cancellationToken)
  {
    var validation = await _credentialScopeService.ValidateLogonTokenScopes(
      creator, tenantId, scopes, cancellationToken);
    if (!validation.IsSuccess)
    {
      return HttpResult.Fail<ScopePreparation>(validation.ErrorCode, validation.Reason);
    }

    return HttpResult.Ok(new ScopePreparation(scopes, creator, actorType));
  }

  private sealed record ScopePreparation(
    IReadOnlyList<InternalDtos.CredentialScopeDto>? ExplicitScopes,
    PrincipalDescriptor Creator,
    string ActorType);
}
