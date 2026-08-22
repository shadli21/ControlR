using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Primitives;

namespace ControlR.Web.Server.Services.Authorization;

/// <summary>
/// Grant-authority operations for credential scopes: validates that a creator may grant the
/// requested scopes (the evaluator is invoked per scope, so deny overrides and group/customer
/// membership precision apply), and writes logon-token scope grant rows with change-log
/// entries. See the permission semantics spec, sections 3 and 6.
/// </summary>
public interface ICredentialScopeService
{
  Task<HttpResult> ValidateGrantableScopes(
    PrincipalDescriptor creator,
    Guid tenantId,
    IReadOnlyList<InternalDtos.CredentialScopeDto> scopes,
    CancellationToken cancellationToken = default);

  /// <summary>
  /// Validates a logon token's scopes; non-Device scopes are rejected.
  /// </summary>
  Task<HttpResult> ValidateLogonTokenScopes(
    PrincipalDescriptor creator,
    Guid tenantId,
    IReadOnlyList<InternalDtos.CredentialScopeDto> scopes,
    CancellationToken cancellationToken = default);

  /// <summary>
  /// Writes a logon token's device-scoped grants and a change-log entry. The token is
  /// created without baseline grants when explicit scopes are supplied, so these are its
  /// full permission set.
  /// </summary>
  Task WriteLogonTokenScopes(
    Guid tokenId,
    Guid deviceId,
    Guid tenantId,
    string actorType,
    Guid actorPrincipalId,
    IReadOnlyList<InternalDtos.CredentialScopeDto> scopes,
    CancellationToken cancellationToken = default);
}

public class CredentialScopeService(
  AppDb appDb,
  IAuthorizationChangeLogFactory changeLogFactory,
  IPermissionEvaluator permissionEvaluator,
  IResourceDescriptorFactory resourceFactory) : ICredentialScopeService
{
  private readonly AppDb _appDb = appDb;
  private readonly IAuthorizationChangeLogFactory _changeLogFactory = changeLogFactory;
  private readonly IPermissionEvaluator _permissionEvaluator = permissionEvaluator;
  private readonly IResourceDescriptorFactory _resourceFactory = resourceFactory;

  public async Task<HttpResult> ValidateGrantableScopes(
    PrincipalDescriptor creator,
    Guid tenantId,
    IReadOnlyList<InternalDtos.CredentialScopeDto> scopes,
    CancellationToken cancellationToken = default)
  {
    var requests = new List<PermissionEvaluationRequest>(scopes.Count);
    foreach (var scope in scopes)
    {
      var scopeResource = await _resourceFactory.CreateScope(
        scope.ScopeKind,
        scope.ScopeId,
        tenantId,
        cancellationToken);
      if (scopeResource is null)
      {
        return HttpResult.Fail(
          HttpResultErrorCode.BadRequest,
          $"Scope target not found in this tenant: {scope.ScopeKind}/{scope.ScopeId}.");
      }

      requests.Add(new PermissionEvaluationRequest(scope.PermissionName, scopeResource));
    }

    var decisions = await _permissionEvaluator.EvaluateBatch(
      creator,
      requests,
      cancellationToken);
    for (var index = 0; index < decisions.Count; index++)
    {
      if (!decisions[index].Allowed)
      {
        var scope = scopes[index];
        return HttpResult.Fail(
          HttpResultErrorCode.BadRequest,
          $"The permission '{scope.PermissionName}' at {scope.ScopeKind} scope is outside the effective permissions of the granting user.");
      }
    }

    return HttpResult.Ok();
  }

  public async Task<HttpResult> ValidateLogonTokenScopes(
    PrincipalDescriptor creator,
    Guid tenantId,
    IReadOnlyList<InternalDtos.CredentialScopeDto> scopes,
    CancellationToken cancellationToken = default)
  {
    foreach (var scope in scopes)
    {
      if (scope.ScopeKind != PermissionScopeKind.Device)
      {
        return HttpResult.Fail(
          HttpResultErrorCode.BadRequest,
          $"Logon token scopes must be Device-scoped; '{scope.ScopeKind}' scopes are not honored for logon tokens.");
      }
    }

    return await ValidateGrantableScopes(creator, tenantId, scopes, cancellationToken);
  }

  public async Task WriteLogonTokenScopes(
    Guid tokenId,
    Guid deviceId,
    Guid tenantId,
    string actorType,
    Guid actorPrincipalId,
    IReadOnlyList<InternalDtos.CredentialScopeDto> scopes,
    CancellationToken cancellationToken = default)
  {
    foreach (var scope in scopes)
    {
      // ValidateLogonTokenScopes guarantees ScopeId == deviceId; fail loudly on deviation.
      var scopeDeviceId = scope.ScopeId ??
        throw new InvalidOperationException("Logon token scope is missing its device id. Scopes must be validated before writing.");
      if (scopeDeviceId != deviceId)
      {
        throw new InvalidOperationException("Logon token scope targets a device other than the token's device. Scopes must be validated before writing.");
      }

      _appDb.PermissionAssignments.Add(PermissionAssignment.CreateGrant(
        PermissionPrincipalKind.LogonToken,
        tokenId,
        scope.PermissionName,
        scope.ScopeKind,
        scopeDeviceId,
        tenantId,
        actorType,
        actorPrincipalId.ToString()));
    }

    _appDb.AuthorizationChangeLogs.Add(_changeLogFactory.Create(
      AuthorizationChangeLogActions.CredentialScopeSet,
      actorType,
      actorPrincipalId,
      AuthorizationChangeLogTargetTypes.LogonToken,
      tokenId,
      tenantId,
      after: new CredentialScopeSetSummary(scopes.Count)));

    await _appDb.SaveChangesAsync(cancellationToken);
  }

}
