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

  Task WriteLogonTokenScopes(
    Guid tokenId,
    Guid deviceId,
    Guid tenantId,
    Guid creatorUserId,
    IReadOnlyList<InternalDtos.CredentialScopeDto> scopes,
    CancellationToken cancellationToken = default);
}

public class CredentialScopeService(
  AppDb appDb,
  IPermissionEvaluator permissionEvaluator) : ICredentialScopeService
{
  private readonly AppDb _appDb = appDb;
  private readonly IPermissionEvaluator _permissionEvaluator = permissionEvaluator;

  public async Task<HttpResult> ValidateGrantableScopes(
    PrincipalDescriptor creator,
    Guid tenantId,
    IReadOnlyList<InternalDtos.CredentialScopeDto> scopes,
    CancellationToken cancellationToken = default)
  {
    foreach (var scope in scopes)
    {
      var scopeResource = await ResolveScopeResource(scope, tenantId, cancellationToken);
      if (scopeResource is null)
      {
        return HttpResult.Fail(
          HttpResultErrorCode.BadRequest,
          $"Scope target not found in this tenant: {scope.ScopeKind}/{scope.ScopeId}.");
      }

      var evaluation = await _permissionEvaluator.Evaluate(
        creator, scope.PermissionName, scopeResource, cancellationToken);

      if (!evaluation.Allowed)
      {
        return HttpResult.Fail(
          HttpResultErrorCode.BadRequest,
          $"The permission '{scope.PermissionName}' at {scope.ScopeKind} scope is outside your effective permissions.");
      }
    }

    return HttpResult.Ok();
  }

  public async Task WriteLogonTokenScopes(
    Guid tokenId,
    Guid deviceId,
    Guid tenantId,
    Guid creatorUserId,
    IReadOnlyList<InternalDtos.CredentialScopeDto> scopes,
    CancellationToken cancellationToken = default)
  {
    foreach (var scope in scopes)
    {
      _appDb.PermissionAssignments.Add(PermissionAssignment.CreateGrant(
        PermissionPrincipalKind.LogonToken,
        tokenId,
        scope.PermissionName,
        scope.ScopeKind,
        scope.ScopeId ?? deviceId,
        tenantId,
        AuthorizationChangeLogActorTypes.User,
        creatorUserId.ToString()));
    }

    _appDb.AuthorizationChangeLogs.Add(AuthorizationChangeLogEntry.Create(
      AuthorizationChangeLogActions.CredentialScopeSet,
      AuthorizationChangeLogActorTypes.User,
      creatorUserId.ToString(),
      AuthorizationChangeLogTargetTypes.LogonToken,
      tokenId.ToString(),
      tenantId,
      after: new CredentialScopeSetSummary(scopes.Count)));

    await _appDb.SaveChangesAsync(cancellationToken);
  }

  /// <summary>
  /// Builds the resource descriptor for a requested credential scope so the creator's
  /// effective permissions can be evaluated at that exact scope. Device scopes carry the
  /// target device's group/customer membership so group- and customer-scoped allows are
  /// honored precisely. Returns <see langword="null"/> when the scope target does not
  /// exist in the tenant.
  /// </summary>
  private async Task<ResourceDescriptor?> ResolveScopeResource(
    InternalDtos.CredentialScopeDto scope,
    Guid tenantId,
    CancellationToken cancellationToken)
  {
    switch (scope.ScopeKind)
    {
      case PermissionScopeKind.Server:
        return new ResourceDescriptor(PermissionScopeKind.Server, null, tenantId);

      case PermissionScopeKind.Tenant:
        return new ResourceDescriptor(PermissionScopeKind.Tenant, tenantId, tenantId);

      case PermissionScopeKind.DeviceGroup:
      {
        if (scope.ScopeId is not { } groupId)
        {
          return null;
        }

        var groupExists = await _appDb.DeviceGroups
          .AnyAsync(x => x.Id == groupId && x.TenantId == tenantId, cancellationToken);
        return groupExists
          ? new ResourceDescriptor(PermissionScopeKind.DeviceGroup, groupId, tenantId)
          : null;
      }

      case PermissionScopeKind.CustomerTenant:
      {
        if (scope.ScopeId is not { } customerId)
        {
          return null;
        }

        var customerExists = await _appDb.Customers
          .AnyAsync(x => x.Id == customerId && x.TenantId == tenantId, cancellationToken);
        return customerExists
          ? new ResourceDescriptor(PermissionScopeKind.CustomerTenant, customerId, tenantId)
          : null;
      }

      case PermissionScopeKind.Device:
      {
        if (scope.ScopeId is not { } deviceId)
        {
          return null;
        }

        var device = await _appDb.Devices
          .AsNoTracking()
          .FirstOrDefaultAsync(x => x.Id == deviceId && x.TenantId == tenantId, cancellationToken);
        if (device is null)
        {
          return null;
        }

        var groupIds = await _appDb.DeviceGroupMembers
          .AsNoTracking()
          .Where(member => member.DeviceId == deviceId)
          .Select(member => member.DeviceGroupId)
          .ToListAsync(cancellationToken);

        return new ResourceDescriptor(PermissionScopeKind.Device, deviceId, tenantId, device.CustomerId, groupIds);
      }

      default:
        return null;
    }
  }
}
