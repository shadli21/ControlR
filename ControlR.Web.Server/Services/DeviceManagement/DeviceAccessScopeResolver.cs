using System.Security.Claims;
using ControlR.Web.Server.Authn;
using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Services.Authorization;
using ControlR.Web.Server.Services.Authorization.PermissionRules;

namespace ControlR.Web.Server.Services.DeviceManagement;

public interface IDeviceAccessScopeResolver
{
  Task<DeviceAccessScope> Resolve(
    ClaimsPrincipal user,
    CancellationToken cancellationToken = default);
}

public sealed class DeviceAccessScopeResolver(
  IPermissionEvaluationContextLoader contextLoader) : IDeviceAccessScopeResolver
{
  private readonly IPermissionEvaluationContextLoader _contextLoader = contextLoader;

  public async Task<DeviceAccessScope> Resolve(
    ClaimsPrincipal user,
    CancellationToken cancellationToken = default)
  {
    if (user.FindFirst(UserClaimTypes.AuthenticationMethod)?.Value ==
        PrincipalClaimValues.LogonTokenMethod &&
        (!Guid.TryParse(
           user.FindFirst(PrincipalClaimTypes.CredentialId)?.Value,
           out _) ||
         !Guid.TryParse(
           user.FindFirst(UserClaimTypes.DeviceSessionScope)?.Value,
           out _)))
    {
      return DeviceAccessScope.None();
    }

    var principal = user.ToPrincipalDescriptor();
    if (principal is null)
    {
      return DeviceAccessScope.None();
    }

    var context = await _contextLoader.Load(principal, cancellationToken);
    if (context.ServerBypass)
    {
      return DeviceAccessScope.ServerWide();
    }

    var deviceReadRules = context.EffectiveRules
      .Where(rule => rule.PermissionName == PermissionNames.DeviceRead)
      .ToList();
    if (deviceReadRules.Count == 0)
    {
      return DeviceAccessScope.None();
    }

    if (principal.CredentialType == CredentialType.LogonToken)
    {
      if (!principal.CredentialId.HasValue || !principal.DeviceScopeId.HasValue)
      {
        return DeviceAccessScope.None();
      }

      var deviceRules = deviceReadRules
        .Where(rule => rule.ScopeKind == PermissionScopeKind.Device &&
                       rule.ScopeId == principal.DeviceScopeId.Value)
        .ToList();
      if (deviceRules.Any(rule => rule.Effect == PermissionEffect.Deny) ||
          !deviceRules.Any(rule => rule.Effect == PermissionEffect.Allow))
      {
        return DeviceAccessScope.None();
      }

      return DeviceAccessScope.Create(
        principal.TenantId,
        false,
        [],
        [],
        [],
        [principal.DeviceScopeId.Value],
        [],
        [],
        [],
        []);
    }

    var scope = BuildScope(deviceReadRules, principal.TenantId);
    if (context.HasExplicitPatScope)
    {
      var ownerScope = BuildScope(context.OwnerRules
        .Where(rule => rule.PermissionName == PermissionNames.DeviceRead)
        .ToList(),
        principal.TenantId);
      return scope.RequireOwnerScope(ownerScope);
    }

    return scope;
  }

  private static DeviceAccessScope BuildScope(
    IReadOnlyCollection<PermissionRule> rules,
    Guid? tenantBoundaryId)
  {
    var allows = rules
      .Where(rule => rule.Effect == PermissionEffect.Allow)
      .ToList();
    if (allows.Count == 0)
    {
      return DeviceAccessScope.None();
    }

    var denies = rules
      .Where(rule => rule.Effect == PermissionEffect.Deny)
      .ToList();

    return DeviceAccessScope.Create(
      tenantBoundaryId,
      allows.Any(rule => rule.ScopeKind == PermissionScopeKind.Server),
      ScopeIds(allows, PermissionScopeKind.Tenant),
      ScopeIds(allows, PermissionScopeKind.DeviceGroup),
      ScopeIds(allows, PermissionScopeKind.CustomerTenant),
      ScopeIds(allows, PermissionScopeKind.Device),
      denies.Any(rule => rule.ScopeKind == PermissionScopeKind.Server)
        ? [Guid.Empty]
        : ScopeIds(denies, PermissionScopeKind.Tenant),
      ScopeIds(denies, PermissionScopeKind.DeviceGroup),
      ScopeIds(denies, PermissionScopeKind.CustomerTenant),
      ScopeIds(denies, PermissionScopeKind.Device));
  }

  private static IReadOnlyCollection<Guid> ScopeIds(
    IReadOnlyCollection<PermissionRule> rules,
    PermissionScopeKind scopeKind) =>
    rules
      .Where(rule => rule.ScopeKind == scopeKind && rule.ScopeId.HasValue)
      .Select(rule => rule.ScopeId.GetValueOrDefault())
      .Distinct()
      .ToList();
}
