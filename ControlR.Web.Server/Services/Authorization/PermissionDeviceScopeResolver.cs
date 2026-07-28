using System.Security.Claims;
using ControlR.Web.Server.Authn;
using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Services.DeviceManagement;

namespace ControlR.Web.Server.Services.Authorization;

/// <summary>
/// Permission-based device access scope resolver. Produces the <see cref="DeviceAccessScope"/>
/// query filter describing which devices a principal may enumerate. It performs no authorization
/// decisions of its own: <see cref="PermissionAssignment"/> rows are interpreted by
/// <see cref="IPermissionRuleResolver"/> (the same component the point-authorization evaluator
/// uses), and this class only projects the resolved <c>device.read</c> allow rules into a scope.
/// The role and tag bridges below are interim pre-rework behavior retired in PR 12/13.
/// </summary>
public class PermissionDeviceScopeResolver(
  IPermissionRuleResolver ruleResolver,
  IDbContextFactory<AppDb> dbContextFactory) : IDeviceAccessScopeResolver
{
  private readonly IDbContextFactory<AppDb> _dbContextFactory = dbContextFactory;
  private readonly IPermissionRuleResolver _ruleResolver = ruleResolver;

  public async Task<DeviceAccessScope> Resolve(
    ClaimsPrincipal user,
    Guid tenantId,
    CancellationToken cancellationToken = default)
  {
    // Hard boundary: logon token sessions are always restricted to their scoped device.
    if (TryGetLogonTokenDeviceScope(user, out var scopedDeviceId))
    {
      return DeviceAccessScope.SingleDevice(scopedDeviceId);
    }

    var principal = PrincipalDescriptorBuilder.FromClaims(user);
    if (principal is null)
    {
      return DeviceAccessScope.None();
    }

    var resolved = await _ruleResolver.Resolve(principal, cancellationToken);

    // Server service account bypass: zero assignments means unrestricted access.
    if (resolved.ServerBypass)
    {
      return DeviceAccessScope.TenantWide();
    }

    // Bridge (deleted in PR 13): TenantAdministrator and DeviceSuperUser roles grant tenant-wide
    // device access. TenantAdministrator's role-bundle does not include device.read, so this
    // hardcoded bridge preserves pre-rework list behavior that the rule set alone would not.
    if (user.IsInRole(RoleNames.TenantAdministrator) || user.IsInRole(RoleNames.DeviceSuperUser))
    {
      return DeviceAccessScope.TenantWide();
    }

    var deviceReadAllows = resolved.Rules
      .Where(rule => rule.Assignment.PermissionName == PermissionNames.DeviceRead &&
                     rule.Assignment.Effect == PermissionEffect.Allow)
      .Select(rule => rule.Assignment)
      .ToList();

    if (deviceReadAllows.Count == 0)
    {
      // Bridge fallback (deleted in PR 13): users with tag associations but no permission
      // assignments retain tag-based device access, preserving pre-rework behavior until the
      // backfill (PR 12) creates assignment rows and tags are removed.
      if (PermissionRuleResolver.ResolvePrincipalKind(principal.PrincipalType) == PermissionPrincipalKind.User)
      {
        await using var db = await _dbContextFactory.CreateDbContextAsync(cancellationToken);
        var tagIds = await db.Users
          .Where(x => x.Id == principal.PrincipalId && x.TenantId == tenantId)
          .SelectMany(x => x.Tags!.Select(tag => tag.Id))
          .ToListAsync(cancellationToken);

        return tagIds.Count == 0
          ? DeviceAccessScope.None()
          : DeviceAccessScope.TaggedDevices(tagIds);
      }

      return DeviceAccessScope.None();
    }

    // Server or Tenant scope grants access to all tenant devices.
    if (deviceReadAllows.Any(x => x.ScopeKind is PermissionScopeKind.Server or PermissionScopeKind.Tenant))
    {
      return DeviceAccessScope.TenantWide();
    }

    var deviceGroupIds = deviceReadAllows
      .Where(x => x.ScopeKind == PermissionScopeKind.DeviceGroup && x.ScopeId.HasValue)
      .Select(x => x.ScopeId!.Value)
      .Distinct()
      .ToList();

    if (deviceGroupIds.Count > 0)
    {
      return DeviceAccessScope.ForDeviceGroups(deviceGroupIds);
    }

    var customerIds = deviceReadAllows
      .Where(x => x.ScopeKind == PermissionScopeKind.CustomerTenant && x.ScopeId.HasValue)
      .Select(x => x.ScopeId!.Value)
      .Distinct()
      .ToList();

    if (customerIds.Count > 0)
    {
      return DeviceAccessScope.ForCustomers(customerIds);
    }

    var deviceIds = deviceReadAllows
      .Where(x => x.ScopeKind == PermissionScopeKind.Device && x.ScopeId.HasValue)
      .Select(x => x.ScopeId!.Value)
      .Distinct()
      .ToList();

    if (deviceIds.Count > 0)
    {
      return DeviceAccessScope.ForSpecificDevices(deviceIds);
    }

    return DeviceAccessScope.None();
  }

  private static bool TryGetLogonTokenDeviceScope(ClaimsPrincipal user, out Guid deviceId)
  {
    deviceId = Guid.Empty;

    var authMethod = user.FindFirst(UserClaimTypes.AuthenticationMethod)?.Value;
    if (authMethod != PrincipalClaimTypes.LogonTokenMethod)
    {
      return false;
    }

    var scopedDeviceIdValue = user.FindFirst(UserClaimTypes.DeviceSessionScope)?.Value;
    return Guid.TryParse(scopedDeviceIdValue, out deviceId);
  }
}
