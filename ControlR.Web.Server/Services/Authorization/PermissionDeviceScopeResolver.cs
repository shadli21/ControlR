using System.Security.Claims;
using ControlR.Web.Server.Authn;
using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Services.Authorization.PermissionRules;
using ControlR.Web.Server.Services.DeviceManagement;

namespace ControlR.Web.Server.Services.Authorization;

/// <summary>
/// Permission-based device access scope resolver. Produces the <see cref="DeviceAccessScope"/>
/// query filter describing which devices a principal may enumerate. It performs no authorization
/// decisions of its own: <see cref="PermissionAssignment"/> rows are interpreted by
/// <see cref="IPermissionRuleResolver"/> (the same component the point-authorization evaluator
/// uses), and this class projects the resolved <c>device.read</c> rules into a scope, honoring
/// deny-overrides-allow: denies become exclusion sets (or <see cref="DeviceAccessScope.None"/>
/// at Server/Tenant scope) so enumeration stays at parity with point evaluation.
/// </summary>
public class PermissionDeviceScopeResolver(
  IPermissionRuleResolver ruleResolver) : IDeviceAccessScopeResolver
{
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

    var deviceReadAssignments = resolved.Rules
      .Where(rule => rule.Assignment.PermissionName == PermissionNames.DeviceRead)
      .Select(rule => rule.Assignment)
      .ToList();

    var allows = deviceReadAssignments
      .Where(x => x.Effect == PermissionEffect.Allow)
      .ToList();

    if (allows.Count == 0)
    {
      return DeviceAccessScope.None();
    }

    var denies = deviceReadAssignments
      .Where(x => x.Effect == PermissionEffect.Deny)
      .ToList();

    // A Server/Tenant-scope deny removes the entire tenant from enumeration, mirroring the
    // point evaluator's deny-overrides-allow semantics.
    if (denies.Any(x => x.ScopeKind is PermissionScopeKind.Server or PermissionScopeKind.Tenant))
    {
      return DeviceAccessScope.None();
    }

    var includesTenantWide = allows.Any(x => x.ScopeKind is PermissionScopeKind.Server or PermissionScopeKind.Tenant);

    var deviceGroupIds = ScopeIds(allows, PermissionScopeKind.DeviceGroup);
    var customerIds = ScopeIds(allows, PermissionScopeKind.CustomerTenant);
    var deviceIds = ScopeIds(allows, PermissionScopeKind.Device);

    var excludedGroupIds = ScopeIds(denies, PermissionScopeKind.DeviceGroup);
    var excludedCustomerIds = ScopeIds(denies, PermissionScopeKind.CustomerTenant);
    var excludedDeviceIds = ScopeIds(denies, PermissionScopeKind.Device);

    if (includesTenantWide &&
        excludedGroupIds.Count == 0 &&
        excludedCustomerIds.Count == 0 &&
        excludedDeviceIds.Count == 0)
    {
      return DeviceAccessScope.TenantWide();
    }

    if (!includesTenantWide &&
        deviceGroupIds.Count == 0 &&
        customerIds.Count == 0 &&
        deviceIds.Count == 0)
    {
      return DeviceAccessScope.None();
    }

    var hasExclusions = excludedGroupIds.Count > 0 ||
        excludedCustomerIds.Count > 0 ||
        excludedDeviceIds.Count > 0;

    // Preserve the legacy single-category shapes when they fully describe the scope.
    if (!includesTenantWide && !hasExclusions)
    {
      if (deviceGroupIds.Count > 0 && customerIds.Count == 0 && deviceIds.Count == 0)
      {
        return DeviceAccessScope.ForDeviceGroups(deviceGroupIds);
      }

      if (customerIds.Count > 0 && deviceGroupIds.Count == 0 && deviceIds.Count == 0)
      {
        return DeviceAccessScope.ForCustomers(customerIds);
      }

      if (deviceIds.Count > 0 && deviceGroupIds.Count == 0 && customerIds.Count == 0)
      {
        return DeviceAccessScope.ForSpecificDevices(deviceIds);
      }
    }

    return DeviceAccessScope.Combined(
      includesTenantWide,
      deviceGroupIds,
      customerIds,
      deviceIds,
      excludedGroupIds,
      excludedCustomerIds,
      excludedDeviceIds);
  }

  private static List<Guid> ScopeIds(List<PermissionAssignment> assignments, PermissionScopeKind scopeKind) =>
    assignments
      .Where(x => x.ScopeKind == scopeKind && x.ScopeId.HasValue)
      .Select(x => x.ScopeId!.Value)
      .Distinct()
      .ToList();

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
