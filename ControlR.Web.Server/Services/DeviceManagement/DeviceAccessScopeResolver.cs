using System.Security.Claims;
using ControlR.Web.Server.Authn;
using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Services.Authorization.PermissionRules;

namespace ControlR.Web.Server.Services.DeviceManagement;

public interface IDeviceAccessScopeResolver
{
  Task<DeviceAccessScope> Resolve(ClaimsPrincipal user, Guid tenantId, CancellationToken cancellationToken = default);
}

/// <summary>
/// Projects a principal's resolved <c>device.read</c> rules (allow/deny) into a
/// <see cref="DeviceAccessScope"/> query filter.
/// </summary>
public class DeviceAccessScopeResolver(
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

    // Server bypass spans all tenants, which DeviceAccessScope cannot represent; callers
    // handle server principals first. Fail closed if one reaches this path directly.
    if (resolved.ServerBypass)
    {
      return DeviceAccessScope.None();
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
      .Select(x => x.ScopeId.GetValueOrDefault())
      .Distinct()
      .ToList();

  private static bool TryGetLogonTokenDeviceScope(ClaimsPrincipal user, out Guid deviceId)
  {
    deviceId = Guid.Empty;

    var authMethod = user.FindFirst(UserClaimTypes.AuthenticationMethod)?.Value;
    if (authMethod != PrincipalClaimValues.LogonTokenMethod)
    {
      return false;
    }

    var scopedDeviceIdValue = user.FindFirst(UserClaimTypes.DeviceSessionScope)?.Value;
    return Guid.TryParse(scopedDeviceIdValue, out deviceId);
  }
}
