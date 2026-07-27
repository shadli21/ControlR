using System.Security.Claims;
using ControlR.Web.Server.Authn;
using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Services.DeviceManagement;

namespace ControlR.Web.Server.Services.Authorization;

/// <summary>
/// Permission-based device access scope resolver. Replaces the legacy role-based
/// <see cref="DeviceAccessScopeResolver"/> by querying <c>PermissionAssignment</c> rows
/// and the interim role-bundle bridge to determine which devices a principal may access.
/// Registered as the <see cref="IDeviceAccessScopeResolver"/> implementation during the
/// PR-sequencing period; the old resolver is deleted in PR 13.
/// </summary>
public class PermissionDeviceScopeResolver(
  IDbContextFactory<AppDb> dbContextFactory,
  IRoleBundleResolver roleBundleResolver) : IDeviceAccessScopeResolver
{
  private readonly IDbContextFactory<AppDb> _dbContextFactory = dbContextFactory;
  private readonly IRoleBundleResolver _roleBundleResolver = roleBundleResolver;

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

    var principalType = user.FindFirst(PrincipalClaimTypes.PrincipalType)?.Value;
    var principalIdClaim = user.FindFirst(PrincipalClaimTypes.PrincipalId)?.Value;

    if (principalType is null || !Guid.TryParse(principalIdClaim, out var principalId))
    {
      return DeviceAccessScope.None();
    }

    await using var db = await _dbContextFactory.CreateDbContextAsync(cancellationToken);

    // Server service account bypass: zero assignments means unrestricted access.
    if (principalType == PrincipalClaimTypes.ServerServiceAccount)
    {
      var hasAssignments = await db.PermissionAssignments
        .IgnoreQueryFilters()
        .AnyAsync(x => x.PrincipalKind == PermissionPrincipalKind.ServiceAccount &&
                       x.PrincipalId == principalId &&
                       x.IsEnabled, cancellationToken);

      if (!hasAssignments)
      {
        return DeviceAccessScope.TenantWide();
      }
    }

    // Role-bundle bridge (deleted in PR 13): TenantAdministrator and DeviceSuperUser
    // roles grant tenant-wide device access, preserving pre-rework behavior.
    if (user.IsInRole(RoleNames.TenantAdministrator) || user.IsInRole(RoleNames.DeviceSuperUser))
    {
      return DeviceAccessScope.TenantWide();
    }

    // Resolve the principal kind for assignment lookups.
    var principalKind = principalType is PrincipalClaimTypes.TenantServiceAccount
        or PrincipalClaimTypes.ServerServiceAccount
      ? PermissionPrincipalKind.ServiceAccount
      : PermissionPrincipalKind.User;

    // Load direct assignments for device.read.
    var directAssignments = await db.PermissionAssignments
      .IgnoreQueryFilters()
      .Where(x => x.PrincipalKind == principalKind &&
                  x.PrincipalId == principalId &&
                  x.IsEnabled &&
                  x.PermissionName == PermissionNames.DeviceRead &&
                  x.Effect == PermissionEffect.Allow)
      .ToListAsync(cancellationToken);

    // Load user-group assignments for device.read (users only).
    var groupAssignments = new List<PermissionAssignment>();
    if (principalKind == PermissionPrincipalKind.User)
    {
      var userGroupIds = await db.UserGroupMembers
        .IgnoreQueryFilters()
        .Where(x => x.UserId == principalId)
        .Select(x => x.UserGroupId)
        .ToListAsync(cancellationToken);

      if (userGroupIds.Count > 0)
      {
        groupAssignments = await db.PermissionAssignments
          .IgnoreQueryFilters()
          .Where(x => x.PrincipalKind == PermissionPrincipalKind.UserGroup &&
                      userGroupIds.Contains(x.PrincipalId) &&
                      x.IsEnabled &&
                      x.PermissionName == PermissionNames.DeviceRead &&
                      x.Effect == PermissionEffect.Allow)
          .ToListAsync(cancellationToken);
      }
    }

    var allAssignments = directAssignments.Concat(groupAssignments).ToList();

    // Role-bundle bridge: if the user's roles grant device.read via the static bundle,
    // treat it as a tenant-scoped allow (same as the evaluator's role-bundle step).
    var roles = user.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList();
    if (roles.Count > 0)
    {
      var bundlePermissions = _roleBundleResolver.ResolvePermissions(roles);
      if (bundlePermissions.Contains(PermissionNames.DeviceRead))
      {
        return DeviceAccessScope.TenantWide();
      }
    }

    if (allAssignments.Count == 0)
    {
      // Bridge fallback (deleted in PR 13): users with tag associations but no permission
      // assignments retain tag-based device access, preserving pre-rework behavior until
      // the backfill (PR 12) creates assignment rows and tags are removed.
      if (principalKind == PermissionPrincipalKind.User)
      {
        var tagIds = await db.Users
          .Where(x => x.Id == principalId && x.TenantId == tenantId)
          .SelectMany(x => x.Tags!.Select(tag => tag.Id))
          .ToListAsync(cancellationToken);

        return tagIds.Count == 0
          ? DeviceAccessScope.None()
          : DeviceAccessScope.TaggedDevices(tagIds);
      }

      return DeviceAccessScope.None();
    }

    // Determine the broadest scope from matching assignments.
    // Server or Tenant scope grants access to all tenant devices.
    if (allAssignments.Any(x => x.ScopeKind is PermissionScopeKind.Server or PermissionScopeKind.Tenant))
    {
      return DeviceAccessScope.TenantWide();
    }

    // DeviceGroup scope: collect group IDs for query filtering via group membership.
    var deviceGroupIds = allAssignments
      .Where(x => x.ScopeKind == PermissionScopeKind.DeviceGroup && x.ScopeId.HasValue)
      .Select(x => x.ScopeId!.Value)
      .Distinct()
      .ToList();

    if (deviceGroupIds.Count > 0)
    {
      return DeviceAccessScope.ForDeviceGroups(deviceGroupIds);
    }

    // CustomerTenant scope: collect customer IDs for query filtering by device customer.
    var customerIds = allAssignments
      .Where(x => x.ScopeKind == PermissionScopeKind.CustomerTenant && x.ScopeId.HasValue)
      .Select(x => x.ScopeId!.Value)
      .Distinct()
      .ToList();

    if (customerIds.Count > 0)
    {
      return DeviceAccessScope.ForCustomers(customerIds);
    }

    // Device scope: collect specific device IDs.
    var deviceIds = allAssignments
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
