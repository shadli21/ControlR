using System.Security.Claims;
using ControlR.Web.Server.Services.Authorization;
using ControlR.Web.Server.Services.DeviceManagement;
using ControlR.Web.Server.Extensions;

namespace ControlR.Web.Server.Extensions.Database;

public static class DeviceAccessQueryExtensions
{
  public static IQueryable<Device> ApplyAccessScope(
    this IQueryable<Device> query,
    Guid tenantId,
    DeviceAccessScope accessScope)
  {
    // Establish a deterministic default ordering at the start of the query so that
    // any downstream operators (Take/Skip, paging) always operate on an ordered
    // query. Callers may still override the ordering via ApplySorting; explicit
    // sorts issued by the caller replace this default.
    query = query.Where(x => x.TenantId == tenantId).OrderBy(x => x.CreatedAt);

    return accessScope.Kind switch
    {
      DeviceAccessScopeKind.TenantWide => query,
      DeviceAccessScopeKind.SingleDevice => query.Where(x => x.Id == accessScope.DeviceId),
      DeviceAccessScopeKind.TaggedDevices => query.Where(x => x.Tags!.Any(tag => accessScope.TagIds.Contains(tag.Id))),
      DeviceAccessScopeKind.SpecificDevices => query.Where(x => accessScope.DeviceIds.Contains(x.Id)),
      DeviceAccessScopeKind.DeviceGroups => query.Where(x =>
        x.DeviceGroupMembers!.Any(m => accessScope.DeviceGroupIds.Contains(m.DeviceGroupId))),
      DeviceAccessScopeKind.Customers => query.Where(x =>
        x.CustomerId.HasValue && accessScope.CustomerIds.Contains(x.CustomerId.Value)),
      DeviceAccessScopeKind.Combined => query.Where(x =>
        (accessScope.IncludesTenantWide ||
         (accessScope.DeviceGroupIds.Count > 0 &&
          x.DeviceGroupMembers!.Any(m => accessScope.DeviceGroupIds.Contains(m.DeviceGroupId))) ||
         (accessScope.CustomerIds.Count > 0 &&
          x.CustomerId.HasValue && accessScope.CustomerIds.Contains(x.CustomerId.Value)) ||
         (accessScope.DeviceIds.Count > 0 && accessScope.DeviceIds.Contains(x.Id))) &&
        !(accessScope.ExcludedDeviceIds.Count > 0 && accessScope.ExcludedDeviceIds.Contains(x.Id)) &&
        !(accessScope.ExcludedDeviceGroupIds.Count > 0 &&
          x.DeviceGroupMembers!.Any(m => accessScope.ExcludedDeviceGroupIds.Contains(m.DeviceGroupId))) &&
        !(accessScope.ExcludedCustomerIds.Count > 0 &&
          x.CustomerId.HasValue && accessScope.ExcludedCustomerIds.Contains(x.CustomerId.Value))),
      _ => query.Where(_ => false)
    };
  }

  /// <summary>
  /// Applies the caller's device access scope to the query. Server-scoped service accounts
  /// bypass scoping entirely (cross-tenant enumeration); all other principals require a tenant
  /// claim and are scoped per their device.read rules. Returns an empty query when the tenant
  /// claim is missing for a non-server principal.
  /// </summary>
  public static async Task<IQueryable<Device>> ApplyDeviceAccessScope(
    this IQueryable<Device> query,
    ClaimsPrincipal user,
    IDeviceAccessScopeResolver scopeResolver,
    CancellationToken cancellationToken = default)
  {
    if (user.IsServerPrincipal())
    {
      return query;
    }

    if (!user.TryGetTenantId(out var tenantId))
    {
      return query.Take(0);
    }

    var accessScope = await scopeResolver.Resolve(user, tenantId, cancellationToken);
    return query.ApplyAccessScope(tenantId, accessScope);
  }
}