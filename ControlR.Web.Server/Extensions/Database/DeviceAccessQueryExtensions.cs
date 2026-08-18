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
    // Deterministic default ordering for stable paging; callers may override via ApplySorting.
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
  /// Applies the caller's device access scope; server principals bypass scoping.
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

    var accessScope = await scopeResolver.Resolve(user, cancellationToken);
    return query.ApplyAccessScope(tenantId, accessScope);
  }
}