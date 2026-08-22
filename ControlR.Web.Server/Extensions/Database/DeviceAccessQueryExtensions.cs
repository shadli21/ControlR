using System.Security.Claims;
using ControlR.Web.Server.Services.DeviceManagement;

namespace ControlR.Web.Server.Extensions.Database;

public static class DeviceAccessQueryExtensions
{
  public static IQueryable<Device> ApplyAccessScope(
    this IQueryable<Device> query,
    DeviceAccessScope accessScope)
  {
    if (accessScope.ExcludedTenantIds.Contains(Guid.Empty))
    {
      return query.Take(0);
    }

    query = query
      .Where(device =>
        (accessScope.IncludesServerWide ||
         accessScope.IncludedTenantIds.Contains(device.TenantId) ||
         accessScope.IncludedDeviceIds.Contains(device.Id) ||
         (device.CustomerId.HasValue &&
          accessScope.IncludedCustomerIds.Contains(device.CustomerId.Value)) ||
         device.DeviceGroupMembers!.Any(member =>
           accessScope.IncludedDeviceGroupIds.Contains(member.DeviceGroupId))) &&
        !accessScope.ExcludedTenantIds.Contains(device.TenantId) &&
        !accessScope.ExcludedDeviceIds.Contains(device.Id) &&
        !(device.CustomerId.HasValue &&
          accessScope.ExcludedCustomerIds.Contains(device.CustomerId.Value)) &&
        !device.DeviceGroupMembers!.Any(member =>
          accessScope.ExcludedDeviceGroupIds.Contains(member.DeviceGroupId)))
      .OrderBy(device => device.CreatedAt);

    if (accessScope.RequiredOwnerScope is not { } ownerScope)
    {
      return query;
    }

    if (ownerScope.ExcludedTenantIds.Contains(Guid.Empty))
    {
      return query.Take(0);
    }

    return query.Where(device =>
      (ownerScope.IncludesServerWide ||
       ownerScope.IncludedTenantIds.Contains(device.TenantId) ||
       ownerScope.IncludedDeviceIds.Contains(device.Id) ||
       (device.CustomerId.HasValue &&
        ownerScope.IncludedCustomerIds.Contains(device.CustomerId.Value)) ||
       device.DeviceGroupMembers!.Any(member =>
         ownerScope.IncludedDeviceGroupIds.Contains(member.DeviceGroupId))) &&
      !ownerScope.ExcludedTenantIds.Contains(device.TenantId) &&
      !ownerScope.ExcludedDeviceIds.Contains(device.Id) &&
      !(device.CustomerId.HasValue &&
        ownerScope.ExcludedCustomerIds.Contains(device.CustomerId.Value)) &&
      !device.DeviceGroupMembers!.Any(member =>
        ownerScope.ExcludedDeviceGroupIds.Contains(member.DeviceGroupId)));
  }

  public static IQueryable<Device> ApplyAccessScope(
    this IQueryable<Device> query,
    Guid tenantId,
    DeviceAccessScope accessScope) =>
    query
      .Where(device => device.TenantId == tenantId)
      .ApplyAccessScope(accessScope);

  public static async Task<IQueryable<Device>> ApplyDeviceAccessScope(
    this IQueryable<Device> query,
    ClaimsPrincipal user,
    IDeviceAccessScopeResolver scopeResolver,
    CancellationToken cancellationToken = default)
  {
    var accessScope = await scopeResolver.Resolve(user, cancellationToken);
    return query.ApplyAccessScope(accessScope);
  }
}