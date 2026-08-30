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
      .ApplyScope(accessScope)
      .OrderBy(device => device.CreatedAt);

    if (accessScope.RequiredOwnerScope is not { } ownerScope)
    {
      return query;
    }

    if (ownerScope.ExcludedTenantIds.Contains(Guid.Empty))
    {
      return query.Take(0);
    }

    return query.ApplyScope(ownerScope);
  }

  private static IQueryable<Device> ApplyScope(
    this IQueryable<Device> query,
    DeviceAccessScope scope) =>
    query.Where(device =>
      (!scope.TenantBoundaryId.HasValue ||
       device.TenantId == scope.TenantBoundaryId.Value) &&
      (scope.IncludesServerWide ||
       scope.IncludedTenantIds.Contains(device.TenantId) ||
       scope.IncludedDeviceIds.Contains(device.Id) ||
       (device.CustomerId.HasValue &&
        scope.IncludedCustomerIds.Contains(device.CustomerId.Value)) ||
       device.DeviceGroupMembers!.Any(member =>
         scope.IncludedDeviceGroupIds.Contains(member.DeviceGroupId))) &&
      !scope.ExcludedTenantIds.Contains(device.TenantId) &&
      !scope.ExcludedDeviceIds.Contains(device.Id) &&
      !(device.CustomerId.HasValue &&
        scope.ExcludedCustomerIds.Contains(device.CustomerId.Value)) &&
      !device.DeviceGroupMembers!.Any(member =>
        scope.ExcludedDeviceGroupIds.Contains(member.DeviceGroupId)));

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