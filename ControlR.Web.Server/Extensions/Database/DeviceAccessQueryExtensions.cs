using ControlR.Web.Server.Services.DeviceManagement;

namespace ControlR.Web.Server.Extensions.Database;

public static class DeviceAccessQueryExtensions
{
  public static IQueryable<Device> ApplyAccessScope(
    this IQueryable<Device> query,
    Guid tenantId,
    DeviceAccessScope accessScope)
  {
    query = query.Where(x => x.TenantId == tenantId);

    return accessScope.Kind switch
    {
      DeviceAccessScopeKind.TenantWide => query,
      DeviceAccessScopeKind.SingleDevice => query.Where(x => x.Id == accessScope.DeviceId),
      DeviceAccessScopeKind.TaggedDevices => query.Where(x => x.Tags!.Any(tag => accessScope.TagIds.Contains(tag.Id))),
      DeviceAccessScopeKind.SpecificDevices => query.Where(x => accessScope.DeviceIds.Contains(x.Id)),
      DeviceAccessScopeKind.DeviceGroups => query.Where(x =>
        x.DeviceGroupMembers!.Any(m => accessScope.DeviceGroupIds.Contains(m.DeviceGroupId))),
      _ => query.Take(0)
    };
  }
}