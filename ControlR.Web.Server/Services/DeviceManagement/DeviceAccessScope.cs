namespace ControlR.Web.Server.Services.DeviceManagement;

public enum DeviceAccessScopeKind
{
  None,
  TenantWide,
  SingleDevice,
  TaggedDevices,
  SpecificDevices,
  DeviceGroups,
  Customers
}

/// <summary>
/// Represents the resolved set of devices a principal is authorized to access.
/// Produced by <see cref="IDeviceAccessScopeResolver"/> and consumed by query-filter
/// extensions to restrict device queries to the authorized subset.
/// </summary>
public sealed record DeviceAccessScope
{
  private DeviceAccessScope(
    DeviceAccessScopeKind kind,
    Guid? deviceId,
    IReadOnlyCollection<Guid>? tagIds,
    IReadOnlyCollection<Guid>? deviceIds,
    IReadOnlyCollection<Guid>? deviceGroupIds,
    IReadOnlyCollection<Guid>? customerIds = null)
  {
    Kind = kind;
    DeviceId = deviceId;
    TagIds = tagIds ?? [];
    DeviceIds = deviceIds ?? [];
    DeviceGroupIds = deviceGroupIds ?? [];
    CustomerIds = customerIds ?? [];
  }

  public IReadOnlyCollection<Guid> CustomerIds { get; }
  public Guid? DeviceId { get; }
  public IReadOnlyCollection<Guid> DeviceGroupIds { get; }
  public IReadOnlyCollection<Guid> DeviceIds { get; }
  public DeviceAccessScopeKind Kind { get; }
  public IReadOnlyCollection<Guid> TagIds { get; }

  public static DeviceAccessScope None() => new(DeviceAccessScopeKind.None, null, [], [], []);

  public static DeviceAccessScope SingleDevice(Guid deviceId) =>
    new(DeviceAccessScopeKind.SingleDevice, deviceId, [], [], []);

  public static DeviceAccessScope TaggedDevices(IReadOnlyCollection<Guid> tagIds) =>
    new(DeviceAccessScopeKind.TaggedDevices, null, tagIds, [], []);

  public static DeviceAccessScope TenantWide() => new(DeviceAccessScopeKind.TenantWide, null, [], [], []);

  public static DeviceAccessScope ForSpecificDevices(IReadOnlyCollection<Guid> deviceIds) =>
    new(DeviceAccessScopeKind.SpecificDevices, null, [], deviceIds, []);

  public static DeviceAccessScope ForDeviceGroups(IReadOnlyCollection<Guid> deviceGroupIds) =>
    new(DeviceAccessScopeKind.DeviceGroups, null, [], [], deviceGroupIds);

  public static DeviceAccessScope ForCustomers(IReadOnlyCollection<Guid> customerIds) =>
    new(DeviceAccessScopeKind.Customers, null, [], [], [], customerIds);
}