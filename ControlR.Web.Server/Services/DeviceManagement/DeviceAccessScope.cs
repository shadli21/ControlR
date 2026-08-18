namespace ControlR.Web.Server.Services.DeviceManagement;

public enum DeviceAccessScopeKind
{
  None,
  TenantWide,
  SingleDevice,
  TaggedDevices,
  SpecificDevices,
  DeviceGroups,
  Customers,
  Combined
}

/// <summary>
/// Resolved device set for a principal; Combined unions inclusion categories (tenant-wide,
/// groups, customers, devices) and subtracts explicit-deny exclusions (deny overrides allow).
/// </summary>
public sealed record DeviceAccessScope
{
  private DeviceAccessScope(
    DeviceAccessScopeKind kind,
    Guid? deviceId,
    IReadOnlyCollection<Guid>? tagIds,
    IReadOnlyCollection<Guid>? deviceIds,
    IReadOnlyCollection<Guid>? deviceGroupIds,
    IReadOnlyCollection<Guid>? customerIds = null,
    bool includesTenantWide = false,
    IReadOnlyCollection<Guid>? excludedDeviceIds = null,
    IReadOnlyCollection<Guid>? excludedDeviceGroupIds = null,
    IReadOnlyCollection<Guid>? excludedCustomerIds = null)
  {
    Kind = kind;
    DeviceId = deviceId;
    TagIds = tagIds ?? [];
    DeviceIds = deviceIds ?? [];
    DeviceGroupIds = deviceGroupIds ?? [];
    CustomerIds = customerIds ?? [];
    IncludesTenantWide = includesTenantWide;
    ExcludedDeviceIds = excludedDeviceIds ?? [];
    ExcludedDeviceGroupIds = excludedDeviceGroupIds ?? [];
    ExcludedCustomerIds = excludedCustomerIds ?? [];
  }

  public IReadOnlyCollection<Guid> CustomerIds { get; }
  public Guid? DeviceId { get; }
  public IReadOnlyCollection<Guid> DeviceGroupIds { get; }
  public IReadOnlyCollection<Guid> DeviceIds { get; }
  public IReadOnlyCollection<Guid> ExcludedCustomerIds { get; }
  public IReadOnlyCollection<Guid> ExcludedDeviceGroupIds { get; }
  public IReadOnlyCollection<Guid> ExcludedDeviceIds { get; }
  /// <summary>
  /// Whether a Combined scope includes all tenant devices (via a Server/Tenant-scope allow).
  /// </summary>
  public bool IncludesTenantWide { get; }
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

  public static DeviceAccessScope Combined(
    bool includesTenantWide,
    IReadOnlyCollection<Guid> deviceGroupIds,
    IReadOnlyCollection<Guid> customerIds,
    IReadOnlyCollection<Guid> deviceIds,
    IReadOnlyCollection<Guid> excludedDeviceGroupIds,
    IReadOnlyCollection<Guid> excludedCustomerIds,
    IReadOnlyCollection<Guid> excludedDeviceIds) =>
    new(
      DeviceAccessScopeKind.Combined,
      null, [], deviceIds, deviceGroupIds, customerIds,
      includesTenantWide, excludedDeviceIds, excludedDeviceGroupIds, excludedCustomerIds);
}