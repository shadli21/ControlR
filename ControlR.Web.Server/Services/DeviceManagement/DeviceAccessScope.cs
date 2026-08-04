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
/// Represents the resolved set of devices a principal is authorized to access.
/// Produced by <see cref="IDeviceAccessScopeResolver"/> and consumed by query-filter
/// extensions to restrict device queries to the authorized subset. The <see cref="DeviceAccessScopeKind.Combined"/>
/// kind unions multiple inclusion categories (tenant-wide, device groups, customers, specific
/// devices) and subtracts exclusion sets derived from explicit deny rules, mirroring the
/// point-authorization evaluator's deny-overrides-allow semantics.
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
  /// True when a <see cref="DeviceAccessScopeKind.Combined"/> scope includes all tenant devices
  /// (from a Server/Tenant-scope allow) before exclusions are applied.
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