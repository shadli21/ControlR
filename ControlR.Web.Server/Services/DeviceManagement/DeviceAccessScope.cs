namespace ControlR.Web.Server.Services.DeviceManagement;

public sealed record DeviceAccessScope(
  bool IncludesServerWide,
  IReadOnlyCollection<Guid> IncludedTenantIds,
  IReadOnlyCollection<Guid> IncludedDeviceGroupIds,
  IReadOnlyCollection<Guid> IncludedCustomerIds,
  IReadOnlyCollection<Guid> IncludedDeviceIds,
  IReadOnlyCollection<Guid> ExcludedTenantIds,
  IReadOnlyCollection<Guid> ExcludedDeviceGroupIds,
  IReadOnlyCollection<Guid> ExcludedCustomerIds,
  IReadOnlyCollection<Guid> ExcludedDeviceIds,
  DeviceAccessScope? RequiredOwnerScope)
{
  public static DeviceAccessScope None() =>
    new(false, [], [], [], [], [], [], [], [], null);

  public static DeviceAccessScope ServerWide() =>
    new(true, [], [], [], [], [], [], [], [], null);

  public static DeviceAccessScope Create(
    bool includesServerWide,
    IReadOnlyCollection<Guid> includedTenantIds,
    IReadOnlyCollection<Guid> includedDeviceGroupIds,
    IReadOnlyCollection<Guid> includedCustomerIds,
    IReadOnlyCollection<Guid> includedDeviceIds,
    IReadOnlyCollection<Guid> excludedTenantIds,
    IReadOnlyCollection<Guid> excludedDeviceGroupIds,
    IReadOnlyCollection<Guid> excludedCustomerIds,
    IReadOnlyCollection<Guid> excludedDeviceIds) =>
    new(
      includesServerWide,
      includedTenantIds,
      includedDeviceGroupIds,
      includedCustomerIds,
      includedDeviceIds,
      excludedTenantIds,
      excludedDeviceGroupIds,
      excludedCustomerIds,
      excludedDeviceIds,
      null);

  public DeviceAccessScope RequireOwnerScope(DeviceAccessScope ownerScope) =>
    this with { RequiredOwnerScope = ownerScope };
}