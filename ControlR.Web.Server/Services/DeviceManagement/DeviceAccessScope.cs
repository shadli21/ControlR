namespace ControlR.Web.Server.Services.DeviceManagement;

public sealed record DeviceAccessScope(
  Guid? TenantBoundaryId,
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
    new(null, false, [], [], [], [], [], [], [], [], null);

  public static DeviceAccessScope ServerWide() =>
    new(null, true, [], [], [], [], [], [], [], [], null);

  public static DeviceAccessScope Create(
    Guid? tenantBoundaryId,
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
      tenantBoundaryId,
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