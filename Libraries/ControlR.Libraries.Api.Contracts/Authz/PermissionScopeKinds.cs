namespace ControlR.Libraries.Api.Contracts.Authz;

public static class PermissionScopeKinds
{
  /// <summary>
  /// Returns the broadest scope kind from the set, or <see langword="null"/> when empty.
  /// </summary>
  public static PermissionScopeKind? GetBroadestLegalScope(
    IReadOnlyCollection<PermissionScopeKind> scopeKinds)
  {
    if (scopeKinds.Count == 0)
    {
      return null;
    }

    return scopeKinds.MaxBy(GetBreadth);
  }

  private static int GetBreadth(PermissionScopeKind scopeKind) => scopeKind switch
  {
    PermissionScopeKind.Device => 0,
    PermissionScopeKind.DeviceGroup => 1,
    PermissionScopeKind.UserGroup => 1,
    PermissionScopeKind.CustomerTenant => 2,
    PermissionScopeKind.Tenant => 3,
    PermissionScopeKind.Server => 4,
    _ => throw new ArgumentOutOfRangeException(
      nameof(scopeKind), scopeKind, "Not a legal resource scope kind.")
  };
}
