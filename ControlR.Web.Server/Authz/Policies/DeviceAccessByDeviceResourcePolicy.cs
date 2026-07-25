using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Data.Enums;

namespace ControlR.Web.Server.Authz.Policies;

/// <summary>
/// Resource-based authorization policy for device access. Delegates to the centralized
/// permission evaluator with <c>device.read</c>. The policy name is preserved so existing
/// consumers (controllers, hubs) continue working during the PR-sequencing period.
/// In PR 11 (Endpoint Migration Sweep), consumers will migrate to granular per-permission
/// policies and this bridge will be removed in PR 13.
/// </summary>
public static class DeviceAccessByDeviceResourcePolicy
{
  public const string PolicyName = "DeviceAccessByDeviceResourcePolicy";

  public static AuthorizationPolicy Create()
  {
    return new AuthorizationPolicyBuilder()
      .RequireAuthenticatedUser()
      .RequirePermission(PermissionNames.DeviceRead, PermissionScopeKind.Device)
      .Build();
  }
}