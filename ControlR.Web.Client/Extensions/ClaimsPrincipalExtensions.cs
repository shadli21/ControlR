using System.Security.Claims;

namespace ControlR.Web.Client.Extensions;

public static class ClaimsPrincipalExtensions
{

  /// <summary>
  /// Returns true when the server evaluated the named client policy against its canonical
  /// (tenant/server) resource while producing the current auth snapshot and the decision was
  /// allowed. Client policy grants are <see cref="PermissionPolicies.ClientPolicyClaimType"/>
  /// claims whose value is the policy name. This deliberately does not match resource-scoped
  /// permission names, which are never emitted as global claims.
  /// </summary>
  public static bool HasClientPolicy(this ClaimsPrincipal user, string policyName)
  {
    if (!user.IsAuthenticated())
    {
      return false;
    }

    return user.HasClaim(PermissionPolicies.ClientPolicyClaimType, policyName);
  }

  public static bool IsAuthenticated(this ClaimsPrincipal user)
  {
    return user.Identity?.IsAuthenticated ?? false;
  }

  /// <summary>
  /// Tries to extract the device scope id from the <c>controlr:device:scope:id</c> claim.
  /// Present only on logon-token sessions, restricting the session to a single device.
  /// </summary>
  public static bool TryGetDeviceScopeId(
    this ClaimsPrincipal user,
    out Guid deviceId)
  {
    if (!user.IsAuthenticated())
    {
      deviceId = Guid.Empty;
      return false;
    }

    var scopeClaim = user.FindFirst(UserClaimTypes.DeviceSessionScope);
    return Guid.TryParse(scopeClaim?.Value, out deviceId);
  }

  public static bool TryGetTenantId(
    this ClaimsPrincipal user,
    out Guid tenantId)
  {
    if (!user.IsAuthenticated())
    {
      tenantId = Guid.Empty;
      return false;
    }

    var tenantClaim = user.FindFirst(UserClaimTypes.TenantId);
    return Guid.TryParse(tenantClaim?.Value, out tenantId);
  }

  public static bool TryGetUserId(
    this ClaimsPrincipal user,
    out Guid userId)
  {
    if (!user.IsAuthenticated())
    {
      userId = Guid.Empty;
      return false;
    }

    var userIdClaim = user.FindFirst(UserClaimTypes.UserId);
    return Guid.TryParse(userIdClaim?.Value, out userId);
  }
}