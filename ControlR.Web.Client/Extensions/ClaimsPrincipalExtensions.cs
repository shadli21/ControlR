using System.Security.Claims;

namespace ControlR.Web.Client.Extensions;

public static class ClaimsPrincipalExtensions
{
  public static bool IsAuthenticated(this ClaimsPrincipal user)
  {
    return user.Identity?.IsAuthenticated ?? false;
  }

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