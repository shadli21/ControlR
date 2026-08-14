namespace ControlR.Web.Client.Authz;

public static class UserClaimTypes
{
  public const string AllowedDesktopSessionId = "controlr:desktop-session:allowed-id";
  public const string AuthenticationMethod = "controlr:auth:method";
  public const string DesktopSessionRestriction = "controlr:desktop-session:restricted";

  // New explicit claim indicating that the authenticated session is restricted to ONLY this device.
  public const string DeviceSessionScope = "controlr:device:scope:id";
  public const string SessionCorrelationId = "controlr:session:correlation:id";
  public const string TenantId = "controlr:tenant:id";
  public const string UserId = "controlr:user:id";
}