namespace ControlR.Web.Client.Authz;

public static class UserClaimTypes
{
  public const string AllowedDesktopSessionId = "controlr:desktop-session:allowed-id";
  public const string AuthenticationMethod = "controlr:auth:method";
  public const string DesktopSessionRestriction = "controlr:desktop-session:restricted";

  // Session restricted to this device only (logon-token sessions).
  public const string DeviceSessionScope = "controlr:device:scope:id";
  public const string SessionCorrelationId = "controlr:session:correlation:id";
  public const string TenantId = "controlr:tenant:id";
  public const string UserId = "controlr:user:id";
}