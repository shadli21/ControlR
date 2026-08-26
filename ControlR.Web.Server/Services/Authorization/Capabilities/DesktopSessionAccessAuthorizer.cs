using ControlR.Web.Server.Authz.Permissions;

namespace ControlR.Web.Server.Services.Authorization.Capabilities;

public interface IDesktopSessionAccessAuthorizer
{
  bool CanUse(PrincipalDescriptor principal, Guid deviceId, int systemSessionId);
}

public class DesktopSessionAccessAuthorizer : IDesktopSessionAccessAuthorizer
{
  public bool CanUse(PrincipalDescriptor principal, Guid deviceId, int systemSessionId)
  {
    if (principal.CredentialType != CredentialType.LogonToken)
    {
      return true;
    }

    if (principal.DeviceScopeId != deviceId)
    {
      return false;
    }

    if (!principal.HasDesktopSessionRestriction)
    {
      return true;
    }

    return principal.AllowedDesktopSessionIds?.Contains(systemSessionId) == true;
  }
}