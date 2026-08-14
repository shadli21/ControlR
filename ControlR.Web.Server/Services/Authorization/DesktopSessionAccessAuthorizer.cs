using ControlR.Web.Server.Authn;
using ControlR.Web.Server.Authz.Permissions;

namespace ControlR.Web.Server.Services.Authorization;

public interface IDesktopSessionAccessAuthorizer
{
  bool CanUse(PrincipalDescriptor principal, Guid deviceId, int systemSessionId);
}

public class DesktopSessionAccessAuthorizer : IDesktopSessionAccessAuthorizer
{
  public bool CanUse(PrincipalDescriptor principal, Guid deviceId, int systemSessionId)
  {
    if (principal.CredentialType != PrincipalClaimTypes.LogonTokenCredentialType)
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