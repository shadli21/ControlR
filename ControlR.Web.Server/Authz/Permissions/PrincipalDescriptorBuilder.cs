using System.Security.Claims;
using ControlR.Web.Server.Authn;

namespace ControlR.Web.Server.Authz.Permissions;

/// <summary>
/// Builds a <see cref="PrincipalDescriptor"/> from an authenticated principal's claims. Shared
/// by the authorization handler (point authorization) and the device-scope resolver (set
/// enumeration) so both interpret the same claims identically.
/// </summary>
public static class PrincipalDescriptorBuilder
{
  public static PrincipalDescriptor? FromClaims(ClaimsPrincipal user)
  {
    var principalTypeClaim = user.FindFirst(PrincipalClaimTypes.PrincipalType)?.Value;
    var principalIdClaim = user.FindFirst(PrincipalClaimTypes.PrincipalId)?.Value;

    if (PrincipalTypeParser.Parse(principalTypeClaim) is not { } principalType ||
      !Guid.TryParse(principalIdClaim, out var principalId))
    {
      return null;
    }

    Guid? tenantId = null;
    var tenantClaim = user.FindFirst(UserClaimTypes.TenantId)?.Value;
    if (Guid.TryParse(tenantClaim, out var parsedTenantId))
    {
      tenantId = parsedTenantId;
    }

    if (principalType is not PrincipalType.ServerServiceAccount &&
        !tenantId.HasValue)
    {
      return null;
    }

    Guid? credentialId = null;
    var credentialIdClaim = user.FindFirst(PrincipalClaimTypes.CredentialId)?.Value;
    if (Guid.TryParse(credentialIdClaim, out var parsedCredentialId))
    {
      credentialId = parsedCredentialId;
    }

    Guid? deviceScopeId = null;
    var deviceScopeClaim = user.FindFirst(UserClaimTypes.DeviceSessionScope)?.Value;
    if (Guid.TryParse(deviceScopeClaim, out var parsedDeviceScopeId))
    {
      deviceScopeId = parsedDeviceScopeId;
    }

    var allowedDesktopSessionIds = user
      .FindAll(UserClaimTypes.AllowedDesktopSessionId)
      .Select(x => int.TryParse(x.Value, out var sessionId) ? (int?)sessionId : null)
      .OfType<int>()
      .ToHashSet();
    var hasDesktopSessionRestriction = user.HasClaim(
      UserClaimTypes.DesktopSessionRestriction,
      bool.TrueString);

    var authMethod = user.FindFirst(UserClaimTypes.AuthenticationMethod)?.Value ?? "unknown";
    var credentialTypeClaim = user.FindFirst(PrincipalClaimTypes.CredentialType)?.Value;
    var credentialType = CredentialTypeParser.Parse(credentialTypeClaim);

    return new PrincipalDescriptor(
      principalType,
      principalId,
      tenantId,
      authMethod,
      credentialId,
      credentialType,
      deviceScopeId,
      allowedDesktopSessionIds.Count == 0 ? null : allowedDesktopSessionIds,
      hasDesktopSessionRestriction);
  }
}
