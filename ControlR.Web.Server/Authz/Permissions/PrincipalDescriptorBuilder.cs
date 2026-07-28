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
    var principalType = user.FindFirst(PrincipalClaimTypes.PrincipalType)?.Value;
    var principalIdClaim = user.FindFirst(PrincipalClaimTypes.PrincipalId)?.Value;

    if (principalType is null || !Guid.TryParse(principalIdClaim, out var principalId))
    {
      return null;
    }

    Guid? tenantId = null;
    var tenantClaim = user.FindFirst(UserClaimTypes.TenantId)?.Value;
    if (Guid.TryParse(tenantClaim, out var parsedTenantId))
    {
      tenantId = parsedTenantId;
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

    var authMethod = user.FindFirst(UserClaimTypes.AuthenticationMethod)?.Value ?? "unknown";
    var credentialType = user.FindFirst(PrincipalClaimTypes.CredentialType)?.Value;
    var roles = user.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList();

    return new PrincipalDescriptor(
      principalType,
      principalId,
      tenantId,
      authMethod,
      credentialId,
      credentialType,
      deviceScopeId,
      roles);
  }
}
