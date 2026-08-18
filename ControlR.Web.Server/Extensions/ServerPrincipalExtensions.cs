using System.Security.Claims;
using ControlR.Libraries.Api.Contracts.Enums;
using ControlR.Web.Client.Extensions;
using ControlR.Web.Server.Authn;

namespace ControlR.Web.Server.Extensions;

/// <summary>
/// Extension methods for reading canonical <c>controlr:*</c> claims from a
/// <see cref="ClaimsPrincipal"/>. These claims are emitted by all authentication
/// handlers (PAT, logon token, service account credential, cookie, interactive bearer).
/// </summary>
public static class ServerPrincipalExtensions
{
  /// <summary>
  /// Maps the authenticated principal's <c>controlr:principal:type</c> claim to the
  /// corresponding <see cref="InstallerKeyCreatorKind"/>. Defaults to <see cref="InstallerKeyCreatorKind.User"/>
  /// when the claim is absent or unrecognized.
  /// </summary>
  public static InstallerKeyCreatorKind GetCreatorKind(this ClaimsPrincipal user)
  {
    return user.GetPrincipalType() switch
    {
      PrincipalClaimValues.ServerServiceAccount => InstallerKeyCreatorKind.ServerServiceAccount,
      PrincipalClaimValues.TenantServiceAccount => InstallerKeyCreatorKind.TenantServiceAccount,
      _ => InstallerKeyCreatorKind.User,
    };
  }

  /// <summary>
  /// Gets the principal type value from the <c>controlr:principal:type</c> claim, or null.
  /// </summary>
  public static string? GetPrincipalType(this ClaimsPrincipal user)
  {
    return user.FindFirst(PrincipalClaimTypes.PrincipalType)?.Value;
  }

  /// <summary>
  /// Returns true when the principal is a server-scoped service account (which
  /// operates cross-tenant by design) or when the principal's tenant claim matches
  /// <paramref name="resourceTenantId"/>. Use as defense-in-depth on V1 endpoints
  /// that load a resource by ID and need to confirm the caller belongs to the
  /// resource's tenant.
  /// </summary>
  public static bool IsInTenant(this ClaimsPrincipal user, Guid resourceTenantId)
  {
    if (user.IsServerPrincipal())
    {
      return true;
    }

    return user.TryGetTenantId(out var callerTenantId) && callerTenantId == resourceTenantId;
  }

  /// <summary>
  /// Returns true when the principal is a server-scoped service account.
  /// </summary>
  public static bool IsServerPrincipal(this ClaimsPrincipal user)
  {
    return user.FindFirst(PrincipalClaimTypes.PrincipalType)?.Value
      == PrincipalClaimValues.ServerServiceAccount;
  }

  /// <summary>
  /// Tries to extract the credential id from the <c>controlr:credential:id</c> claim.
  /// </summary>
  public static bool TryGetCredentialId(this ClaimsPrincipal user, out Guid credentialId)
  {
    var claim = user.FindFirst(PrincipalClaimTypes.CredentialId);
    return Guid.TryParse(claim?.Value, out credentialId);
  }

  /// <summary>
  /// Tries to extract the stable principal id (user or service account) from the
  /// <c>controlr:principal:id</c> claim emitted by all authentication handlers.
  /// </summary>
  public static bool TryGetPrincipalId(this ClaimsPrincipal user, out Guid principalId)
  {
    var claim = user.FindFirst(PrincipalClaimTypes.PrincipalId);
    return Guid.TryParse(claim?.Value, out principalId);
  }

  /// <summary>
  /// Resolves the effective tenant id for an operation. Server-scoped service accounts
  /// may target any tenant (the supplied <paramref name="requestTenantId"/> is trusted).
  /// All other principals must have a tenant claim that matches
  /// <paramref name="requestTenantId"/>; the caller's claim value is returned so the
  /// request body is never the source of truth for non-server principals.
  /// </summary>
  public static bool TryResolveTenantId(
    this ClaimsPrincipal user,
    Guid requestTenantId,
    out Guid tenantId)
  {
    if (user.IsServerPrincipal())
    {
      tenantId = requestTenantId;
      return true;
    }

    if (!user.TryGetTenantId(out var callerTenantId) || callerTenantId != requestTenantId)
    {
      tenantId = Guid.Empty;
      return false;
    }

    tenantId = callerTenantId;
    return true;
  }
}
