using System.Security.Claims;
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
  /// Gets the principal type value from the <c>controlr:principal:type</c> claim, or null.
  /// </summary>
  public static string? GetPrincipalType(this ClaimsPrincipal user)
  {
    return user.FindFirst(PrincipalClaimTypes.PrincipalType)?.Value;
  }

  /// <summary>
  /// Returns true when the principal is a server-scoped service account.
  /// </summary>
  public static bool IsServerPrincipal(this ClaimsPrincipal user)
  {
    return user.FindFirst(PrincipalClaimTypes.PrincipalType)?.Value
      == PrincipalClaimTypes.ServerServiceAccount;
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
}
