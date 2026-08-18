namespace ControlR.Web.Server.Authz.Permissions;

/// <summary>
/// Translates the canonical principal-type claim <em>values</em> (see
/// <see cref="Authn.PrincipalClaimValues"/>) into the typed <see cref="PrincipalType"/> enum.
/// Unknown or absent values return null so callers can fail closed.
/// </summary>
public static class PrincipalTypeParser
{
  public static PrincipalType? Parse(string? value) => value switch
  {
    Authn.PrincipalClaimValues.User => PrincipalType.User,
    Authn.PrincipalClaimValues.ServerServiceAccount => PrincipalType.ServerServiceAccount,
    Authn.PrincipalClaimValues.TenantServiceAccount => PrincipalType.TenantServiceAccount,
    _ => null
  };
}
