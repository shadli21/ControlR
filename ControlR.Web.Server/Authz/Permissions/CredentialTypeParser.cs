namespace ControlR.Web.Server.Authz.Permissions;

/// <summary>
/// Translates the canonical credential-type claim <em>values</em> (see
/// <see cref="Authn.PrincipalClaimValues"/>) into the typed <see cref="CredentialType"/> enum.
/// Unknown or absent values return null so callers can fail closed.
/// </summary>
public static class CredentialTypeParser
{
  public static CredentialType? Parse(string? value) => value switch
  {
    Authn.PrincipalClaimValues.PersonalAccessTokenCredentialType => CredentialType.PersonalAccessToken,
    Authn.PrincipalClaimValues.LogonTokenCredentialType => CredentialType.LogonToken,
    Authn.PrincipalClaimValues.ServiceAccountCredentialType => CredentialType.ServiceAccountCredential,
    _ => null
  };
}
