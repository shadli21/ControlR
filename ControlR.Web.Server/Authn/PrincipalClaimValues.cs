namespace ControlR.Web.Server.Authn;

/// <summary>
/// Canonical claim <em>value</em> strings written into the <c>controlr:*</c> claims. Split from
/// <see cref="PrincipalClaimTypes"/> (which holds claim <em>names</em>) so the two concepts don't
/// share a grab-bag. These are the serialized wire values; the domain model uses typed enums such
/// as <see cref="Authz.Permissions.PrincipalType"/>.
/// </summary>
public static class PrincipalClaimValues
{
  /// <summary>Credential-type value for a logon token.</summary>
  public const string LogonTokenCredentialType = "LogonToken";

  /// <summary>Authentication method value for a logon token.</summary>
  public const string LogonTokenMethod = "logon-token";

  /// <summary>Credential-type value for a personal access token.</summary>
  public const string PersonalAccessTokenCredentialType = "PersonalAccessToken";

  /// <summary>Authentication method value for a personal access token.</summary>
  public const string PersonalAccessTokenMethod = "personal-access-token";

  /// <summary>Principal-type value for a server-scoped service account.</summary>
  public const string ServerServiceAccount = "server-service-account";

  /// <summary>Authentication method value for a service-account credential.</summary>
  public const string ServiceAccountCredentialMethod = "service-account-credential";

  /// <summary>Credential-type value for a service-account credential.</summary>
  public const string ServiceAccountCredentialType = "ServiceAccountCredential";

  /// <summary>Principal-type value for a tenant-scoped service account.</summary>
  public const string TenantServiceAccount = "tenant-service-account";

  /// <summary>Principal-type value for a user.</summary>
  public const string User = "user";
}
