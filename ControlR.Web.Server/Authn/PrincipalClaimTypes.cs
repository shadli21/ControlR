namespace ControlR.Web.Server.Authn;

/// <summary>
/// Canonical claim types and principal-type values used by the permission rework.
/// Phase 1 introduces the <c>server-service-account</c> principal type; Phase 2 adds
/// <c>tenant-service-account</c> and user/credential variants.
/// </summary>
public static class PrincipalClaimTypes
{
  /// <summary>The credential id when the principal authenticated via a credential (PAT, logon token, service account credential).</summary>
  public const string CredentialId = "controlr:credential:id";

  /// <summary>The credential type (PersonalAccessToken, LogonToken, ServiceAccountCredential).</summary>
  public const string CredentialType = "controlr:credential:type";

  /// <summary>Credential-type value for a logon token.</summary>
  public const string LogonTokenCredentialType = "LogonToken";

  /// <summary>Authentication method value for a logon token.</summary>
  public const string LogonTokenMethod = "logon-token";

  /// <summary>Credential-type value for a personal access token.</summary>
  public const string PersonalAccessTokenCredentialType = "PersonalAccessToken";

  /// <summary>Authentication method value for a personal access token.</summary>
  public const string PersonalAccessTokenMethod = "personal-access-token";

  /// <summary>The stable id of the principal (AppUser.Id or ServiceAccount.Id).</summary>
  public const string PrincipalId = "controlr:principal:id";

  /// <summary>Identifies the kind of principal (user, server-service-account, tenant-service-account).</summary>
  public const string PrincipalType = "controlr:principal:type";

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
