namespace ControlR.Web.Server.Authn;

/// <summary>Canonical claim names used by the permission evaluator.</summary>
public static class PrincipalClaimTypes
{
  /// <summary>The credential id when the principal authenticated via a credential (PAT, logon token, service account credential).</summary>
  public const string CredentialId = "controlr:credential:id";

  /// <summary>The credential type (PersonalAccessToken, LogonToken, ServiceAccountCredential).</summary>
  public const string CredentialType = "controlr:credential:type";

  /// <summary>The stable id of the principal (AppUser.Id or ServiceAccount.Id).</summary>
  public const string PrincipalId = "controlr:principal:id";

  /// <summary>Identifies the kind of principal (user, server-service-account, tenant-service-account).</summary>
  public const string PrincipalType = "controlr:principal:type";
}

