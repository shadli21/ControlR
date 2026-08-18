namespace ControlR.Web.Server.Authn;

/// <summary>
/// Canonical claim <strong>names</strong> used by the permission rework. Holds only the claim-type
/// identifiers; the values written into those claims live in <see cref="PrincipalClaimValues"/> and
/// are modeled as typed enums (e.g. <see cref="Authz.Permissions.PrincipalType"/>) in the domain.
/// Phase 1 introduces the <c>server-service-account</c> principal type; Phase 2 adds
/// <c>tenant-service-account</c> and user/credential variants.
/// </summary>
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

