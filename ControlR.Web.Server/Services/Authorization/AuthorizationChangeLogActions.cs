namespace ControlR.Web.Server.Services.Authorization;

/// <summary>
/// Well-known action types for <see cref="AuthorizationChangeLog"/> entries.
/// Stored as human-readable strings in the database for raw inspection.
/// </summary>
public static class AuthorizationChangeLogActions
{
  public const string CredentialScopeRemoved = "credential-scope-removed";
  public const string CredentialScopeSet = "credential-scope-set";
  public const string CredentialScopeTrim = "credential-scope-trim";
  public const string ServiceAccountCreated = "service-account-created";
  public const string ServiceAccountCredentialCreated = "service-account-credential-created";
  public const string ServiceAccountCredentialRevoked = "service-account-credential-revoked";
  public const string ServiceAccountDeleted = "service-account-deleted";
  public const string ServiceAccountUpdated = "service-account-updated";
}

/// <summary>
/// Well-known actor principal types for <see cref="AuthorizationChangeLog"/> entries.
/// Mirrors the canonical principal-type claim values.
/// </summary>
public static class AuthorizationChangeLogActorTypes
{
  public const string ServiceAccount = "service-account";
  public const string System = "system";
  public const string User = "user";
}

/// <summary>
/// Well-known target types for <see cref="AuthorizationChangeLog"/> entries.
/// </summary>
public static class AuthorizationChangeLogTargetTypes
{
  public const string LogonToken = "LogonToken";
  public const string PermissionAssignment = "PermissionAssignment";
  public const string PersonalAccessToken = "PersonalAccessToken";
  public const string ServiceAccount = "ServiceAccount";
  public const string ServiceAccountCredential = "ServiceAccountCredential";
}
