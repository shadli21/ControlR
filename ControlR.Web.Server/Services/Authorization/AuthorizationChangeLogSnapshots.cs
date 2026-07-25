namespace ControlR.Web.Server.Services.Authorization;

/// <summary>
/// Snapshot of a service account's state at a point in time.
/// Used for create/update/delete audit entries.
/// </summary>
public sealed record ServiceAccountSnapshot(
  string Name,
  string Kind,
  string? Description,
  bool IsEnabled);

/// <summary>
/// Snapshot of a service account credential's state at a point in time.
/// Used for credential create/revoke audit entries.
/// </summary>
public sealed record ServiceAccountCredentialSnapshot(
  string Name,
  Guid ServiceAccountId);

/// <summary>
/// Snapshot of a single permission assignment (credential scope) row.
/// Used for scope removal and trim audit entries.
/// </summary>
public sealed record CredentialScopeSnapshot(
  string PermissionName,
  string ScopeKind,
  Guid? ScopeId);

/// <summary>
/// Summary of a batch credential scope mutation.
/// Used for scope-set audit entries where individual rows are not enumerated.
/// </summary>
public sealed record CredentialScopeSetSummary(int ScopeCount);
