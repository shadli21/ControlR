using ControlR.Web.Server.Data.Enums;

namespace ControlR.Web.Server.Services.Authorization;

/// <summary>
/// Snapshot of a service account's state at a point in time.
/// Used for create/update/delete audit entries.
/// </summary>
public sealed record ServiceAccountSnapshot(
  string Name,
  ServiceAccountKind Kind,
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
  PermissionScopeKind ScopeKind,
  Guid? ScopeId);

/// <summary>
/// Summary of a batch credential scope mutation.
/// Used for scope-set audit entries where individual rows are not enumerated.
/// </summary>
public sealed record CredentialScopeSetSummary(int ScopeCount);

/// <summary>
/// Summary of a failed batch credential scope write. Written before orphan-token cleanup
/// so the failed creation attempt leaves a trail in <see cref="AuthorizationChangeLog"/>.
/// </summary>
public sealed record CredentialScopeSetFailureSummary(int ScopeCount, string Reason);

/// <summary>
/// Summary of a preset-seeding operation. One entry is written per seed call rather than one
/// per seeded row, so bootstrap grants are auditable without per-row noise.
/// </summary>
public sealed record PermissionAssignmentSeedSummary(int Count, IReadOnlyList<string> Presets);

/// <summary>
/// Snapshot of a customer's state at a point in time.
/// Used for create/update/delete audit entries.
/// </summary>
public sealed record CustomerSnapshot(string Name, string? Description, string? Notes);

/// <summary>
/// Summary of a customer device-assignment change.
/// Used for device assignment audit entries.
/// </summary>
public sealed record CustomerDeviceAssignmentChange(int Count);

/// <summary>
/// Snapshot of a device group's state at a point in time.
/// Used for create/update/delete audit entries.
/// </summary>
public sealed record DeviceGroupSnapshot(string Name, string? Description);

/// <summary>
/// Summary of a device group membership change.
/// Used for member add/remove audit entries.
/// </summary>
public sealed record DeviceGroupMembershipChange(int Count);

/// <summary>
/// Snapshot of a user group's state at a point in time.
/// Used for create/update/delete audit entries.
/// </summary>
public sealed record UserGroupSnapshot(string Name, string? Description);

/// <summary>
/// Summary of a user group membership change.
/// Used for member add/remove audit entries.
/// </summary>
public sealed record UserGroupMembershipChange(int Count);

/// <summary>
/// Snapshot of a permission assignment's key fields.
/// Used for create/delete audit entries.
/// </summary>
public sealed record PermissionAssignmentSnapshot(
  string PermissionName,
  PermissionEffect Effect,
  PermissionScopeKind ScopeKind,
  Guid? ScopeId);
