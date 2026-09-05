using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Services.Authorization;

namespace ControlR.Web.Server.Services.PermissionAssignments;

/// <summary>
/// Seeds permission assignments for newly created or bootstrap principals. Unlike
/// <see cref="IPermissionAssignmentManager"/>, this is a system-level operation with no actor,
/// authority, or tenant-visibility checks, so it is not part of that interface.
/// </summary>
public interface IPermissionAssignmentSeeder
{
  Task SeedAssignments(
    Guid userId,
    Guid tenantId,
    IEnumerable<string> presetNames,
    CancellationToken cancellationToken = default);

  /// <summary>
  /// Seeds the default permission baseline every interactive (non-external) user receives.
  /// Call sites must not inline the preset list. Growing the baseline is a change here plus
  /// the unreleased-migration parity update in RoleBackfillMigrationTests.
  /// </summary>
  Task SeedUserBaseline(
    Guid userId,
    Guid tenantId,
    CancellationToken cancellationToken = default);
}

public class PermissionAssignmentSeeder(
  AppDb appDb,
  IAuthorizationChangeLogFactory changeLogFactory) : IPermissionAssignmentSeeder
{
  private readonly AppDb _appDb = appDb;
  private readonly IAuthorizationChangeLogFactory _changeLogFactory = changeLogFactory;

  /// <summary>
  /// Seeds a principal's preset permissions at their broadest legal scope (Server or Tenant).
  /// Writes one summary change-log entry per seed operation.
  /// </summary>
  public async Task SeedAssignments(
    Guid userId,
    Guid tenantId,
    IEnumerable<string> presetNames,
    CancellationToken cancellationToken = default)
  {
    // Load existing assignments once for in-memory dedup; userId is a primary key, so the
    // scan isn't tenant-filtered and a concurrent seed for the same principal isn't expected.
    var existing = await _appDb.PermissionAssignments
      .IgnoreQueryFilters()
      .AsNoTracking()
      .Where(x => x.PrincipalId == userId && x.PrincipalKind == PermissionPrincipalKind.User)
      .Select(x => new AssignmentKey(x.PermissionName, x.ScopeKind, x.ScopeId, x.Effect))
      .ToHashSetAsync(cancellationToken);

    var appliedPresets = new List<string>();
    var seeded = new HashSet<string>();
    var seededCount = 0;
    foreach (var presetName in presetNames)
    {
      var permissions = PermissionPresets.GetPermissions(presetName);
      if (permissions.Count == 0)
      {
        continue;
      }

      appliedPresets.Add(presetName);
      foreach (var permission in permissions)
      {
        if (!seeded.Add(permission))
        {
          continue;
        }

        var scopeKind = PermissionCatalog.GetBroadestTenantLegalScope(permission) ?? PermissionScopeKind.Tenant;
        var scopeId = scopeKind == PermissionScopeKind.Server ? (Guid?)null : tenantId;

        if (existing.Contains(new AssignmentKey(permission, scopeKind, scopeId, PermissionEffect.Allow)))
        {
          continue;
        }

        _appDb.PermissionAssignments.Add(PermissionAssignment.CreateGrant(
          PermissionPrincipalKind.User,
          userId,
          permission,
          scopeKind,
          scopeId,
          tenantId,
          createdBy: null));
        seededCount++;
      }
    }

    if (seededCount > 0)
    {
      _appDb.AuthorizationChangeLogs.Add(_changeLogFactory.Create(
        AuthorizationChangeLogActions.PermissionAssignmentsSeeded,
        actor: null,
        AuthorizationChangeLogTargetTypes.User,
        userId,
        tenantId,
        after: new PermissionAssignmentSeedSummary(seededCount, appliedPresets)));
    }

    await _appDb.SaveChangesAsync(cancellationToken);
  }

  /// <summary>
  /// Seeds the default permission baseline every interactive (non-external) user receives.
  /// </summary>
  public Task SeedUserBaseline(
    Guid userId,
    Guid tenantId,
    CancellationToken cancellationToken = default) =>
    SeedAssignments(userId, tenantId, [PermissionPresets.SelfService], cancellationToken);

  private readonly record struct AssignmentKey(
    string PermissionName,
    PermissionScopeKind ScopeKind,
    Guid? ScopeId,
    PermissionEffect Effect);
}
