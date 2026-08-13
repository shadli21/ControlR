using ControlR.Web.Server.Authz.Permissions;

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
}

public class PermissionAssignmentSeeder(AppDb appDb) : IPermissionAssignmentSeeder
{
  private readonly AppDb _appDb = appDb;

  /// <summary>
  /// Seeds permission assignments for every permission in the given presets. Each permission is
  /// scoped to its <b>broadest legal scope</b> from the catalog (Server &gt; Tenant &gt;
  /// CustomerTenant/DeviceGroup &gt; Device). Server-wide permissions get ScopeKind.Server with
  /// no ScopeId or OwningTenantId; everything else lands at Tenant scope targeting the given
  /// tenant, matching the PermissionEvaluator's ScopeMatches requirements.
  /// </summary>
  public async Task SeedAssignments(
    Guid userId,
    Guid tenantId,
    IEnumerable<string> presetNames,
    CancellationToken cancellationToken = default)
  {
    var seeded = new HashSet<string>();
    foreach (var presetName in presetNames)
    {
      var permissions = PermissionPresets.GetPermissions(presetName);
      if (permissions.Count == 0)
      {
        continue;
      }

      foreach (var permission in permissions)
      {
        if (!seeded.Add(permission))
        {
          continue;
        }

        var scopeKind = PermissionCatalog.GetBroadestLegalScope(permission) ?? PermissionScopeKind.Tenant;
        var scopeId = scopeKind == PermissionScopeKind.Server ? (Guid?)null : tenantId;

        _appDb.PermissionAssignments.Add(PermissionAssignment.CreateGrant(
          PermissionPrincipalKind.User,
          userId,
          permission,
          scopeKind,
          scopeId,
          tenantId,
          AuthorizationChangeLogActorTypes.System,
          userId.ToString()));
      }
    }

    await _appDb.SaveChangesAsync(cancellationToken);
  }
}
