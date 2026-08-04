using ControlR.Libraries.Hosting;
using ControlR.Web.Server.Data.Enums;

namespace ControlR.Web.Server.Services.Authorization;

/// <summary>
/// Periodically sweeps personal access tokens that carry explicit scope rows and trims any
/// row that exceeds the owning user's current effective permissions (e.g., after an admin
/// revokes a user's permission). Excess rows are already inert at evaluation time (the
/// PermissionEvaluator intersects PAT scopes with the user's live permissions), so this is
/// storage hygiene rather than a security boundary; staleness is bounded by the sweep period.
/// Each trimmed row is recorded in the <see cref="AuthorizationChangeLog"/>.
/// </summary>
public class PatScopeTrimBackgroundService(
  IDbContextFactory<AppDb> dbContextFactory,
  TimeProvider timeProvider,
  ILogger<PeriodicBackgroundService> logger)
  : PeriodicBackgroundService(TimeSpan.FromMinutes(15), true, timeProvider, logger)
{
  private readonly IDbContextFactory<AppDb> _dbContextFactory = dbContextFactory;

  protected override async Task HandleElapsed()
  {
    await Sweep(CancellationToken.None);
  }

  protected override async Task OnStartingAsync(CancellationToken stoppingToken)
  {
    await Sweep(stoppingToken);
  }

  private async Task ResolveAndTrimAsync(
    AppDb db, Guid tokenId, CancellationToken cancellationToken)
  {
    var scopeRows = await db.PermissionAssignments
      .IgnoreQueryFilters()
      .Where(x => x.PrincipalKind == PermissionPrincipalKind.PersonalAccessToken &&
                  x.PrincipalId == tokenId &&
                  x.IsEnabled)
      .ToListAsync(cancellationToken);

    if (scopeRows.Count == 0)
    {
      return;
    }

    var owningUserId = await db.PersonalAccessTokens
      .IgnoreQueryFilters()
      .Where(x => x.Id == tokenId)
      .Select(x => (Guid?)x.UserId)
      .FirstOrDefaultAsync(cancellationToken);

    if (owningUserId is null)
    {
      Logger.LogWarning(
        "Cannot resolve owning user for personal access token {TokenId}. Skipping trim.",
        tokenId);
      return;
    }

    var userEffectivePermissions = await ResolveUserEffectivePermissions(
      db, owningUserId.Value, cancellationToken);

    var excessRows = scopeRows
      .Where(row => !userEffectivePermissions.Contains(row.PermissionName))
      .ToList();

    if (excessRows.Count == 0)
    {
      return;
    }

    foreach (var row in excessRows)
    {
      db.AuthorizationChangeLogs.Add(AuthorizationChangeLogEntry.Create(
        AuthorizationChangeLogActions.CredentialScopeTrim,
        AuthorizationChangeLogActorTypes.System,
        actorPrincipalId: null,
        AuthorizationChangeLogTargetTypes.PermissionAssignment,
        row.Id.ToString(),
        row.OwningTenantId,
        before: new CredentialScopeSnapshot(
          row.PermissionName, row.ScopeKind, row.ScopeId)));

      db.PermissionAssignments.Remove(row);
    }

    await db.SaveChangesAsync(cancellationToken);

    Logger.LogInformation(
      "Trimmed {Count} excess scope row(s) from personal access token {TokenId}.",
      excessRows.Count, tokenId);
  }

  private async Task<HashSet<string>> ResolveUserEffectivePermissions(
    AppDb db, Guid userId, CancellationToken cancellationToken)
  {
    var permissions = new HashSet<string>();

    var directAssignments = await db.PermissionAssignments
      .IgnoreQueryFilters()
      .Where(x => x.PrincipalKind == PermissionPrincipalKind.User &&
                  x.PrincipalId == userId &&
                  x.IsEnabled &&
                  x.Effect == PermissionEffect.Allow)
      .Select(x => x.PermissionName)
      .ToListAsync(cancellationToken);

    permissions.UnionWith(directAssignments);

    var userGroupIds = await db.UserGroupMembers
      .IgnoreQueryFilters()
      .Where(x => x.UserId == userId)
      .Select(x => x.UserGroupId)
      .ToListAsync(cancellationToken);

    if (userGroupIds.Count > 0)
    {
      var groupPermissions = await db.PermissionAssignments
        .IgnoreQueryFilters()
        .Where(x => x.PrincipalKind == PermissionPrincipalKind.UserGroup &&
                    userGroupIds.Contains(x.PrincipalId) &&
                    x.IsEnabled &&
                    x.Effect == PermissionEffect.Allow)
        .Select(x => x.PermissionName)
        .ToListAsync(cancellationToken);

      permissions.UnionWith(groupPermissions);
    }

    return permissions;
  }

  private async Task Sweep(CancellationToken cancellationToken)
  {
    await using var db = await _dbContextFactory.CreateDbContextAsync(cancellationToken);

    var tokenIds = await db.PermissionAssignments
      .IgnoreQueryFilters()
      .Where(x => x.PrincipalKind == PermissionPrincipalKind.PersonalAccessToken &&
                  x.IsEnabled)
      .Select(x => x.PrincipalId)
      .Distinct()
      .ToListAsync(cancellationToken);

    if (tokenIds.Count == 0)
    {
      return;
    }

    foreach (var tokenId in tokenIds)
    {
      try
      {
        await ResolveAndTrimAsync(db, tokenId, cancellationToken);
      }
      catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
      {
        throw;
      }
      catch (Exception ex)
      {
        Logger.LogError(ex,
          "Error trimming scopes for personal access token {TokenId}.", tokenId);
      }
    }
  }
}
