using ControlR.Web.Server.Data.Enums;

namespace ControlR.Web.Server.Services.Authorization;

/// <summary>
/// Background service that processes credential scope trim commands from the
/// <see cref="IPatScopeTrimQueue"/>. When a credential's scope rows exceed the
/// owning user's effective permissions (e.g., after an admin revokes a user's
/// permission), this service removes the excess rows and writes an
/// <see cref="AuthorizationChangeLog"/> entry per trimmed assignment.
/// Deduplicates by credential ID within a processing batch to avoid redundant work.
/// </summary>
public class PatScopeTrimBackgroundService(
  IPatScopeTrimQueue trimQueue,
  IDbContextFactory<AppDb> dbContextFactory,
  ILogger<PatScopeTrimBackgroundService> logger) : BackgroundService
{
  private readonly IDbContextFactory<AppDb> _dbContextFactory = dbContextFactory;
  private readonly ILogger<PatScopeTrimBackgroundService> _logger = logger;
  private readonly IPatScopeTrimQueue _trimQueue = trimQueue;

  protected override async Task ExecuteAsync(CancellationToken stoppingToken)
  {
    _logger.LogInformation("PatScopeTrimBackgroundService started.");

    await foreach (var command in _trimQueue.Reader.ReadAllAsync(stoppingToken))
    {
      try
      {
        await ProcessTrimCommand(command, stoppingToken);
      }
      catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
      {
        break;
      }
      catch (Exception ex)
      {
        _logger.LogError(ex,
          "Error processing scope trim for credential {CredentialId} ({PrincipalKind}).",
          command.CredentialId, command.PrincipalKind);
      }
    }

    _logger.LogInformation("PatScopeTrimBackgroundService stopped.");
  }

  private static async Task<Guid?> ResolveOwningUserId(
    AppDb db, PatScopeTrimCommand command, CancellationToken cancellationToken)
  {
    if (command.PrincipalKind == PermissionPrincipalKind.PersonalAccessToken)
    {
      return await db.PersonalAccessTokens
        .IgnoreQueryFilters()
        .Where(x => x.Id == command.CredentialId)
        .Select(x => (Guid?)x.UserId)
        .FirstOrDefaultAsync(cancellationToken);
    }

    return null;
  }

  private async Task ProcessTrimCommand(PatScopeTrimCommand command, CancellationToken cancellationToken)
  {
    await using var db = await _dbContextFactory.CreateDbContextAsync(cancellationToken);

    var scopeRows = await db.PermissionAssignments
      .IgnoreQueryFilters()
      .Where(x => x.PrincipalKind == command.PrincipalKind &&
                  x.PrincipalId == command.CredentialId &&
                  x.IsEnabled)
      .ToListAsync(cancellationToken);

    if (scopeRows.Count == 0)
    {
      return;
    }

    var owningUserId = await ResolveOwningUserId(db, command, cancellationToken);
    if (owningUserId is null)
    {
      _logger.LogWarning(
        "Cannot resolve owning user for credential {CredentialId}. Skipping trim.",
        command.CredentialId);
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

    _logger.LogInformation(
      "Trimmed {Count} excess scope row(s) from credential {CredentialId} ({PrincipalKind}).",
      excessRows.Count, command.CredentialId, command.PrincipalKind);
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
}
