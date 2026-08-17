using ControlR.Libraries.Hosting;
using ControlR.Web.Server.Services.Authorization;

namespace ControlR.Web.Server.Services.LogonTokens;

public class LogonTokenCleanupBackgroundService(
  IDbContextFactory<AppDb> dbContextFactory,
  IAuthorizationChangeLogFactory changeLogFactory,
  IOptions<AppOptions> appOptions,
  TimeProvider timeProvider,
  ILogger<PeriodicBackgroundService> logger)
  : PeriodicBackgroundService(
    period: TimeSpan.FromHours(1),
    catchExceptions: true,
    timeProvider: timeProvider,
    logger: logger)
{
  private const int GrantCleanupBatchSize = 500;

  private readonly IOptions<AppOptions> _appOptions = appOptions;
  private readonly IAuthorizationChangeLogFactory _changeLogFactory = changeLogFactory;
  private readonly SemaphoreSlim _cleanupLock = new(1, 1);
  private readonly IDbContextFactory<AppDb> _dbContextFactory = dbContextFactory;
  private readonly ILogger _logger = logger;
  private readonly TimeProvider _timeProvider = timeProvider;
  private CancellationToken _stoppingToken;

  public async Task<int> CleanExpiredTokens(CancellationToken cancellationToken = default)
  {
    var now = _timeProvider.GetUtcNow();
    await using var db = await _dbContextFactory.CreateDbContextAsync(cancellationToken);
    var query = db.LogonTokens
      .Where(x => x.ExpiresAt < now || x.IsConsumed);

    var removedCount = await query.ExecuteDeleteCompatAsync(db, cancellationToken);

    if (removedCount > 0)
    {
      _logger.LogInformation("Removed {RemovedCount} expired or consumed logon tokens.", removedCount);
    }

    return removedCount;
  }

  /// <summary>
  /// Removes logon-token grant rows that outlived the cleanup cutoff. Tokens themselves die
  /// within a day of creation (consumption or hourly expiry cleanup), but their grant rows
  /// must outlive the token because the cookie session keeps using them; after the cutoff
  /// even the longest-lived session has expired, so the rows are safe to remove. Each former
  /// token's removed rows are summarized in the <see cref="AuthorizationChangeLog"/>. Rows
  /// are removed in batches, each with a fresh <see cref="AppDb"/> so the change tracker
  /// stays bounded regardless of backlog size.
  /// </summary>
  public async Task<int> CleanOrphanedTokenGrants(CancellationToken cancellationToken = default)
  {
    var cutoff = GetGrantCleanupCutoff();
    if (!cutoff.HasValue)
    {
      return 0;
    }

    var totalRemoved = 0;
    while (true)
    {
      cancellationToken.ThrowIfCancellationRequested();

      var removedCount = await RemoveGrantBatch(cutoff.Value, cancellationToken);
      if (removedCount == 0)
      {
        break;
      }

      totalRemoved += removedCount;
    }

    if (totalRemoved > 0)
    {
      _logger.LogInformation(
        "Removed {RemovedCount} orphaned logon token grant row(s) created before {Cutoff}.",
        totalRemoved,
        cutoff.Value);
    }

    return totalRemoved;
  }

  protected override async Task HandleElapsed()
  {
    await RunCleanup(_stoppingToken);
  }

  protected override async Task OnStartingAsync(CancellationToken stoppingToken)
  {
    _stoppingToken = stoppingToken;
    await RunCleanup(stoppingToken);
  }

  private DateTimeOffset? GetGrantCleanupCutoff()
  {
    var cleanupDays = _appOptions.Value.LogonTokenGrantCleanupAfterDays;
    if (cleanupDays < 1)
    {
      return null;
    }

    return _timeProvider.GetUtcNow() - TimeSpan.FromDays(cleanupDays);
  }

  private async Task<int> RemoveGrantBatch(DateTimeOffset cutoff, CancellationToken cancellationToken)
  {
    await using var db = await _dbContextFactory.CreateDbContextAsync(cancellationToken);

    var batch = await db.PermissionAssignments
      .IgnoreQueryFilters()
      .Where(x => x.PrincipalKind == PermissionPrincipalKind.LogonToken && x.CreatedAt < cutoff)
      .OrderBy(x => x.Id)
      .Take(GrantCleanupBatchSize)
      .ToListAsync(cancellationToken);

    if (batch.Count == 0)
    {
      return 0;
    }

    foreach (var tokenGroup in batch.GroupBy(x => x.PrincipalId))
    {
      db.AuthorizationChangeLogs.Add(_changeLogFactory.Create(
        AuthorizationChangeLogActions.CredentialScopeRemoved,
        AuthorizationChangeLogActorTypes.System,
        actorPrincipalId: null,
        AuthorizationChangeLogTargetTypes.LogonToken,
        tokenGroup.Key,
        tokenGroup.First().OwningTenantId,
        before: new CredentialScopeSetSummary(tokenGroup.Count())));
    }

    db.PermissionAssignments.RemoveRange(batch);
    await db.SaveChangesAsync(cancellationToken);

    return batch.Count;
  }

  private async Task RunCleanup(CancellationToken cancellationToken)
  {
    if (!await _cleanupLock.WaitAsync(0, cancellationToken))
    {
      return;
    }

    try
    {
      await CleanExpiredTokens(cancellationToken);
      await CleanOrphanedTokenGrants(cancellationToken);
    }
    finally
    {
      _cleanupLock.Release();
    }
  }
}
