using ControlR.Libraries.Hosting;

namespace ControlR.Web.Server.Services.Authorization;

public class AuthorizationChangeLogCleanupBackgroundService(
  IDbContextFactory<AppDb> dbContextFactory,
  IOptions<AppOptions> appOptions,
  TimeProvider timeProvider,
  ILogger<PeriodicBackgroundService> logger)
  : PeriodicBackgroundService(TimeSpan.FromHours(24), true, timeProvider, logger)
{
  private readonly IOptions<AppOptions> _appOptions = appOptions;
  private readonly IDbContextFactory<AppDb> _dbContextFactory = dbContextFactory;
  private readonly ILogger _logger = logger;
  private readonly TimeProvider _timeProvider = timeProvider;

  public async Task<int> CleanExpiredEntries(CancellationToken cancellationToken = default)
  {
    var cutoff = GetRetentionCutoff();
    if (!cutoff.HasValue)
    {
      return 0;
    }

    await using var db = await _dbContextFactory.CreateDbContextAsync(cancellationToken);
    var query = db.AuthorizationChangeLogs
      .Where(x => x.CreatedAt < cutoff.Value);

    int removedCount;

    if (db.Database.IsRelational())
    {
      removedCount = await query.ExecuteDeleteAsync(cancellationToken);
    }
    else
    {
      var expiredEntries = await query.ToListAsync(cancellationToken);
      removedCount = expiredEntries.Count;

      if (removedCount > 0)
      {
        db.AuthorizationChangeLogs.RemoveRange(expiredEntries);
        await db.SaveChangesAsync(cancellationToken);
      }
    }

    if (removedCount > 0)
    {
      _logger.LogInformation(
        "Removed {RemovedCount} authorization change log entries older than {Cutoff}.",
        removedCount,
        cutoff.Value);
    }

    return removedCount;
  }

  protected override async Task HandleElapsed()
  {
    await CleanExpiredEntries();
  }

  protected override async Task OnStartingAsync(CancellationToken stoppingToken)
  {
    await CleanExpiredEntries(stoppingToken);
  }

  private DateTimeOffset? GetRetentionCutoff()
  {
    var retentionDays = _appOptions.Value.AuthorizationChangeLogRetentionDays;
    if (retentionDays <= 0)
    {
      return null;
    }

    return _timeProvider.GetUtcNow() - TimeSpan.FromDays(retentionDays);
  }
}
