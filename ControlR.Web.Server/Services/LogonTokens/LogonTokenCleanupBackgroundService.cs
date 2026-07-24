using ControlR.Libraries.Hosting;

namespace ControlR.Web.Server.Services.LogonTokens;

public class LogonTokenCleanupBackgroundService(
  IDbContextFactory<AppDb> dbContextFactory,
  TimeProvider timeProvider,
  ILogger<PeriodicBackgroundService> logger)
  : PeriodicBackgroundService(TimeSpan.FromHours(1), true, timeProvider, logger)
{
  private readonly IDbContextFactory<AppDb> _dbContextFactory = dbContextFactory;
  private readonly ILogger _logger = logger;
  private readonly TimeProvider _timeProvider = timeProvider;

  public async Task<int> CleanExpiredTokens(CancellationToken cancellationToken = default)
  {
    var now = _timeProvider.GetUtcNow();
    await using var db = await _dbContextFactory.CreateDbContextAsync(cancellationToken);
    var query = db.LogonTokens
      .Where(x => x.ExpiresAt < now || x.IsConsumed);

    int removedCount;

    if (db.Database.IsRelational())
    {
      removedCount = await query.ExecuteDeleteAsync(cancellationToken);
    }
    else
    {
      var expiredTokens = await query.ToListAsync(cancellationToken);
      removedCount = expiredTokens.Count;

      if (removedCount > 0)
      {
        db.LogonTokens.RemoveRange(expiredTokens);
        await db.SaveChangesAsync(cancellationToken);
      }
    }

    if (removedCount > 0)
    {
      _logger.LogInformation("Removed {RemovedCount} expired or consumed logon tokens.", removedCount);
    }

    return removedCount;
  }

  protected override async Task HandleElapsed()
  {
    await CleanExpiredTokens();
  }

  protected override async Task OnStartingAsync(CancellationToken stoppingToken)
  {
    await CleanExpiredTokens(stoppingToken);
  }
}
