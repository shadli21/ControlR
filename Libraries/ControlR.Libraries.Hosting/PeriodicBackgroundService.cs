using ControlR.Libraries.Shared.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace ControlR.Libraries.Hosting;

public abstract class PeriodicBackgroundService(
  TimeSpan period,
  TimeProvider timeProvider, 
  ILogger<PeriodicBackgroundService> logger) : BackgroundService
{
  protected readonly ILogger<PeriodicBackgroundService> Logger = logger;

  protected override async Task ExecuteAsync(CancellationToken stoppingToken)
  {
    using var timer = new PeriodicTimer(period, timeProvider);
    using var dedupeScope = Logger.EnterDedupeScope();
    try
    {
      while (await timer.WaitForNextTickAsync(stoppingToken))
      {
        await HandleElapsed();
      }
    }
    catch (OperationCanceledException)
    {
      Logger.LogInformation("Stopping background service. Application is stopping.");
    }
    catch (Exception ex)
    {
      Logger.LogError(ex, "Error in periodic background service.");
    }
  }

  protected abstract Task HandleElapsed();
}
