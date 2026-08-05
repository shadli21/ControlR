using ControlR.Libraries.Hosting;
using ControlR.Web.Server.Authn;
using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Data.Enums;

namespace ControlR.Web.Server.Services.Authorization;

/// <summary>
/// Periodically sweeps personal access tokens that carry explicit scope rows and trims any
/// row that exceeds the owning user's current effective permissions (e.g., after an admin
/// revokes a user's permission). Excess rows are already inert at evaluation time (the
/// PermissionEvaluator intersects PAT scopes with the user's live permissions), so this is
/// storage hygiene rather than a security boundary; staleness is bounded by the sweep period.
/// Each trimmed row is recorded in the <see cref="AuthorizationChangeLog"/>. Effective
/// permissions are resolved through <see cref="IPermissionRuleResolver"/> so row
/// interpretation stays in its single source of truth.
/// </summary>
public class PatScopeTrimBackgroundService(
  IDbContextFactory<AppDb> dbContextFactory,
  IServiceScopeFactory scopeFactory,
  TimeProvider timeProvider,
  ILogger<PeriodicBackgroundService> logger)
  : PeriodicBackgroundService(TimeSpan.FromMinutes(15), true, timeProvider, logger)
{
  private readonly IDbContextFactory<AppDb> _dbContextFactory = dbContextFactory;
  private readonly IServiceScopeFactory _scopeFactory = scopeFactory;

  protected override async Task HandleElapsed()
  {
    await Sweep(CancellationToken.None);
  }

  protected override async Task OnStartingAsync(CancellationToken stoppingToken)
  {
    await Sweep(stoppingToken);
  }

  private async Task ResolveAndTrimAsync(
    AppDb db,
    IPermissionRuleResolver ruleResolver,
    Guid tokenId,
    CancellationToken cancellationToken)
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

    var owner = await db.PersonalAccessTokens
      .IgnoreQueryFilters()
      .Where(x => x.Id == tokenId)
      .Select(x => new { x.UserId, UserTenantId = x.User!.TenantId })
      .FirstOrDefaultAsync(cancellationToken);

    if (owner is null)
    {
      Logger.LogWarning(
        "Cannot resolve owning user for personal access token {TokenId}. Skipping trim.",
        tokenId);
      return;
    }

    var principal = new PrincipalDescriptor(
      PrincipalType: PrincipalClaimTypes.User,
      PrincipalId: owner.UserId,
      TenantId: owner.UserTenantId,
      AuthMethod: "pat-scope-trim");

    var resolved = await ruleResolver.Resolve(principal, cancellationToken);
    var userEffectivePermissions = resolved.GetEffectivePermissionNames();

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

    using var scope = _scopeFactory.CreateScope();
    var ruleResolver = scope.ServiceProvider.GetRequiredService<IPermissionRuleResolver>();

    foreach (var tokenId in tokenIds)
    {
      try
      {
        await ResolveAndTrimAsync(db, ruleResolver, tokenId, cancellationToken);
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
