using ControlR.Web.Server.Authn;
using ControlR.Web.Server.Authz.Permissions;

namespace ControlR.Web.Server.Services.Authorization.PermissionRules;

/// <summary>
/// Interprets <see cref="PermissionAssignment"/> rows into a principal's effective permission
/// rules, used by both the evaluator and the device-scope resolver.
/// </summary>
public interface IPermissionRuleResolver
{
  Task<List<PermissionAssignment>> LoadAssignments(
    PermissionPrincipalKind principalKind,
    Guid principalId,
    CancellationToken cancellationToken);
  Task<ResolvedPrincipalPermissions> Resolve(
    PrincipalDescriptor principal,
    CancellationToken cancellationToken);
}

public class PermissionRuleResolver(
  IDbContextFactory<AppDb> dbContextFactory) : IPermissionRuleResolver
{

  // Memoization cache: within a scoped request, the same principal's assignments
  // may be loaded multiple times (Resolve → LoadAssignments, Evaluate → LoadAssignments).
  private readonly Dictionary<(PermissionPrincipalKind Kind, Guid Id), List<PermissionAssignment>> _cache = [];
  private readonly IDbContextFactory<AppDb> _dbContextFactory = dbContextFactory;

  public async Task<List<PermissionAssignment>> LoadAssignments(
    PermissionPrincipalKind principalKind,
    Guid principalId,
    CancellationToken cancellationToken)
  {
    var key = (principalKind, principalId);
    if (_cache.TryGetValue(key, out var cached))
    {
      return cached;
    }

    await using var db = await _dbContextFactory.CreateDbContextAsync(cancellationToken);
    var assignments = await LoadAssignments(db, principalKind, principalId, cancellationToken);
    _cache[key] = assignments;
    return assignments;
  }

  public async Task<ResolvedPrincipalPermissions> Resolve(
    PrincipalDescriptor principal,
    CancellationToken cancellationToken)
  {
    await using var db = await _dbContextFactory.CreateDbContextAsync(cancellationToken);

    // Server service accounts with no assignments bypass evaluation; once an admin attaches
    // any, they're evaluated (disabling all fails closed, never reverting to bypass).
    if (principal.PrincipalType == PrincipalType.ServerServiceAccount)
    {
      var hasAssignments = await db.PermissionAssignments
        .IgnoreQueryFilters()
        .AnyAsync(x => x.PrincipalKind == PermissionPrincipalKind.ServiceAccount &&
                       x.PrincipalId == principal.PrincipalId, cancellationToken);

      if (!hasAssignments)
      {
        return ResolvedPrincipalPermissions.Bypass();
      }
    }

    var principalKind = ResolvePrincipalKind(principal.PrincipalType);
    var rules = new List<PermissionRule>();

    // Tenant-confined principals see own-tenant rows plus server-scoped rows (no owning
    // tenant); rows from a former tenant are inert. Server service accounts are exempt.
    var userTenantFilter = principal.PrincipalType is PrincipalType.User or PrincipalType.UserGroup or PrincipalType.TenantServiceAccount
      ? principal.TenantId
      : null;

    // Route through the memoizing LoadAssignments so the same principal's rows are read from
    // the DB once per scoped request (Resolve and Evaluate both call this).
    var directAssignments = await LoadAssignments(
      principalKind, principal.PrincipalId, cancellationToken);

    foreach (var assignment in directAssignments.Where(x => IsOwnedByPrincipalTenant(x, userTenantFilter)))
    {
      rules.Add(new PermissionRule(assignment, RuleSource.Direct, SourcePriority.Direct));
    }

    if (principal.PrincipalType == PrincipalType.User)
    {
      var groupAssignments = await LoadUserGroupAssignmentsAsync(db, principal.PrincipalId, cancellationToken);
      foreach (var assignment in groupAssignments.Where(x => IsOwnedByPrincipalTenant(x, userTenantFilter)))
      {
        rules.Add(new PermissionRule(assignment, RuleSource.UserGroup, SourcePriority.UserGroup));
      }
    }

    return ResolvedPrincipalPermissions.Scoped(rules);
  }

  internal static PermissionPrincipalKind ResolvePrincipalKind(PrincipalType principalType) => principalType switch
  {
    PrincipalType.TenantServiceAccount or PrincipalType.ServerServiceAccount => PermissionPrincipalKind.ServiceAccount,
    PrincipalType.UserGroup => PermissionPrincipalKind.UserGroup,
    _ => PermissionPrincipalKind.User
  };

  private static bool IsOwnedByPrincipalTenant(PermissionAssignment assignment, Guid? principalTenantId) =>
    principalTenantId is null ||
    assignment.OwningTenantId is null ||
    assignment.OwningTenantId == principalTenantId;

  private static async Task<List<PermissionAssignment>> LoadAssignments(
    AppDb db,
    PermissionPrincipalKind principalKind,
    Guid principalId,
    CancellationToken cancellationToken)
  {
    return await db.PermissionAssignments
      .IgnoreQueryFilters()
      .Where(x => x.PrincipalKind == principalKind && x.PrincipalId == principalId && x.IsEnabled)
      .ToListAsync(cancellationToken);
  }

  private static async Task<List<PermissionAssignment>> LoadUserGroupAssignmentsAsync(
    AppDb db,
    Guid userId,
    CancellationToken cancellationToken)
  {
    var groupIds = await db.UserGroupMembers
      .IgnoreQueryFilters()
      .Where(x => x.UserId == userId)
      .Select(x => x.UserGroupId)
      .ToListAsync(cancellationToken);

    if (groupIds.Count == 0)
    {
      return [];
    }

    return await db.PermissionAssignments
      .IgnoreQueryFilters()
      .Where(x => x.PrincipalKind == PermissionPrincipalKind.UserGroup &&
                  groupIds.Contains(x.PrincipalId) &&
                  x.IsEnabled)
      .ToListAsync(cancellationToken);
  }
}
