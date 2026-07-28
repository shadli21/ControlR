using ControlR.Web.Server.Authn;
using ControlR.Web.Server.Authz.Permissions;

namespace ControlR.Web.Server.Services.Authorization;

public enum RuleSource
{
  Direct,
  UserGroup,
  RoleBundle,
  PatGrant,
  LogonTokenGrant
}

/// <summary>
/// Source priority for tie-breaking. Lower values win. Credential grants are highest
/// priority because they represent the narrowest, most intentional grant.
/// </summary>
public enum SourcePriority
{
  CredentialPat = 0,
  CredentialLogonToken = 1,
  Direct = 2,
  UserGroup = 3,
  RoleBundle = 4
}

public sealed record PermissionRule(
  PermissionAssignment Assignment,
  RuleSource Source,
  SourcePriority Priority);

/// <summary>
/// The result of interpreting a principal's permission assignments. <see cref="ServerBypass"/>
/// is true for a server-scoped service account that has no explicit assignments (the zero-config
/// RMM use case); such a principal is unrestricted. Otherwise <see cref="Rules"/> holds the
/// assembled allow/deny rules (direct, user-group, and the interim role-bundle bridge).
/// </summary>
public sealed record ResolvedPrincipalPermissions(
  bool ServerBypass,
  IReadOnlyList<PermissionRule> Rules)
{
  public static ResolvedPrincipalPermissions Bypass() => new(true, []);

  public static ResolvedPrincipalPermissions Scoped(IReadOnlyList<PermissionRule> rules) => new(false, rules);
}

/// <summary>
/// Single source of truth for interpreting <see cref="PermissionAssignment"/> rows into a
/// principal's effective permission rules. Both the point-authorization evaluator
/// (<see cref="IPermissionEvaluator"/>) and the set-enumeration device-scope resolver
/// (<see cref="DeviceManagement.IDeviceAccessScopeResolver"/>) consume this so assignment
/// rows are interpreted in exactly one place. Credential-grant bounding and per-resource
/// scope/deny resolution remain the evaluator's responsibility; query projection remains
/// the resolver's.
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
  IDbContextFactory<AppDb> dbContextFactory,
  IRoleBundleResolver roleBundleResolver) : IPermissionRuleResolver
{
  private readonly IDbContextFactory<AppDb> _dbContextFactory = dbContextFactory;
  private readonly IRoleBundleResolver _roleBundleResolver = roleBundleResolver;

  public async Task<List<PermissionAssignment>> LoadAssignments(
    PermissionPrincipalKind principalKind,
    Guid principalId,
    CancellationToken cancellationToken)
  {
    await using var db = await _dbContextFactory.CreateDbContextAsync(cancellationToken);
    return await LoadAssignments(db, principalKind, principalId, cancellationToken);
  }

  public async Task<ResolvedPrincipalPermissions> Resolve(
    PrincipalDescriptor principal,
    CancellationToken cancellationToken)
  {
    await using var db = await _dbContextFactory.CreateDbContextAsync(cancellationToken);

    // Server-scoped service accounts bypass evaluation when they have no explicit
    // permission assignments (the zero-config RMM use case). Once an admin attaches
    // assignments to a server service account, it opts into fine-grained evaluation
    // while retaining cross-tenant reach (no tenant filter on its assignments).
    if (principal.PrincipalType == PrincipalClaimTypes.ServerServiceAccount)
    {
      var hasAssignments = await db.PermissionAssignments
        .IgnoreQueryFilters()
        .AnyAsync(x => x.PrincipalKind == PermissionPrincipalKind.ServiceAccount &&
                       x.PrincipalId == principal.PrincipalId &&
                       x.IsEnabled, cancellationToken);

      if (!hasAssignments)
      {
        return ResolvedPrincipalPermissions.Bypass();
      }
    }

    var principalKind = ResolvePrincipalKind(principal.PrincipalType);
    var rules = new List<PermissionRule>();

    var directAssignments = await LoadAssignments(
      db, principalKind, principal.PrincipalId, cancellationToken);
    foreach (var assignment in directAssignments)
    {
      rules.Add(new PermissionRule(assignment, RuleSource.Direct, SourcePriority.Direct));
    }

    if (principal.PrincipalType == PrincipalClaimTypes.User)
    {
      var groupAssignments = await LoadUserGroupAssignmentsAsync(db, principal.PrincipalId, cancellationToken);
      foreach (var assignment in groupAssignments)
      {
        rules.Add(new PermissionRule(assignment, RuleSource.UserGroup, SourcePriority.UserGroup));
      }
    }

    // Interim role-bundle bridge (deleted in PR 13): each role maps to a static set of
    // permission names, synthesized as allow rules scoped to the principal's tenant to
    // preserve tenant isolation.
    if (principal.Roles is { Count: > 0 })
    {
      var bundleScopeKind = principal.TenantId.HasValue
        ? PermissionScopeKind.Tenant
        : PermissionScopeKind.Server;

      foreach (var roleName in principal.Roles)
      {
        var bundlePermissions = _roleBundleResolver.ResolvePermissions([roleName]);
        foreach (var permission in bundlePermissions)
        {
          rules.Add(new PermissionRule(
            new PermissionAssignment
            {
              PermissionName = permission,
              Effect = PermissionEffect.Allow,
              ScopeKind = bundleScopeKind,
              ScopeId = principal.TenantId,
              PrincipalKind = PermissionPrincipalKind.User,
              PrincipalId = principal.PrincipalId,
              IsEnabled = true
            },
            RuleSource.RoleBundle,
            SourcePriority.RoleBundle));
        }
      }
    }

    return ResolvedPrincipalPermissions.Scoped(rules);
  }

  internal static PermissionPrincipalKind ResolvePrincipalKind(string principalType) =>
    principalType is PrincipalClaimTypes.TenantServiceAccount
        or PrincipalClaimTypes.ServerServiceAccount
      ? PermissionPrincipalKind.ServiceAccount
      : PermissionPrincipalKind.User;

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
