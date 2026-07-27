using ControlR.Web.Server.Authn;
using ControlR.Web.Server.Authz.Permissions;

namespace ControlR.Web.Server.Services.Authorization;

/// <summary>
/// Centralized permission evaluator implementing the deterministic evaluation algorithm
/// defined in the permission rework plan. All authorization decisions flow through this
/// class. Uses unfiltered AppDb queries (IgnoreQueryFilters) because the evaluator must
/// see all assignment rows regardless of the requesting principal's tenant context.
/// </summary>
public interface IPermissionEvaluator
{
  Task<PermissionEvaluationResult> Evaluate(
    PrincipalDescriptor principal,
    string permissionName,
    ResourceDescriptor resource,
    CancellationToken cancellationToken);

  Task<IReadOnlySet<string>> GetEffectivePermissionNames(
    PrincipalDescriptor principal,
    CancellationToken cancellationToken);
}

public class PermissionEvaluator(
  IDbContextFactory<AppDb> dbContextFactory,
  IRoleBundleResolver roleBundleResolver) : IPermissionEvaluator
{
  private readonly IDbContextFactory<AppDb> _dbContextFactory = dbContextFactory;
  private readonly IRoleBundleResolver _roleBundleResolver = roleBundleResolver;

  public async Task<PermissionEvaluationResult> Evaluate(
    PrincipalDescriptor principal,
    string permissionName,
    ResourceDescriptor resource,
    CancellationToken cancellationToken)
  {
    // Server-scoped service accounts bypass evaluation when they have no explicit
    // permission assignments (the zero-config RMM use case). Once an admin attaches
    // assignments to a server service account, it opts into fine-grained evaluation
    // while retaining cross-tenant reach (no tenant filter on its assignments).
    if (principal.PrincipalType == PrincipalClaimTypes.ServerServiceAccount)
    {
      await using var bypassDb = await _dbContextFactory.CreateDbContextAsync(cancellationToken);
      var hasAssignments = await bypassDb.PermissionAssignments
        .IgnoreQueryFilters()
        .AnyAsync(x => x.PrincipalKind == PermissionPrincipalKind.ServiceAccount &&
                       x.PrincipalId == principal.PrincipalId &&
                       x.IsEnabled, cancellationToken);

      if (!hasAssignments)
      {
        return PermissionEvaluationResult.Allow("server-service-account-bypass", "Server");
      }
    }

    await using var db = await _dbContextFactory.CreateDbContextAsync(cancellationToken);

    var rules = new List<EvaluationRule>();

    // Step 4: Load explicit (direct) permission assignments for the principal.
    // Service accounts (both server and tenant scoped) use PrincipalKind.ServiceAccount.
    var principalKind = principal.PrincipalType is PrincipalClaimTypes.TenantServiceAccount
        or PrincipalClaimTypes.ServerServiceAccount
      ? PermissionPrincipalKind.ServiceAccount
      : PermissionPrincipalKind.User;

    var directAssignments = await LoadAssignments(
      db, principalKind, principal.PrincipalId, cancellationToken);

    foreach (var assignment in directAssignments)
    {
      rules.Add(new EvaluationRule(assignment, RuleSource.Direct, SourcePriority.Direct));
    }

    // Step 5: Load indirect assignments through user group membership (users only).
    if (principal.PrincipalType == PrincipalClaimTypes.User)
    {
      var groupAssignments = await LoadUserGroupAssignments(db, principal, cancellationToken);
      foreach (var assignment in groupAssignments)
      {
        rules.Add(new EvaluationRule(assignment, RuleSource.UserGroup, SourcePriority.UserGroup));
      }
    }

    // Step 6: Resolve seeded role-bundle permissions from role claims (interim bridge,
    // deleted in PR 13). Each role maps to a static set of permission names. Scoped to
    // the principal's tenant to preserve tenant isolation.
    if (principal.Roles is { Count: > 0 })
    {
      var bundleScopeKind = principal.TenantId.HasValue
        ? PermissionScopeKind.Tenant
        : PermissionScopeKind.Server;

      foreach (var roleName in principal.Roles)
      {
        var bundlePermissions = _roleBundleResolver.ResolvePermissions([roleName]);
        foreach (var perm in bundlePermissions)
        {
          rules.Add(new EvaluationRule(
            new PermissionAssignment
            {
              PermissionName = perm,
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

    // Logon token device-scope enforcement: a logon token session is always restricted
    // to the device it was created for. This is a hard security boundary that applies
    // regardless of scope rows or bridge mode.
    if (principal.CredentialType == PrincipalClaimTypes.LogonTokenCredentialType)
    {
      if (!principal.DeviceScopeId.HasValue)
      {
        return PermissionEvaluationResult.Deny("Logon token principal is missing required device scope.");
      }

      if (resource.Kind == PermissionScopeKind.Device &&
          resource.Id.HasValue &&
          resource.Id.Value != principal.DeviceScopeId.Value)
      {
        return PermissionEvaluationResult.Deny("Logon token session is restricted to its scoped device.");
      }
    }

    // Steps 7-8: Credential-scoped principals (PAT / logon token) use the granting model.
    // The credential's scope rows define what it can do, bounded by the user's effective
    // permissions. Zero scope rows grants nothing.
    // BRIDGE (deleted in PR 13): Until PR 7 adds scope management, no scope rows exist yet.
    // During the bridge period, zero scope rows falls through to the user's effective
    // permissions (preserving pre-rework behavior where PATs/logon tokens inherit full
    // user authority). After PR 13, zero rows will deny.
    if (principal.IsCredentialScoped && principal.CredentialId.HasValue)
    {
      var credentialKind = principal.CredentialType == PrincipalClaimTypes.PersonalAccessTokenCredentialType
        ? PermissionPrincipalKind.PersonalAccessToken
        : PermissionPrincipalKind.LogonToken;

      var credentialAssignments = await LoadAssignments(
        db, credentialKind, principal.CredentialId.Value, cancellationToken);

      if (credentialAssignments.Count > 0)
      {
        // Bounded constraint: intersect credential grants with the user's effective
        // permissions computed above. A user cannot grant a credential permissions they
        // do not themselves hold.
        var userEffectivePermissions = rules
          .Where(r => r.Assignment.Effect == PermissionEffect.Allow)
          .Select(r => r.Assignment.PermissionName)
          .ToHashSet();

        var boundedAssignments = credentialAssignments
          .Where(a => userEffectivePermissions.Contains(a.PermissionName))
          .ToList();

        if (boundedAssignments.Count == 0)
        {
          return PermissionEvaluationResult.Deny("Credential scope grants are outside the user's effective permissions.");
        }

        // Logon tokens are additionally device-scoped: grants must target the specific
        // device the token was created for, preventing cross-device access.
        if (principal.CredentialType == PrincipalClaimTypes.LogonTokenCredentialType &&
            principal.DeviceScopeId.HasValue)
        {
          boundedAssignments = boundedAssignments
            .Where(a => a.ScopeKind == PermissionScopeKind.Device && a.ScopeId == principal.DeviceScopeId.Value)
            .ToList();

          if (boundedAssignments.Count == 0)
          {
            return PermissionEvaluationResult.Deny("Logon token grants do not match the device scope.");
          }
        }

        // Replace the user's rules entirely with the bounded credential grants.
        // The credential's scope is the exclusive permission set for this request.
        rules.Clear();
        var priority = credentialKind == PermissionPrincipalKind.PersonalAccessToken
          ? SourcePriority.CredentialPat
          : SourcePriority.CredentialLogonToken;
        var source = credentialKind == PermissionPrincipalKind.PersonalAccessToken
          ? RuleSource.PatGrant
          : RuleSource.LogonTokenGrant;

        foreach (var assignment in boundedAssignments)
        {
          rules.Add(new EvaluationRule(assignment, source, priority));
        }
      }
      else if (principal.CredentialType == PrincipalClaimTypes.LogonTokenCredentialType &&
               principal.DeviceScopeId.HasValue &&
               resource.Kind == PermissionScopeKind.Device &&
               resource.Id == principal.DeviceScopeId.Value)
      {
        // BRIDGE (deleted in PR 13): Logon token sessions accessing their scoped device
        // are allowed unconditionally when no scope rows exist. This preserves the old
        // DeviceAccessScopeKind.SingleDevice behavior for external/transient users who
        // have no roles or explicit assignments. After PR 7 adds scope management and
        // PR 13 removes the bridge, zero rows will deny.
        return PermissionEvaluationResult.Allow("logon-token-device-scope-bridge", "Device");
      }
    }

    // Step 9: Filter to rules matching the requested permission and resource scope.
    var matchingRules = rules
      .Where(r => r.Assignment.IsEnabled &&
                  r.Assignment.PermissionName == permissionName &&
                  ScopeMatches(r.Assignment, resource))
      .ToList();

    if (matchingRules.Count == 0)
    {
      return PermissionEvaluationResult.Deny("No matching permission assignment found (default deny).");
    }

    // Step 11: Explicit deny always overrides allow, regardless of source or scope.
    var denyRule = matchingRules
      .Where(r => r.Assignment.Effect == PermissionEffect.Deny)
      .OrderBy(r => r.Priority)
      .ThenBy(r => ScopeSpecificity(r.Assignment.ScopeKind))
      .FirstOrDefault();

    if (denyRule is not null)
    {
      return PermissionEvaluationResult.Deny(
        $"Explicit deny from {denyRule.Source} at scope {denyRule.Assignment.ScopeKind}.");
    }

    // Step 12: If any matching allow exists, allow.
    var allowRule = matchingRules
      .Where(r => r.Assignment.Effect == PermissionEffect.Allow)
      .OrderBy(r => r.Priority)
      .ThenBy(r => ScopeSpecificity(r.Assignment.ScopeKind))
      .FirstOrDefault();

    if (allowRule is not null)
    {
      return PermissionEvaluationResult.Allow(
        allowRule.Source.ToString(), allowRule.Assignment.ScopeKind.ToString());
    }

    // Step 13: Default deny.
    return PermissionEvaluationResult.Deny("No matching allow rule found (default deny).");
  }

  /// <summary>
  /// Returns the set of permission names the principal effectively holds (allow rules not
  /// overridden by deny), evaluated at the name level without regard to resource scope. Used
  /// to emit permission claims for client-side policy evaluation. Considers direct assignments,
  /// user-group assignments, and the interim role-bundle bridge. Credential-scoping and the
  /// server-service-account bypass do not apply to interactive UI sessions, which are the only
  /// consumers of this method.
  /// </summary>
  public async Task<IReadOnlySet<string>> GetEffectivePermissionNames(
    PrincipalDescriptor principal,
    CancellationToken cancellationToken)
  {
    await using var db = await _dbContextFactory.CreateDbContextAsync(cancellationToken);

    var principalKind = principal.PrincipalType is PrincipalClaimTypes.TenantServiceAccount
        or PrincipalClaimTypes.ServerServiceAccount
      ? PermissionPrincipalKind.ServiceAccount
      : PermissionPrincipalKind.User;

    var rules = new List<EvaluationRule>();

    var directAssignments = await LoadAssignments(db, principalKind, principal.PrincipalId, cancellationToken);
    foreach (var assignment in directAssignments)
    {
      rules.Add(new EvaluationRule(assignment, RuleSource.Direct, SourcePriority.Direct));
    }

    if (principal.PrincipalType == PrincipalClaimTypes.User)
    {
      var groupAssignments = await LoadUserGroupAssignments(db, principal, cancellationToken);
      foreach (var assignment in groupAssignments)
      {
        rules.Add(new EvaluationRule(assignment, RuleSource.UserGroup, SourcePriority.UserGroup));
      }
    }

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
          rules.Add(new EvaluationRule(
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

    var effective = new HashSet<string>();
    foreach (var group in rules.GroupBy(rule => rule.Assignment.PermissionName))
    {
      if (group.Any(rule => rule.Assignment.Effect == PermissionEffect.Deny))
      {
        continue;
      }

      if (group.Any(rule => rule.Assignment.Effect == PermissionEffect.Allow))
      {
        effective.Add(group.Key);
      }
    }

    return effective;
  }

  /// <summary>
  /// Determines whether an assignment's scope covers the requested resource.
  /// Scope is hierarchical: Server covers everything, Tenant covers resources within
  /// that tenant, DeviceGroup covers devices within the group, Device covers only itself.
  /// </summary>
  private static bool ScopeMatches(PermissionAssignment assignment, ResourceDescriptor resource)
  {
    if (assignment.ScopeKind == PermissionScopeKind.Server)
    {
      return true;
    }

    if (assignment.ScopeKind == PermissionScopeKind.Tenant)
    {
      return resource.TenantId.HasValue && assignment.ScopeId == resource.TenantId.Value;
    }

    if (assignment.ScopeKind == resource.Kind)
    {
      return assignment.ScopeId == resource.Id;
    }

    // A DeviceGroup-scoped assignment also covers individual devices within that group.
    // Membership validation is deferred to the caller; here we allow the match so the
    // evaluator doesn't need a second DB round-trip for group membership.
    if (assignment.ScopeKind == PermissionScopeKind.DeviceGroup &&
        resource.Kind == PermissionScopeKind.Device)
    {
      return true;
    }

    // A CustomerTenant-scoped assignment covers individual devices that belong to that
    // customer. Membership is checked precisely here via the device's CustomerId (carried
    // on the resource descriptor), so no deferred validation is needed.
    if (assignment.ScopeKind == PermissionScopeKind.CustomerTenant &&
        resource.Kind == PermissionScopeKind.Device)
    {
      return resource.CustomerId.HasValue && assignment.ScopeId == resource.CustomerId.Value;
    }

    return false;
  }

  /// <summary>
  /// Returns a numeric specificity rank for scope kinds. Lower values are more specific
  /// (narrower). Used to break ties when multiple rules match at the same source priority.
  /// </summary>
  private static int ScopeSpecificity(PermissionScopeKind scopeKind) => scopeKind switch
  {
    PermissionScopeKind.Device => 0,
    PermissionScopeKind.DeviceGroup => 1,
    PermissionScopeKind.CustomerTenant => 2,
    PermissionScopeKind.Tenant => 3,
    PermissionScopeKind.Server => 4,
    _ => 5
  };

  private async Task<List<PermissionAssignment>> LoadAssignments(
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

  private async Task<List<PermissionAssignment>> LoadUserGroupAssignments(
    AppDb db,
    PrincipalDescriptor principal,
    CancellationToken cancellationToken)
  {
    var groupIds = await db.UserGroupMembers
      .IgnoreQueryFilters()
      .Where(x => x.UserId == principal.PrincipalId)
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

  private enum RuleSource
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
  private enum SourcePriority
  {
    CredentialPat = 0,
    CredentialLogonToken = 1,
    Direct = 2,
    UserGroup = 3,
    RoleBundle = 4
  }

  private sealed record EvaluationRule(
    PermissionAssignment Assignment,
    RuleSource Source,
    SourcePriority Priority);
}
