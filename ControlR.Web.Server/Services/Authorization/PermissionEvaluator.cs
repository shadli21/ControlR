using ControlR.Web.Server.Authn;
using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Services.Authorization.PermissionRules;

namespace ControlR.Web.Server.Services.Authorization;

/// <summary>
/// Centralized permission evaluator implementing the deterministic evaluation algorithm
/// defined in the permission rework plan. All point-authorization decisions flow through this
/// class. <see cref="PermissionAssignment"/> rows are interpreted by <see cref="IPermissionRuleResolver"/>;
/// this class adds credential-grant bounding, logon-token device enforcement, per-resource scope
/// matching, and deny/allow resolution.
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
  IPermissionRuleResolver ruleResolver,
  IDbContextFactory<AppDb> dbContextFactory) : IPermissionEvaluator
{
  private readonly IDbContextFactory<AppDb> _dbContextFactory = dbContextFactory;
  private readonly IPermissionRuleResolver _ruleResolver = ruleResolver;

  public async Task<PermissionEvaluationResult> Evaluate(
    PrincipalDescriptor principal,
    string permissionName,
    ResourceDescriptor resource,
    CancellationToken cancellationToken)
  {
    var resolved = await _ruleResolver.Resolve(principal, cancellationToken);

    if (resolved.ServerBypass)
    {
      return PermissionEvaluationResult.Allow("server-service-account-bypass", "Server");
    }

    var rules = resolved.Rules.ToList();

    // Logon tokens are always restricted to their scoped device.
    if (principal.CredentialType == CredentialType.LogonToken)
    {
      if (!principal.DeviceScopeId.HasValue)
      {
        return PermissionEvaluationResult.Deny("Logon token principal is missing required device scope.");
      }

      // A logon token without a credential id cannot resolve its grant rows; fail closed.
      if (!principal.CredentialId.HasValue)
      {
        return PermissionEvaluationResult.Deny("Logon token principal is missing required credential id.");
      }

      if (resource.Kind == PermissionScopeKind.Device &&
          resource.Id.HasValue &&
          resource.Id.Value != principal.DeviceScopeId.Value)
      {
        return PermissionEvaluationResult.Deny("Logon token session is restricted to its scoped device.");
      }
    }

    // Credential-scoped principals. PATs act as their owning user (scope rows are optional
    // least-privilege). Logon tokens are self-contained device grants to a recipient who may
    // have no permissions of their own, never inherited from or bounded by the recipient.
    if (principal.IsCredentialScoped && principal.CredentialId.HasValue)
    {
      var isLogonToken = principal.CredentialType == CredentialType.LogonToken;
      var credentialKind = isLogonToken
        ? PermissionPrincipalKind.LogonToken
        : PermissionPrincipalKind.PersonalAccessToken;

      var credentialAssignments = await _ruleResolver.LoadAssignments(
        credentialKind, principal.CredentialId.Value, cancellationToken);

      if (isLogonToken)
      {
        // Zero rows grants nothing; grants are restricted to the token's scoped device
        // (hard-enforced above), so the token can never reach beyond its device.
        var deviceAssignments = credentialAssignments
          .Where(a => a.ScopeKind == PermissionScopeKind.Device &&
                      principal.DeviceScopeId.HasValue &&
                      a.ScopeId == principal.DeviceScopeId.Value)
          .ToList();

        if (deviceAssignments.Count == 0)
        {
          return PermissionEvaluationResult.Deny("Logon token grants do not match the device scope.");
        }

        rules.Clear();
        foreach (var assignment in deviceAssignments)
        {
          rules.Add(new PermissionRule(assignment, RuleSource.LogonTokenGrant, SourcePriority.CredentialLogonToken));
        }
      }
      else if (credentialAssignments.Count > 0)
      {
        // Batch-load device-scoped rows to avoid N+1 queries.
        var deviceScopes = credentialAssignments
          .Where(a => a.ScopeKind == PermissionScopeKind.Device && a.ScopeId.HasValue)
          .Select(a => a.ScopeId!.Value)
          .Distinct()
          .ToList();

        var deviceInfo = new Dictionary<Guid, DeviceInfo>();
        if (deviceScopes.Count > 0)
        {
          await using var db = await _dbContextFactory.CreateDbContextAsync(cancellationToken);

          // Load device details in a single query.
          var devices = await db.Devices
            .IgnoreQueryFilters()
            .AsNoTracking()
            .Where(d => deviceScopes.Contains(d.Id))
            .ToListAsync(cancellationToken);

          // Load group memberships in a single query, then GroupBy in memory.
          var groupRows = await db.DeviceGroupMembers
            .IgnoreQueryFilters()
            .AsNoTracking()
            .Where(m => deviceScopes.Contains(m.DeviceId))
            .Select(m => new { m.DeviceId, m.DeviceGroupId })
            .ToListAsync(cancellationToken);

          var groupMappings = groupRows
            .GroupBy(r => r.DeviceId)
            .ToDictionary(g => g.Key, g => g.Select(r => r.DeviceGroupId).ToList());

          deviceInfo = devices
            .ToDictionary(
              d => d.Id,
              d => new DeviceInfo(
                d.Id,
                d.TenantId,
                d.CustomerId,
                groupMappings.TryGetValue(d.Id, out var g) ? g : []));
        }

        var boundedAssignments = new List<PermissionAssignment>();
        foreach (var row in credentialAssignments)
        {
          bool covered;
          if (row.ScopeKind == PermissionScopeKind.Device && row.ScopeId.HasValue)
          {
            covered = deviceInfo.TryGetValue(row.ScopeId.Value, out var info)
              ? ResolveMatchingRules(rules, row.PermissionName,
                  new ResourceDescriptor(PermissionScopeKind.Device, info.Id, info.TenantId, info.CustomerId, info.GroupIds)).Allowed
              : false;
          }
          else
          {
            covered = UserRulesCoverScope(rules, row);
          }

          if (covered)
          {
            boundedAssignments.Add(row);
          }
        }

        if (boundedAssignments.Count == 0)
        {
          return PermissionEvaluationResult.Deny("Credential scope grants are outside the user's effective permissions.");
        }

        rules.Clear();
        foreach (var assignment in boundedAssignments)
        {
          rules.Add(new PermissionRule(assignment, RuleSource.PatGrant, SourcePriority.CredentialPat));
        }
      }
      // A PAT with zero scope rows falls through unchanged: it acts as the user with the
      // user's full effective permissions resolved above.
    }

    return ResolveMatchingRules(rules, permissionName, resource);
  }

  /// <summary>
  /// Returns the user's effective permission names (deny overrides allow), ignoring
  /// credential-scoping and the server-service-account bypass. This is the *user's* set, for
  /// paths that act as the user proper (e.g. claim emission and hub topic subscription).
  /// Use <see cref="Evaluate"/> when deciding what a credential (PAT/logon token) may do.
  /// </summary>
  public async Task<IReadOnlySet<string>> GetEffectivePermissionNames(
    PrincipalDescriptor principal,
    CancellationToken cancellationToken)
  {
    var resolved = await _ruleResolver.Resolve(principal, cancellationToken);
    return resolved.GetEffectivePermissionNames();
  }

  /// <summary>
  /// Resolves the allow/deny outcome for the rules matching a permission at a resource:
  /// explicit deny overrides allow; otherwise any matching allow permits; otherwise default deny.
  /// </summary>
  private static PermissionEvaluationResult ResolveMatchingRules(
    List<PermissionRule> rules,
    string permissionName,
    ResourceDescriptor resource)
  {
    var matchingRules = rules
      .Where(r => r.Assignment.IsEnabled &&
                  r.Assignment.PermissionName == permissionName &&
                  ScopeMatches(r.Assignment, resource))
      .ToList();

    if (matchingRules.Count == 0)
    {
      return PermissionEvaluationResult.Deny("No matching permission assignment found (default deny).");
    }

    // Explicit deny always overrides allow, regardless of source or scope.
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

    return PermissionEvaluationResult.Deny("No matching allow rule found (default deny).");
  }

  /// <summary>
  /// Whether a user rule's scope covers a credential scope row. Only server grants cover
  /// server-scoped rows or rows without an owning tenant (fail-closed); group, customer, and
  /// device grants cover only same-scope rows.
  /// </summary>
  private static bool RuleCoversScope(
    PermissionAssignment userRule,
    PermissionScopeKind rowScopeKind,
    Guid? rowScopeId,
    Guid? rowOwningTenantId)
  {
    if (userRule.ScopeKind == PermissionScopeKind.Server)
    {
      return true;
    }

    if (rowScopeKind == PermissionScopeKind.Server)
    {
      return false;
    }

    return (userRule.ScopeKind, rowScopeKind) switch
    {
      (PermissionScopeKind.Tenant, PermissionScopeKind.Tenant) => userRule.ScopeId == rowScopeId,
      (PermissionScopeKind.Tenant, _) => rowOwningTenantId.HasValue && userRule.ScopeId == rowOwningTenantId.Value,
      (PermissionScopeKind.DeviceGroup, PermissionScopeKind.DeviceGroup) => userRule.ScopeId == rowScopeId,
      (PermissionScopeKind.CustomerTenant, PermissionScopeKind.CustomerTenant) => userRule.ScopeId == rowScopeId,
      (PermissionScopeKind.Device, PermissionScopeKind.Device) => userRule.ScopeId == rowScopeId,
      _ => false
    };
  }

  /// <summary>
  /// Whether the assignment's scope covers the requested resource (Server covers all,
  /// Tenant covers within tenant, DeviceGroup/CustomerTenant cover their devices, Device itself).
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

    // DeviceGroup/CustomerTenant-scoped assignments also cover devices in that group/customer.
    if (assignment.ScopeKind == PermissionScopeKind.DeviceGroup &&
        resource.Kind == PermissionScopeKind.Device)
    {
      return assignment.ScopeId.HasValue &&
             resource.DeviceGroupIds is not null &&
             resource.DeviceGroupIds.Contains(assignment.ScopeId.Value);
    }

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

  /// <summary>
  /// Determines whether a credential scope row is covered by the owning user's rules with
  /// deny-overrides-allow semantics: at least one user allow must cover the row's scope and
  /// no user deny may cover it.
  /// </summary>
  private static bool UserRulesCoverScope(List<PermissionRule> userRules, PermissionAssignment row)
  {
    var coveringRules = userRules
      .Where(r => r.Assignment.PermissionName == row.PermissionName &&
                  RuleCoversScope(r.Assignment, row.ScopeKind, row.ScopeId, row.OwningTenantId))
      .ToList();

    return coveringRules.Any(r => r.Assignment.Effect == PermissionEffect.Allow) &&
           !coveringRules.Any(r => r.Assignment.Effect == PermissionEffect.Deny);
  }

  /// <summary>
  /// Lightweight snapshot of a device's identity and group memberships,
  /// loaded in batch to avoid N+1 queries.
  /// </summary>
  private record DeviceInfo(Guid Id, Guid? TenantId, Guid? CustomerId, IReadOnlyList<Guid> GroupIds);
}
