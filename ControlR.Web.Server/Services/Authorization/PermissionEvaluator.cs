using ControlR.Web.Server.Authn;
using ControlR.Web.Server.Authz.Permissions;

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

public class PermissionEvaluator(IPermissionRuleResolver ruleResolver) : IPermissionEvaluator
{
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

    // Logon token device-scope enforcement. A logon token session is always restricted
    // to the device it was created for. This is a hard security boundary that applies
    // regardless of scope rows.
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

    // Credential-scoped principals. PATs and logon tokens have fundamentally
    // different authorization models:
    //   - A PAT authenticates as its owning user. With no explicit scope rows it inherits
    //     the user's full effective permissions (user-equivalent). Explicit scope rows are
    //     an optional least-privilege restriction, bounded by the user's permissions.
    //   - A logon token is a self-contained device grant issued to a recipient who may have
    //     no permissions of their own (e.g., an external user). Its grants are authoritative
    //     and device-bound, never inherited from or bounded by the recipient.
    if (principal.IsCredentialScoped && principal.CredentialId.HasValue)
    {
      var isLogonToken = principal.CredentialType == PrincipalClaimTypes.LogonTokenCredentialType;
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
        // Explicit PAT scopes are an optional restriction: a PAT can never exceed its owning
        // user's effective rights. Each scope row survives only when the user's own rules
        // cover the row's scope with an allow and no matching deny. Coverage is evaluated
        // without device group/customer membership knowledge, so user allows that reach a
        // resource only through group or customer membership do not cover rows scoped to
        // that resource (fail-closed).
        var boundedAssignments = credentialAssignments
          .Where(a => UserRulesCoverScope(rules, a))
          .ToList();

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

    // Filter to rules matching the requested permission and resource scope.
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

    // If any matching allow exists, allow.
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

    // Default deny.
    return PermissionEvaluationResult.Deny("No matching allow rule found (default deny).");
  }

  /// <summary>
  /// Returns the set of permission names the principal effectively holds (allow rules not
  /// overridden by deny), evaluated at the name level without regard to resource scope. Used
  /// to emit permission claims for client-side policy evaluation. Assignment rows are interpreted
  /// by <see cref="IPermissionRuleResolver"/> (direct, user-group, and the interim role-bundle
  /// bridge). Credential-scoping and the server-service-account bypass do not apply to interactive
  /// UI sessions, which are the only consumers of this method.
  /// </summary>
  public async Task<IReadOnlySet<string>> GetEffectivePermissionNames(
    PrincipalDescriptor principal,
    CancellationToken cancellationToken)
  {
    var resolved = await _ruleResolver.Resolve(principal, cancellationToken);

    var effective = new HashSet<string>();
    foreach (var group in resolved.Rules.GroupBy(rule => rule.Assignment.PermissionName))
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
  /// Determines whether a user rule's scope covers a credential scope row. Server grants cover
  /// every row scope; only server grants cover server-scoped rows. Tenant grants cover rows
  /// scoped to the same tenant and rows scoped to narrower categories within it (device,
  /// group, and customer membership within the tenant is not knowable at bounding time).
  /// Group, customer, and device grants cover only rows scoped to the same group, customer,
  /// or device, so rows a user reaches only through membership are not covered (fail-closed).
  /// </summary>
  private static bool RuleCoversScope(
    PermissionAssignment userRule,
    PermissionScopeKind rowScopeKind,
    Guid? rowScopeId)
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
      (PermissionScopeKind.Tenant, _) => true,
      (PermissionScopeKind.DeviceGroup, PermissionScopeKind.DeviceGroup) => userRule.ScopeId == rowScopeId,
      (PermissionScopeKind.CustomerTenant, PermissionScopeKind.CustomerTenant) => userRule.ScopeId == rowScopeId,
      (PermissionScopeKind.Device, PermissionScopeKind.Device) => userRule.ScopeId == rowScopeId,
      _ => false
    };
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

    // A DeviceGroup-scoped assignment covers individual devices that belong to that group.
    // Membership is checked precisely here via the device's group IDs (carried on the resource
    // descriptor), mirroring the CustomerTenant check, so no deferred validation is needed.
    if (assignment.ScopeKind == PermissionScopeKind.DeviceGroup &&
        resource.Kind == PermissionScopeKind.Device)
    {
      return assignment.ScopeId.HasValue &&
             resource.DeviceGroupIds is not null &&
             resource.DeviceGroupIds.Contains(assignment.ScopeId.Value);
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

  /// <summary>
  /// Determines whether a credential scope row is covered by the owning user's rules with
  /// deny-overrides-allow semantics: at least one user allow must cover the row's scope and
  /// no user deny may cover it.
  /// </summary>
  private static bool UserRulesCoverScope(List<PermissionRule> userRules, PermissionAssignment row)
  {
    var coveringRules = userRules
      .Where(r => r.Assignment.PermissionName == row.PermissionName &&
                  RuleCoversScope(r.Assignment, row.ScopeKind, row.ScopeId))
      .ToList();

    return coveringRules.Any(r => r.Assignment.Effect == PermissionEffect.Allow) &&
           !coveringRules.Any(r => r.Assignment.Effect == PermissionEffect.Deny);
  }
}
