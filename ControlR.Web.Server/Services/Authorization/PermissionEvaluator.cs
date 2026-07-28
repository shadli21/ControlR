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

      var credentialAssignments = await _ruleResolver.LoadAssignments(
        credentialKind, principal.CredentialId.Value, cancellationToken);

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
          rules.Add(new PermissionRule(assignment, source, priority));
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
}
