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

    // Logon token device-scope enforcement. A logon token session is always restricted
    // to the device it was created for. This is a hard security boundary that applies
    // regardless of scope rows.
    if (principal.CredentialType == CredentialType.LogonToken)
    {
      if (!principal.DeviceScopeId.HasValue)
      {
        return PermissionEvaluationResult.Deny("Logon token principal is missing required device scope.");
      }

      // A logon token without a credential id cannot resolve its grant rows; fail closed
      // rather than falling through to the recipient user's rules. This keeps the grant
      // model keyed on the same condition as this boundary.
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
        // Explicit PAT scopes are an optional restriction: a PAT can never exceed its owning
        // user's effective rights. Each scope row survives only when the user's own rules
        // cover it: device-scoped rows are checked precisely against the target device
        // (loading its group/customer membership), other rows via scope coverage rules. In
        // both cases a matching user deny discards the row.
        var boundedAssignments = new List<PermissionAssignment>();
        foreach (var row in credentialAssignments)
        {
          var covered = row.ScopeKind == PermissionScopeKind.Device && row.ScopeId.HasValue
            ? await UserRulesCoverDeviceScope(rules, row, cancellationToken)
            : UserRulesCoverScope(rules, row);

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
  /// Returns the set of permission names the principal effectively holds (allow rules not
  /// overridden by deny), evaluated at the name level without regard to resource scope.
  /// This is the *user's* set: credential-scoping (PAT scope rows, logon-token device
  /// grants) and the server-service-account bypass do not apply. Consumers are interactive
  /// or system paths that act as the user proper — claim emission for client-side policy
  /// evaluation (<c>IdentityRevalidatingAuthenticationStateProvider</c>), hub topic
  /// subscription (<c>ViewerHub.JoinServerTopics</c>), the server-admin guard in
  /// <c>PermissionAssignmentManager</c>, and the caller-permission check in
  /// <c>UsersController</c>. Do not use this to decide what a credential (PAT/logon token)
  /// may do; use <see cref="Evaluate"/> for those paths. Assignment rows are interpreted
  /// by <see cref="IPermissionRuleResolver"/> (direct and user-group).
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
  /// explicit deny overrides allow; otherwise any matching allow permits; otherwise default
  /// deny. Used both by the main evaluation path and by PAT scope bounding.
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
  /// Determines whether a user rule's scope covers a credential scope row. Server grants cover
  /// every row scope; only server grants cover server-scoped rows. Tenant grants cover rows
  /// scoped to the same tenant and rows owned by that tenant in narrower categories (a row's
  /// owning tenant is recorded on the row at write time, so membership within the tenant is
  /// not re-resolved here; rows without an owning tenant are not covered — fail-closed).
  /// Group, customer, and device grants cover only rows scoped to the same group, customer,
  /// or device, so rows a user reaches only through membership are not covered (fail-closed).
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
                  RuleCoversScope(r.Assignment, row.ScopeKind, row.ScopeId, row.OwningTenantId))
      .ToList();

    return coveringRules.Any(r => r.Assignment.Effect == PermissionEffect.Allow) &&
           !coveringRules.Any(r => r.Assignment.Effect == PermissionEffect.Deny);
  }

  /// <summary>
  /// Determines precisely whether the owning user's rules cover a device-scoped credential
  /// row by resolving the target device's tenant, customer, and group memberships and
  /// running the standard match/deny resolution against the user's rules. A missing device
  /// fails closed.
  /// </summary>
  private async Task<bool> UserRulesCoverDeviceScope(
    List<PermissionRule> userRules,
    PermissionAssignment row,
    CancellationToken cancellationToken)
  {
    await using var db = await _dbContextFactory.CreateDbContextAsync(cancellationToken);

    var device = await db.Devices
      .IgnoreQueryFilters()
      .AsNoTracking()
      .FirstOrDefaultAsync(x => x.Id == row.ScopeId, cancellationToken);
      
    if (device is null)
    {
      return false;
    }

    var groupIds = await db.DeviceGroupMembers
      .IgnoreQueryFilters()
      .AsNoTracking()
      .Where(member => member.DeviceId == device.Id)
      .Select(member => member.DeviceGroupId)
      .ToListAsync(cancellationToken);

    var resource = new ResourceDescriptor(
      PermissionScopeKind.Device, device.Id, device.TenantId, device.CustomerId, groupIds);

    return ResolveMatchingRules(userRules, row.PermissionName, resource).Allowed;
  }
}
