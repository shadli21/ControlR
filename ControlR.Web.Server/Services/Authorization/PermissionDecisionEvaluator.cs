using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Services.Authorization.PermissionRules;

namespace ControlR.Web.Server.Services.Authorization;

public interface IPermissionDecisionEvaluator
{
  PermissionEvaluationResult Evaluate(
    PermissionEvaluationContext context,
    string permissionName,
    ResourceDescriptor resource);

  PermissionEvaluationResult EvaluateRules(
    IReadOnlyList<PermissionRule> rules,
    string permissionName,
    ResourceDescriptor resource);
}

public sealed class PermissionDecisionEvaluator : IPermissionDecisionEvaluator
{
  public PermissionEvaluationResult Evaluate(
    PermissionEvaluationContext context,
    string permissionName,
    ResourceDescriptor resource)
  {
    if (!PermissionCatalog.Exists(permissionName))
    {
      return PermissionEvaluationResult.Deny($"Unknown permission '{permissionName}'.");
    }

    if (context.ServerBypass)
    {
      return PermissionEvaluationResult.Allow("server-service-account-bypass", "Server");
    }

    var principal = context.Principal;
    if (principal.CredentialType == CredentialType.LogonToken)
    {
      if (!principal.DeviceScopeId.HasValue)
      {
        return PermissionEvaluationResult.Deny("Logon token principal is missing required device scope.");
      }

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

      if (context.EffectiveRules.Count == 0)
      {
        return PermissionEvaluationResult.Deny("Logon token grants do not match the device scope.");
      }
    }

    if (context.HasExplicitPatScope)
    {
      var ownerDecision = EvaluateRules(context.OwnerRules, permissionName, resource);
      if (!ownerDecision.Allowed)
      {
        return PermissionEvaluationResult.Deny(
          "Credential scope grants are outside the user's effective permissions.");
      }

      return EvaluateRules(context.EffectiveRules, permissionName, resource);
    }

    return EvaluateRules(context.EffectiveRules, permissionName, resource);
  }

  public PermissionEvaluationResult EvaluateRules(
    IReadOnlyList<PermissionRule> rules,
    string permissionName,
    ResourceDescriptor resource)
  {
    if (!PermissionCatalog.Exists(permissionName))
    {
      return PermissionEvaluationResult.Deny($"Unknown permission '{permissionName}'.");
    }

    var matchingRules = rules
      .Where(rule => rule.PermissionName == permissionName &&
                     PermissionScopeMatcher.Matches(rule, resource))
      .ToList();

    if (matchingRules.Count == 0)
    {
      return PermissionEvaluationResult.Deny("No matching permission assignment found (default deny).");
    }

    var denyRule = matchingRules
      .Where(rule => rule.Effect == PermissionEffect.Deny)
      .OrderBy(rule => rule.Priority)
      .ThenBy(rule => ScopeSpecificity(rule.ScopeKind))
      .FirstOrDefault();

    if (denyRule is not null)
    {
      return PermissionEvaluationResult.Deny(
        $"Explicit deny from {denyRule.Source} at scope {denyRule.ScopeKind}.");
    }

    var allowRule = matchingRules
      .Where(rule => rule.Effect == PermissionEffect.Allow)
      .OrderBy(rule => rule.Priority)
      .ThenBy(rule => ScopeSpecificity(rule.ScopeKind))
      .FirstOrDefault();

    return allowRule is null
      ? PermissionEvaluationResult.Deny("No matching allow rule found (default deny).")
      : PermissionEvaluationResult.Allow(
          allowRule.Source.ToString(), allowRule.ScopeKind.ToString());
  }

  private static int ScopeSpecificity(PermissionScopeKind scopeKind) => scopeKind switch
  {
    PermissionScopeKind.Device => 0,
    PermissionScopeKind.DeviceGroup => 1,
    PermissionScopeKind.CustomerTenant => 2,
    PermissionScopeKind.UserGroup => 3,
    PermissionScopeKind.Tenant => 4,
    PermissionScopeKind.Server => 5,
    _ => 6
  };
}
