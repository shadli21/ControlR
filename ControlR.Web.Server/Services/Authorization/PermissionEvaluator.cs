using ControlR.Web.Server.Authz.Permissions;

namespace ControlR.Web.Server.Services.Authorization;

public interface IPermissionEvaluator
{
  Task<PermissionEvaluationResult> Evaluate(
    PrincipalDescriptor principal,
    string permissionName,
    ResourceDescriptor resource,
    CancellationToken cancellationToken);
  Task<IReadOnlyList<PermissionEvaluationResult>> EvaluateBatch(
    PrincipalDescriptor principal,
    IReadOnlyList<PermissionEvaluationRequest> requests,
    CancellationToken cancellationToken);
  Task<IReadOnlyDictionary<string, PermissionEvaluationResult>> EvaluateMany(
    PrincipalDescriptor principal,
    IReadOnlyCollection<string> permissionNames,
    ResourceDescriptor resource,
    CancellationToken cancellationToken);
  Task<IReadOnlySet<string>> GetPermissionHints(
    PrincipalDescriptor principal,
    CancellationToken cancellationToken);
}

public sealed class PermissionEvaluator(
  IPermissionEvaluationContextLoader contextLoader,
  IPermissionDecisionEvaluator decisionEvaluator) : IPermissionEvaluator
{
  private readonly IPermissionEvaluationContextLoader _contextLoader = contextLoader;
  private readonly IPermissionDecisionEvaluator _decisionEvaluator = decisionEvaluator;

  public async Task<PermissionEvaluationResult> Evaluate(
    PrincipalDescriptor principal,
    string permissionName,
    ResourceDescriptor resource,
    CancellationToken cancellationToken)
  {
    var context = await _contextLoader.Load(principal, cancellationToken);
    return _decisionEvaluator.Evaluate(context, permissionName, resource);
  }

  public async Task<IReadOnlyList<PermissionEvaluationResult>> EvaluateBatch(
    PrincipalDescriptor principal,
    IReadOnlyList<PermissionEvaluationRequest> requests,
    CancellationToken cancellationToken)
  {
    if (requests.Count == 0)
    {
      return [];
    }

    var context = await _contextLoader.Load(principal, cancellationToken);
    return [.. requests.Select(request =>
      _decisionEvaluator.Evaluate(context, request.PermissionName, request.Resource))];
  }

  public async Task<IReadOnlyDictionary<string, PermissionEvaluationResult>> EvaluateMany(
    PrincipalDescriptor principal,
    IReadOnlyCollection<string> permissionNames,
    ResourceDescriptor resource,
    CancellationToken cancellationToken)
  {
    if (permissionNames.Count == 0)
    {
      return new Dictionary<string, PermissionEvaluationResult>();
    }

    var context = await _contextLoader.Load(principal, cancellationToken);
    return permissionNames
      .Distinct(StringComparer.Ordinal)
      .ToDictionary(
        permissionName => permissionName,
        permissionName => _decisionEvaluator.Evaluate(context, permissionName, resource),
        StringComparer.Ordinal);
  }

  public async Task<IReadOnlySet<string>> GetPermissionHints(
    PrincipalDescriptor principal,
    CancellationToken cancellationToken)
  {
    var context = await _contextLoader.Load(principal, cancellationToken);
    if (context.ServerBypass)
    {
      return PermissionCatalog.All.Keys.ToHashSet(StringComparer.Ordinal);
    }

    var hints = new HashSet<string>(StringComparer.Ordinal);
    foreach (var group in context.EffectiveRules.GroupBy(rule => rule.PermissionName))
    {
      if (group.Any(rule => rule.Effect == PermissionEffect.Deny))
      {
        continue;
      }

      if (group.Any(rule => rule.Effect == PermissionEffect.Allow) &&
          PermissionCatalog.Exists(group.Key))
      {
        hints.Add(group.Key);
      }
    }

    return hints;
  }
}
          // Load device details in a single query.
