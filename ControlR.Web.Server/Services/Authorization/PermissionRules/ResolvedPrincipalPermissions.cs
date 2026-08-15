namespace ControlR.Web.Server.Services.Authorization.PermissionRules;

/// <summary>
/// The result of interpreting a principal's permission assignments. <see cref="ServerBypass"/>
/// is true for a server-scoped service account that has no explicit assignments (the zero-config
/// RMM use case); such a principal is unrestricted. Otherwise <see cref="Rules"/> holds the
/// assembled allow/deny rules (direct and user-group).
/// </summary>
public sealed record ResolvedPrincipalPermissions(
  bool ServerBypass,
  IReadOnlyList<PermissionRule> Rules)
{
  public static ResolvedPrincipalPermissions Bypass() => new(true, []);

  public static ResolvedPrincipalPermissions Scoped(IReadOnlyList<PermissionRule> rules) => new(false, rules);

  /// <summary>
  /// Projects the resolved rules to the set of permission names the principal effectively
  /// holds at the name level, honoring deny-overrides-allow: a name with any deny rule is
  /// excluded even if allows also exist.
  /// </summary>
  public IReadOnlySet<string> GetEffectivePermissionNames()
  {
    var effective = new HashSet<string>();
    foreach (var group in Rules.GroupBy(rule => rule.Assignment.PermissionName))
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
}
