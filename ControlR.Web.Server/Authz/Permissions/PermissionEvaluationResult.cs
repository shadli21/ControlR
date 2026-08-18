using System.Diagnostics.CodeAnalysis;

namespace ControlR.Web.Server.Authz.Permissions;

/// <summary>
/// The result of a permission evaluation. Instances can only be created through the
/// <see cref="Allow"/> and <see cref="Deny"/> factories, which guarantee the invariant that
/// allowed results carry a rule source/scope and denied results carry a denial reason.
/// </summary>
public sealed class PermissionEvaluationResult
{
  private PermissionEvaluationResult(
    bool allowed,
    string? matchedRuleSource,
    string? matchedScope,
    string? denialReason)
  {
    Allowed = allowed;
    MatchedRuleSource = matchedRuleSource;
    MatchedScope = matchedScope;
    DenialReason = denialReason;
  }

  [MemberNotNullWhen(true, nameof(MatchedRuleSource))]
  [MemberNotNullWhen(true, nameof(MatchedScope))]
  [MemberNotNullWhen(false, nameof(DenialReason))]
  public bool Allowed { get; }
  public string? DenialReason { get; }
  public string? MatchedRuleSource { get; }
  public string? MatchedScope { get; }

  public static PermissionEvaluationResult Allow(string ruleSource, string scope) =>
    new(true, ruleSource, scope, null);

  public static PermissionEvaluationResult Deny(string reason) =>
    new(false, null, null, reason);
}
