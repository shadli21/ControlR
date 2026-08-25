using System.Diagnostics.CodeAnalysis;

namespace ControlR.Web.Server.Authz.Permissions;

/// <summary>
/// Result of a permission evaluation. Create via <see cref="Allow"/> or <see cref="Deny"/>.
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
