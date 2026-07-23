namespace ControlR.Web.Server.Authz.Permissions;

public sealed record PermissionEvaluationResult(
  bool Allowed,
  string? MatchedRuleSource = null,
  string? MatchedScope = null,
  string? DenialReason = null)
{
  public static PermissionEvaluationResult Allow(string ruleSource, string scope) =>
    new(true, ruleSource, scope);

  public static PermissionEvaluationResult Deny(string reason) =>
    new(false, DenialReason: reason);
}
