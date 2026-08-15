namespace ControlR.Web.Server.Services.Authorization.PermissionRules;

public sealed record PermissionRule(
  PermissionAssignment Assignment,
  RuleSource Source,
  SourcePriority Priority);
