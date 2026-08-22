namespace ControlR.Web.Server.Services.Authorization.PermissionRules;

public sealed record PermissionRule(
  string PermissionName,
  PermissionEffect Effect,
  PermissionScopeKind ScopeKind,
  Guid? ScopeId,
  Guid? OwningTenantId,
  RuleSource Source,
  SourcePriority Priority)
{
  public static PermissionRule Create(
    PermissionAssignment assignment,
    RuleSource source,
    SourcePriority priority) =>
    new(
      assignment.PermissionName,
      assignment.Effect,
      assignment.ScopeKind,
      assignment.ScopeId,
      assignment.OwningTenantId,
      source,
      priority);
}
