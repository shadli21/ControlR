namespace ControlR.Web.Server.Services.Authorization.PermissionRules;

/// <summary>
/// Builds <see cref="PermissionRule"/> instances from <see cref="PermissionAssignment"/> rows,
/// applying the shared enabled-row and tenant-ownership filtering used by both the evaluation
/// context loader and the self-protection path so the two cannot drift apart.
/// </summary>
public static class PermissionRuleFactory
{
  public static IReadOnlyList<PermissionRule> CreateDirectRules(
    IEnumerable<PermissionAssignment> assignments,
    Guid? tenantId) =>
    [.. assignments
      .Where(assignment => IsOwnedByPrincipalTenant(assignment, tenantId))
      .Select(assignment => PermissionRule.Create(
        assignment, RuleSource.Direct, SourcePriority.Direct))];

  public static IReadOnlyList<PermissionRule> CreateGroupRules(
    IEnumerable<PermissionAssignment> assignments,
    Guid? tenantId) =>
    [.. assignments
      .Where(assignment => IsOwnedByPrincipalTenant(assignment, tenantId))
      .Select(assignment => PermissionRule.Create(
        assignment, RuleSource.UserGroup, SourcePriority.UserGroup))];

  private static bool IsOwnedByPrincipalTenant(
    PermissionAssignment assignment,
    Guid? tenantId) =>
    assignment.IsEnabled &&
    (tenantId is null ||
     assignment.OwningTenantId is null ||
     assignment.OwningTenantId == tenantId);
}
