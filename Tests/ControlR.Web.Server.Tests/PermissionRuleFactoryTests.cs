using ControlR.Libraries.Api.Contracts.Enums;
using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Data.Entities;
using ControlR.Web.Server.Services.Authorization.PermissionRules;

namespace ControlR.Web.Server.Tests;

public class PermissionRuleFactoryTests
{
  [Fact]
  public void CreateDirectRules_FiltersEnabledAndTenantOwned()
  {
    var tenantId = Guid.NewGuid();
    var otherTenant = Guid.NewGuid();
    var assignments = new[]
    {
      CreateAssignment(tenantId),
      CreateAssignment(null),
      CreateAssignment(otherTenant),
      CreateAssignment(tenantId, isEnabled: false)
    };

    var rules = PermissionRuleFactory.CreateDirectRules(assignments, tenantId);

    Assert.Equal(2, rules.Count);
    Assert.All(rules, rule => Assert.Equal(RuleSource.Direct, rule.Source));
    Assert.All(rules, rule => Assert.Equal(SourcePriority.Direct, rule.Priority));
  }

  [Fact]
  public void CreateGroupRules_UsesUserGroupSourceAndPriority()
  {
    var tenantId = Guid.NewGuid();
    var assignments = new[] { CreateAssignment(tenantId) };

    var rules = PermissionRuleFactory.CreateGroupRules(assignments, tenantId);

    var rule = Assert.Single(rules);
    Assert.Equal(RuleSource.UserGroup, rule.Source);
    Assert.Equal(SourcePriority.UserGroup, rule.Priority);
  }

  private static PermissionAssignment CreateAssignment(
    Guid? owningTenantId,
    bool isEnabled = true) =>
    PermissionAssignment.CreateGrant(
      PermissionPrincipalKind.User,
      Guid.NewGuid(),
      PermissionNames.DeviceRead,
      PermissionScopeKind.Tenant,
      Guid.NewGuid(),
      owningTenantId,
      "test",
      Guid.NewGuid().ToString(),
      isEnabled: isEnabled);
}
