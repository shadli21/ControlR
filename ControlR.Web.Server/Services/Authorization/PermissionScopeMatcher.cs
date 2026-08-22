using ControlR.Web.Server.Authz.Permissions;

namespace ControlR.Web.Server.Services.Authorization;

public static class PermissionScopeMatcher
{
  public static bool Matches(PermissionRules.PermissionRule rule, ResourceDescriptor resource)
  {
    if (rule.ScopeKind == PermissionScopeKind.Server)
    {
      return true;
    }

    if (rule.ScopeKind == PermissionScopeKind.Tenant)
    {
      return resource.TenantId.HasValue && rule.ScopeId == resource.TenantId.Value;
    }

    if (rule.ScopeKind == resource.Kind)
    {
      return rule.ScopeId == resource.Id;
    }

    if (rule.ScopeKind == PermissionScopeKind.DeviceGroup &&
        resource.Kind == PermissionScopeKind.Device)
    {
      return rule.ScopeId.HasValue &&
             resource.DeviceGroupIds is not null &&
             resource.DeviceGroupIds.Contains(rule.ScopeId.Value);
    }

    if (rule.ScopeKind == PermissionScopeKind.CustomerTenant &&
        resource.Kind == PermissionScopeKind.Device)
    {
      return resource.CustomerId.HasValue && rule.ScopeId == resource.CustomerId.Value;
    }

    return false;
  }
}
