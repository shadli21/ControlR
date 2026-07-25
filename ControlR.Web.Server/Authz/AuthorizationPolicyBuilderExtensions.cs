using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Data.Enums;

namespace ControlR.Web.Server.Authz;

public static class AuthorizationPolicyBuilderExtensions
{
  /// <summary>
  /// Adds a <see cref="PermissionRequirement"/> to the policy. The requirement delegates
  /// to the centralized permission evaluator at authorization time.
  /// </summary>
  public static AuthorizationPolicyBuilder RequirePermission(
    this AuthorizationPolicyBuilder builder,
    string permissionName,
    PermissionScopeKind scopeKind = PermissionScopeKind.Tenant)
  {
    builder.Requirements.Add(new PermissionRequirement(
      permissionName, new ResourceDescriptor(scopeKind)));
    return builder;
  }

  public static AuthorizationPolicyBuilder RequireServiceProviderAssertion(
    this AuthorizationPolicyBuilder builder,
    Func<IServiceProvider, AuthorizationHandlerContext, IAuthorizationHandler, Task<bool>> assertion)
  {
    builder.Requirements.Add(new ServiceProviderAsyncRequirement(assertion));
    return builder;
  }

  public static AuthorizationPolicyBuilder RequireServiceProviderAssertion(
    this AuthorizationPolicyBuilder builder,
    Func<IServiceProvider, AuthorizationHandlerContext, IAuthorizationHandler, bool> assertion)
  {
    builder.Requirements.Add(new ServiceProviderRequirement(assertion));
    return builder;
  }
}