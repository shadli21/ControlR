using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Services.Authorization.PermissionRules;

namespace ControlR.Web.Server.Services.Authorization;

public sealed record PermissionEvaluationContext(
  PrincipalDescriptor Principal,
  bool ServerBypass,
  IReadOnlyList<PermissionRule> OwnerRules,
  IReadOnlyList<PermissionRule> EffectiveRules,
  bool HasExplicitPatScope)
{
  public static PermissionEvaluationContext Bypass(PrincipalDescriptor principal) =>
    new(principal, true, [], [], false);
}
