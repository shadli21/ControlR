using ControlR.Web.Server.Services.Authorization;

namespace ControlR.Web.Server.Authz.Permissions;

/// <summary>
/// Authorization handler that bridges ASP.NET Core policy/resource authorization to the
/// centralized <see cref="IPermissionEvaluator"/>. Builds a <see cref="PrincipalDescriptor"/>
/// from the authenticated principal's claims, resolves the resource descriptor, and
/// delegates the allow/deny decision to the evaluator.
/// </summary>
public class PermissionRequirementHandler(
  IPermissionEvaluator evaluator,
  IResourceDescriptorFactory resourceFactory,
  IHttpContextAccessor httpContextAccessor,
  ILogger<PermissionRequirementHandler> logger)
  : AuthorizationHandler<PermissionRequirement, object>
{
  private readonly IPermissionEvaluator _evaluator = evaluator;
  private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor;
  private readonly ILogger<PermissionRequirementHandler> _logger = logger;
  private readonly IResourceDescriptorFactory _resourceFactory = resourceFactory;

  protected override async Task HandleRequirementAsync(
    AuthorizationHandlerContext context,
    PermissionRequirement requirement,
    object resource)
  {
    var principal = PrincipalDescriptorBuilder.FromClaims(context.User);
    if (principal is null)
    {
      _logger.LogWarning("Cannot build principal descriptor from claims. Denying {Permission}.", requirement.PermissionName);
      context.Fail(new AuthorizationFailureReason(this, "Missing required principal claims."));
      return;
    }

    var cancellationToken = _httpContextAccessor.HttpContext?.RequestAborted ?? CancellationToken.None;

    var resourceDescriptor = await ResolveResource(requirement.Resource, resource, principal, cancellationToken);

    var result = await _evaluator.Evaluate(
      principal, requirement.PermissionName, resourceDescriptor, cancellationToken);

    if (result.Allowed)
    {
      context.Succeed(requirement);
      return;
    }

    _logger.LogDebug(
      "Permission denied: {Permission} on {Resource} for principal {PrincipalId}. Reason: {Reason}",
      requirement.PermissionName, resourceDescriptor, principal.PrincipalId, result.DenialReason);
    context.Fail(new AuthorizationFailureReason(this, result.DenialReason ?? "Permission denied."));
  }

  private async Task<ResourceDescriptor> ResolveResource(
    ResourceDescriptor requirementResource,
    object resource,
    PrincipalDescriptor principal,
    CancellationToken cancellationToken)
  {
    if (resource is Device device)
    {
      return await _resourceFactory.CreateDevice(device, cancellationToken);
    }

    if (requirementResource.Kind == PermissionScopeKind.Tenant &&
        requirementResource.TenantId is null &&
        principal.TenantId.HasValue)
    {
      return _resourceFactory.CreateTenant(principal.TenantId.Value);
    }

    return requirementResource;
  }
}
