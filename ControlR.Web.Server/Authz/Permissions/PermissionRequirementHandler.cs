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
  IDbContextFactory<AppDb> dbContextFactory,
  ILogger<PermissionRequirementHandler> logger)
  : AuthorizationHandler<PermissionRequirement, object>
{
  private readonly IDbContextFactory<AppDb> _dbContextFactory = dbContextFactory;
  private readonly IPermissionEvaluator _evaluator = evaluator;
  private readonly ILogger<PermissionRequirementHandler> _logger = logger;

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

    var resourceDescriptor = await ResolveResource(requirement.Resource, resource, principal, CancellationToken.None);

    var result = await _evaluator.Evaluate(
      principal, requirement.PermissionName, resourceDescriptor, CancellationToken.None);

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

  private async Task<IReadOnlyCollection<Guid>> ResolveDeviceGroupIds(
    Device device,
    CancellationToken cancellationToken)
  {
    if (device.DeviceGroupMembers is not null)
    {
      return [.. device.DeviceGroupMembers.Select(member => member.DeviceGroupId)];
    }

    await using var db = await _dbContextFactory.CreateDbContextAsync(cancellationToken);
    return await db.DeviceGroupMembers
      .IgnoreQueryFilters()
      .AsNoTracking()
      .Where(member => member.DeviceId == device.Id)
      .Select(member => member.DeviceGroupId)
      .ToListAsync(cancellationToken);
  }

  private async Task<ResourceDescriptor> ResolveResource(
    ResourceDescriptor requirementResource,
    object resource,
    PrincipalDescriptor principal,
    CancellationToken cancellationToken)
  {
    if (resource is Device device)
    {
      var deviceGroupIds = await ResolveDeviceGroupIds(device, cancellationToken);
      return new ResourceDescriptor(
        PermissionScopeKind.Device, device.Id, device.TenantId, device.CustomerId, deviceGroupIds);
    }

    if (requirementResource.TenantId is null && principal.TenantId.HasValue)
    {
      return requirementResource with { TenantId = principal.TenantId.Value };
    }

    return requirementResource;
  }
}
