using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Data.Enums;
using ControlR.Web.Server.Primitives;
using ControlR.Web.Server.Services.Authorization;

namespace ControlR.Web.Server.Services.PermissionAssignments;

/// <summary>
/// Manages permission assignments: CRUD with validation, cleanup on principal/resource
/// deletion, and effective permission queries. All writes emit AuthorizationChangeLog entries.
/// </summary>
public interface IPermissionAssignmentManager
{
  Task<HttpResult<InternalDtos.PermissionAssignmentDto>> Create(
    InternalDtos.CreatePermissionAssignmentRequestDto request,
    Guid tenantId,
    Guid actorPrincipalId,
    CancellationToken cancellationToken = default);

  Task<HttpResult> Delete(
    Guid assignmentId,
    Guid tenantId,
    Guid actorPrincipalId,
    CancellationToken cancellationToken = default);

  Task<IReadOnlyList<InternalDtos.PermissionAssignmentDto>> GetByPrincipal(
    PermissionPrincipalKind principalKind,
    Guid principalId,
    Guid tenantId,
    CancellationToken cancellationToken = default);

  Task<InternalDtos.EffectivePermissionQueryResponseDto> QueryEffectivePermission(
    InternalDtos.EffectivePermissionQueryRequestDto request,
    Guid tenantId,
    CancellationToken cancellationToken = default);
}

public class PermissionAssignmentManager(
  AppDb appDb,
  IPermissionEvaluator permissionEvaluator) : IPermissionAssignmentManager
{
  private readonly AppDb _appDb = appDb;
  private readonly IPermissionEvaluator _permissionEvaluator = permissionEvaluator;

  public async Task<HttpResult<InternalDtos.PermissionAssignmentDto>> Create(
    InternalDtos.CreatePermissionAssignmentRequestDto request,
    Guid tenantId,
    Guid actorPrincipalId,
    CancellationToken cancellationToken = default)
  {
    var principalExists = await ValidatePrincipalExists(request.PrincipalKind, request.PrincipalId, tenantId, cancellationToken);
    if (!principalExists)
    {
      return HttpResult.Fail<InternalDtos.PermissionAssignmentDto>(
        HttpResultErrorCode.BadRequest, $"Principal not found: {request.PrincipalKind}/{request.PrincipalId}");
    }

    if (!PermissionCatalog.Exists(request.PermissionName))
    {
      return HttpResult.Fail<InternalDtos.PermissionAssignmentDto>(
        HttpResultErrorCode.BadRequest, $"Unknown permission name: {request.PermissionName}");
    }

    if (request.ScopeKind is PermissionScopeKind.Device or PermissionScopeKind.DeviceGroup && !request.ScopeId.HasValue)
    {
      return HttpResult.Fail<InternalDtos.PermissionAssignmentDto>(
        HttpResultErrorCode.BadRequest, $"ScopeId is required for scope kind: {request.ScopeKind}");
    }

    var assignment = new PermissionAssignment
    {
      PrincipalKind = request.PrincipalKind,
      PrincipalId = request.PrincipalId,
      PermissionName = request.PermissionName,
      Effect = request.Effect,
      ScopeKind = request.ScopeKind,
      ScopeId = request.ScopeId,
      Notes = request.Notes,
      IsEnabled = true,
      OwningTenantId = request.ScopeKind == PermissionScopeKind.Server ? null : tenantId,
      CreatedByPrincipalType = AuthorizationChangeLogActorTypes.User,
      CreatedByPrincipalId = actorPrincipalId.ToString()
    };

    _appDb.PermissionAssignments.Add(assignment);

    _appDb.AuthorizationChangeLogs.Add(AuthorizationChangeLogEntry.Create(
      AuthorizationChangeLogActions.PermissionAssignmentCreated,
      AuthorizationChangeLogActorTypes.User,
      actorPrincipalId.ToString(),
      AuthorizationChangeLogTargetTypes.PermissionAssignment,
      assignment.Id.ToString(),
      tenantId,
      after: new PermissionAssignmentSnapshot(
        request.PermissionName, request.Effect.ToString(), request.ScopeKind.ToString(), request.ScopeId)));

    await _appDb.SaveChangesAsync(cancellationToken);

    return HttpResult.Ok(MapToDto(assignment));
  }

  public async Task<HttpResult> Delete(
    Guid assignmentId,
    Guid tenantId,
    Guid actorPrincipalId,
    CancellationToken cancellationToken = default)
  {
    var assignment = await _appDb.PermissionAssignments
      .IgnoreQueryFilters()
      .FirstOrDefaultAsync(x => x.Id == assignmentId, cancellationToken);

    if (assignment is null)
    {
      return HttpResult.Fail(HttpResultErrorCode.NotFound, "Permission assignment not found.");
    }

    _appDb.AuthorizationChangeLogs.Add(AuthorizationChangeLogEntry.Create(
      AuthorizationChangeLogActions.PermissionAssignmentDeleted,
      AuthorizationChangeLogActorTypes.User,
      actorPrincipalId.ToString(),
      AuthorizationChangeLogTargetTypes.PermissionAssignment,
      assignmentId.ToString(),
      tenantId,
      before: new PermissionAssignmentSnapshot(
        assignment.PermissionName, assignment.Effect.ToString(), assignment.ScopeKind.ToString(), assignment.ScopeId)));

    _appDb.PermissionAssignments.Remove(assignment);
    await _appDb.SaveChangesAsync(cancellationToken);

    return HttpResult.Ok();
  }

  public async Task<IReadOnlyList<InternalDtos.PermissionAssignmentDto>> GetByPrincipal(
    PermissionPrincipalKind principalKind,
    Guid principalId,
    Guid tenantId,
    CancellationToken cancellationToken = default)
  {
    var assignments = await _appDb.PermissionAssignments
      .IgnoreQueryFilters()
      .Where(x => x.PrincipalKind == principalKind && x.PrincipalId == principalId)
      .OrderBy(x => x.PermissionName)
      .ThenBy(x => x.ScopeKind)
      .ToListAsync(cancellationToken);

    return [.. assignments.Select(MapToDto)];
  }

  public async Task<InternalDtos.EffectivePermissionQueryResponseDto> QueryEffectivePermission(
    InternalDtos.EffectivePermissionQueryRequestDto request,
    Guid tenantId,
    CancellationToken cancellationToken = default)
  {
    IReadOnlyList<string>? roles = null;
    if (request.PrincipalKind == PermissionPrincipalKind.User)
    {
      roles = await _appDb.UserRoles
        .IgnoreQueryFilters()
        .Where(x => x.UserId == request.PrincipalId)
        .Join(_appDb.Roles.IgnoreQueryFilters(),
          ur => ur.RoleId,
          r => r.Id,
          (ur, r) => r.Name!)
        .ToListAsync(cancellationToken);
    }

    var principal = new PrincipalDescriptor(
      PrincipalType: request.PrincipalKind.ToString(),
      PrincipalId: request.PrincipalId,
      TenantId: tenantId,
      AuthMethod: "effective-permission-query",
      Roles: roles);

    var resource = new ResourceDescriptor(request.ScopeKind, request.ScopeId, tenantId);

    var result = await _permissionEvaluator.Evaluate(
      principal, request.PermissionName, resource, cancellationToken);

    return new InternalDtos.EffectivePermissionQueryResponseDto(
      result.Allowed,
      result.Allowed ? null : result.DenialReason ?? "Permission denied by policy evaluation.");
  }

  private static InternalDtos.PermissionAssignmentDto MapToDto(PermissionAssignment assignment)
  {
    return new InternalDtos.PermissionAssignmentDto(
      assignment.Id,
      assignment.PrincipalKind,
      assignment.PrincipalId,
      assignment.PermissionName,
      assignment.Effect,
      assignment.ScopeKind,
      assignment.ScopeId,
      assignment.Notes,
      assignment.IsEnabled,
      assignment.CreatedAt);
  }

  private async Task<bool> ValidatePrincipalExists(
    PermissionPrincipalKind principalKind,
    Guid principalId,
    Guid tenantId,
    CancellationToken cancellationToken)
  {
    return principalKind switch
    {
      PermissionPrincipalKind.User => await _appDb.Users
        .AnyAsync(x => x.Id == principalId && x.TenantId == tenantId, cancellationToken),
      PermissionPrincipalKind.UserGroup => await _appDb.UserGroups
        .AnyAsync(x => x.Id == principalId && x.TenantId == tenantId, cancellationToken),
      PermissionPrincipalKind.ServiceAccount => await _appDb.ServiceAccounts
        .AnyAsync(x => x.Id == principalId, cancellationToken),
      PermissionPrincipalKind.PersonalAccessToken => await _appDb.PersonalAccessTokens
        .AnyAsync(x => x.Id == principalId, cancellationToken),
      PermissionPrincipalKind.LogonToken => await _appDb.LogonTokens
        .AnyAsync(x => x.Id == principalId, cancellationToken),
      _ => false
    };
  }
}
