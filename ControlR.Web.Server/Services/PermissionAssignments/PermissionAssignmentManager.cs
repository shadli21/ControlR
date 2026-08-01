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
  Task<HttpResult> CreateMany(
    IReadOnlyList<InternalDtos.CreatePermissionAssignmentRequestDto> requests,
    Guid tenantId,
    Guid actorPrincipalId,
    CancellationToken cancellationToken = default);
  Task<HttpResult> Delete(
    Guid assignmentId,
    Guid tenantId,
    Guid actorPrincipalId,
    CancellationToken cancellationToken = default);
  Task<HttpResult<InternalDtos.DeleteManyPermissionAssignmentsResponseDto>> DeleteMany(
    IReadOnlyList<Guid> assignmentIds,
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
  Task<HttpResult> ReplaceForPrincipal(
    PermissionPrincipalKind principalKind,
    Guid principalId,
    Guid tenantId,
    Guid actorPrincipalId,
    IReadOnlyList<InternalDtos.CreatePermissionAssignmentRequestDto> assignments,
    CancellationToken cancellationToken = default);
  Task<HttpResult<InternalDtos.PermissionAssignmentDto>> Update(
    Guid assignmentId,
    InternalDtos.UpdatePermissionAssignmentRequestDto request,
    Guid tenantId,
    Guid actorPrincipalId,
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

    if (request.ScopeKind is PermissionScopeKind.Device or PermissionScopeKind.DeviceGroup or PermissionScopeKind.CustomerTenant && !request.ScopeId.HasValue)
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
      ScopeId = NormalizeScopeId(request.ScopeKind, request.ScopeId, tenantId),
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
        request.PermissionName, request.Effect, request.ScopeKind, request.ScopeId)));

    await _appDb.SaveChangesAsync(cancellationToken);

    return HttpResult.Ok(MapToDto(assignment));
  }

  public async Task<HttpResult> CreateMany(
    IReadOnlyList<InternalDtos.CreatePermissionAssignmentRequestDto> requests,
    Guid tenantId,
    Guid actorPrincipalId,
    CancellationToken cancellationToken = default)
  {
    if (requests.Count == 0)
    {
      return HttpResult.Fail(HttpResultErrorCode.BadRequest, "No assignments were provided.");
    }

    var principalExists = await ValidatePrincipalExists(
      requests[0].PrincipalKind, requests[0].PrincipalId, tenantId, cancellationToken);
    if (!principalExists)
    {
      return HttpResult.Fail(
        HttpResultErrorCode.BadRequest, $"Principal not found: {requests[0].PrincipalKind}/{requests[0].PrincipalId}");
    }

    foreach (var request in requests)
    {
      if (!PermissionCatalog.Exists(request.PermissionName))
      {
        return HttpResult.Fail(HttpResultErrorCode.BadRequest, $"Unknown permission name: {request.PermissionName}");
      }

      if (request.ScopeKind is PermissionScopeKind.Device or PermissionScopeKind.DeviceGroup or PermissionScopeKind.CustomerTenant && !request.ScopeId.HasValue)
      {
        return HttpResult.Fail(HttpResultErrorCode.BadRequest, $"ScopeId is required for scope kind: {request.ScopeKind}");
      }

      var assignment = new PermissionAssignment
      {
        PrincipalKind = request.PrincipalKind,
        PrincipalId = request.PrincipalId,
        PermissionName = request.PermissionName,
        Effect = request.Effect,
        ScopeKind = request.ScopeKind,
        ScopeId = NormalizeScopeId(request.ScopeKind, request.ScopeId, tenantId),
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
          request.PermissionName, request.Effect, request.ScopeKind, request.ScopeId)));
    }

    await _appDb.SaveChangesAsync(cancellationToken);

    return HttpResult.Ok();
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
        assignment.PermissionName, assignment.Effect, assignment.ScopeKind, assignment.ScopeId)));

    _appDb.PermissionAssignments.Remove(assignment);
    await _appDb.SaveChangesAsync(cancellationToken);

    return HttpResult.Ok();
  }

  public async Task<HttpResult<InternalDtos.DeleteManyPermissionAssignmentsResponseDto>> DeleteMany(
    IReadOnlyList<Guid> assignmentIds,
    Guid tenantId,
    Guid actorPrincipalId,
    CancellationToken cancellationToken = default)
  {
    if (assignmentIds.Count == 0)
    {
      return HttpResult.Fail<InternalDtos.DeleteManyPermissionAssignmentsResponseDto>(
        HttpResultErrorCode.BadRequest, "No assignment IDs were provided.");
    }

    var assignments = await _appDb.PermissionAssignments
      .IgnoreQueryFilters()
      .Where(x => assignmentIds.Contains(x.Id))
      .ToListAsync(cancellationToken);

    var foundIds = assignments.Select(x => x.Id).ToHashSet();
    var successIds = new List<Guid>(assignments.Count);
    var failureIds = assignmentIds.Except(foundIds).ToList();

    foreach (var assignment in assignments)
    {
      _appDb.AuthorizationChangeLogs.Add(AuthorizationChangeLogEntry.Create(
        AuthorizationChangeLogActions.PermissionAssignmentDeleted,
        AuthorizationChangeLogActorTypes.User,
        actorPrincipalId.ToString(),
        AuthorizationChangeLogTargetTypes.PermissionAssignment,
        assignment.Id.ToString(),
        tenantId,
        before: new PermissionAssignmentSnapshot(
          assignment.PermissionName, assignment.Effect, assignment.ScopeKind, assignment.ScopeId)));

      _appDb.PermissionAssignments.Remove(assignment);
      successIds.Add(assignment.Id);
    }

    await _appDb.SaveChangesAsync(cancellationToken);

    return HttpResult.Ok(new InternalDtos.DeleteManyPermissionAssignmentsResponseDto(successIds, failureIds));
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
    var principal = new PrincipalDescriptor(
      PrincipalType: request.PrincipalKind.ToString(),
      PrincipalId: request.PrincipalId,
      TenantId: tenantId,
      AuthMethod: "effective-permission-query");

    var resource = new ResourceDescriptor(request.ScopeKind, request.ScopeId, tenantId);

    var result = await _permissionEvaluator.Evaluate(
      principal, request.PermissionName, resource, cancellationToken);

    return new InternalDtos.EffectivePermissionQueryResponseDto(
      result.Allowed,
      result.Allowed ? null : result.DenialReason ?? "Permission denied by policy evaluation.");
  }

  public async Task<HttpResult> ReplaceForPrincipal(
    PermissionPrincipalKind principalKind,
    Guid principalId,
    Guid tenantId,
    Guid actorPrincipalId,
    IReadOnlyList<InternalDtos.CreatePermissionAssignmentRequestDto> assignments,
    CancellationToken cancellationToken = default)
  {
    var principalExists = await ValidatePrincipalExists(principalKind, principalId, tenantId, cancellationToken);
    if (!principalExists)
    {
      return HttpResult.Fail(
        HttpResultErrorCode.BadRequest, $"Principal not found: {principalKind}/{principalId}");
    }

    var existing = await _appDb.PermissionAssignments
      .IgnoreQueryFilters()
      .Where(x => x.PrincipalKind == principalKind && x.PrincipalId == principalId)
      .ToListAsync(cancellationToken);

    foreach (var existingAssignment in existing)
    {
      _appDb.AuthorizationChangeLogs.Add(AuthorizationChangeLogEntry.Create(
        AuthorizationChangeLogActions.PermissionAssignmentDeleted,
        AuthorizationChangeLogActorTypes.User,
        actorPrincipalId.ToString(),
        AuthorizationChangeLogTargetTypes.PermissionAssignment,
        existingAssignment.Id.ToString(),
        tenantId,
        before: new PermissionAssignmentSnapshot(
          existingAssignment.PermissionName, existingAssignment.Effect,
          existingAssignment.ScopeKind, existingAssignment.ScopeId)));

      _appDb.PermissionAssignments.Remove(existingAssignment);
    }

    foreach (var request in assignments)
    {
      if (!PermissionCatalog.Exists(request.PermissionName))
      {
        return HttpResult.Fail(HttpResultErrorCode.BadRequest, $"Unknown permission name: {request.PermissionName}");
      }

      var assignment = new PermissionAssignment
      {
        PrincipalKind = principalKind,
        PrincipalId = principalId,
        PermissionName = request.PermissionName,
        Effect = request.Effect,
        ScopeKind = request.ScopeKind,
        ScopeId = NormalizeScopeId(request.ScopeKind, request.ScopeId, tenantId),
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
          request.PermissionName, request.Effect, request.ScopeKind, request.ScopeId)));
    }

    await _appDb.SaveChangesAsync(cancellationToken);

    return HttpResult.Ok();
  }

  public async Task<HttpResult<InternalDtos.PermissionAssignmentDto>> Update(
    Guid assignmentId,
    InternalDtos.UpdatePermissionAssignmentRequestDto request,
    Guid tenantId,
    Guid actorPrincipalId,
    CancellationToken cancellationToken = default)
  {
    var assignment = await _appDb.PermissionAssignments
      .IgnoreQueryFilters()
      .FirstOrDefaultAsync(x => x.Id == assignmentId, cancellationToken);

    if (assignment is null)
    {
      return HttpResult.Fail<InternalDtos.PermissionAssignmentDto>(
        HttpResultErrorCode.NotFound, "Permission assignment not found.");
    }

    if (!PermissionCatalog.Exists(request.PermissionName))
    {
      return HttpResult.Fail<InternalDtos.PermissionAssignmentDto>(
        HttpResultErrorCode.BadRequest, $"Unknown permission name: {request.PermissionName}");
    }

    if (request.ScopeKind is PermissionScopeKind.Device or PermissionScopeKind.DeviceGroup or PermissionScopeKind.CustomerTenant && !request.ScopeId.HasValue)
    {
      return HttpResult.Fail<InternalDtos.PermissionAssignmentDto>(
        HttpResultErrorCode.BadRequest, $"ScopeId is required for scope kind: {request.ScopeKind}");
    }

    var before = new PermissionAssignmentSnapshot(
      assignment.PermissionName, assignment.Effect, assignment.ScopeKind, assignment.ScopeId);

    assignment.PermissionName = request.PermissionName;
    assignment.Effect = request.Effect;
    assignment.ScopeKind = request.ScopeKind;
    assignment.ScopeId = NormalizeScopeId(request.ScopeKind, request.ScopeId, tenantId);
    assignment.Notes = request.Notes;
    assignment.IsEnabled = request.IsEnabled;
    assignment.OwningTenantId = request.ScopeKind == PermissionScopeKind.Server ? null : tenantId;

    _appDb.AuthorizationChangeLogs.Add(AuthorizationChangeLogEntry.Create(
      AuthorizationChangeLogActions.PermissionAssignmentUpdated,
      AuthorizationChangeLogActorTypes.User,
      actorPrincipalId.ToString(),
      AuthorizationChangeLogTargetTypes.PermissionAssignment,
      assignment.Id.ToString(),
      tenantId,
      before: before,
      after: new PermissionAssignmentSnapshot(
        assignment.PermissionName, assignment.Effect, assignment.ScopeKind, assignment.ScopeId)));

    await _appDb.SaveChangesAsync(cancellationToken);

    return HttpResult.Ok(MapToDto(assignment));
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

  /// <summary>
  /// Server scope needs no target; tenant scope implicitly targets the acting user's tenant
  /// (the UI does not collect a ScopeId for these, so the API fills it in).
  /// </summary>
  private static Guid? NormalizeScopeId(PermissionScopeKind scopeKind, Guid? scopeId, Guid tenantId) => scopeKind switch
  {
    PermissionScopeKind.Server => null,
    PermissionScopeKind.Tenant => tenantId,
    _ => scopeId
  };

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
