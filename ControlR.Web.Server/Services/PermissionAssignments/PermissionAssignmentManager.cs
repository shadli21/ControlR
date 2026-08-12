using ControlR.Web.Server.Authn;
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
  Task<HttpResult<int>> ApplyPresets(
    InternalDtos.ApplyPermissionPresetsRequestDto request,
    Guid tenantId,
    PrincipalDescriptor actor,
    CancellationToken cancellationToken = default);
  Task<HttpResult<InternalDtos.PermissionAssignmentDto>> Create(
    InternalDtos.CreatePermissionAssignmentRequestDto request,
    Guid tenantId,
    PrincipalDescriptor actor,
    CancellationToken cancellationToken = default);
  Task<HttpResult> CreateMany(
    IReadOnlyList<InternalDtos.CreatePermissionAssignmentRequestDto> requests,
    Guid tenantId,
    PrincipalDescriptor actor,
    CancellationToken cancellationToken = default);
  Task<HttpResult> Delete(
    Guid assignmentId,
    Guid tenantId,
    PrincipalDescriptor actor,
    CancellationToken cancellationToken = default);
  Task<HttpResult<InternalDtos.DeleteManyPermissionAssignmentsResponseDto>> DeleteMany(
    IReadOnlyList<Guid> assignmentIds,
    Guid tenantId,
    PrincipalDescriptor actor,
    CancellationToken cancellationToken = default);
  Task<IReadOnlyList<InternalDtos.PermissionAssignmentDto>> GetByPrincipal(
    PermissionPrincipalKind principalKind,
    Guid principalId,
    Guid tenantId,
    PrincipalDescriptor actor,
    CancellationToken cancellationToken = default);

  /// <summary>
  /// Replaces a principal's assignments for the scope kinds represented by the given set.
  /// Deletes visible assignments with those scope kinds, then creates the new ones. All
  /// removals and creations are change-logged.
  /// </summary>
  Task<HttpResult> ReplaceForPrincipal(
    PermissionPrincipalKind principalKind,
    Guid principalId,
    Guid tenantId,
    PrincipalDescriptor actor,
    IReadOnlyList<InternalDtos.CreatePermissionAssignmentRequestDto> assignments,
    CancellationToken cancellationToken = default);
  Task<HttpResult<InternalDtos.PermissionAssignmentDto>> Update(
    Guid assignmentId,
    InternalDtos.UpdatePermissionAssignmentRequestDto request,
    Guid tenantId,
    PrincipalDescriptor actor,
    CancellationToken cancellationToken = default);
}

public class PermissionAssignmentManager(
  AppDb appDb,
  IPermissionEvaluator permissionEvaluator,
  ICredentialScopeService credentialScopeService) : IPermissionAssignmentManager
{
  private readonly AppDb _appDb = appDb;
  private readonly ICredentialScopeService _credentialScopeService = credentialScopeService;
  private readonly IPermissionEvaluator _permissionEvaluator = permissionEvaluator;

  public async Task<HttpResult<int>> ApplyPresets(
    InternalDtos.ApplyPermissionPresetsRequestDto request,
    Guid tenantId,
    PrincipalDescriptor actor,
    CancellationToken cancellationToken = default)
  {
    var permissionNames = request.PresetNames
      .SelectMany(PermissionPresets.GetPermissions)
      .Distinct()
      .ToList();

    if (permissionNames.Count == 0)
    {
      return HttpResult.Fail<int>(HttpResultErrorCode.BadRequest, "No preset permissions were found.");
    }

    var assignments = permissionNames
      .Select(permissionName => new InternalDtos.CreatePermissionAssignmentRequestDto(
        request.PrincipalKind,
        request.PrincipalId,
        permissionName,
        PermissionEffect.Allow,
        PermissionCatalog.GetBroadestLegalScope(permissionName) ?? PermissionScopeKind.Tenant,
        null,
        null))
      .ToList();

    if (!request.ReplaceExisting)
    {
      var existingKeys = await _appDb.PermissionAssignments
        .IgnoreQueryFilters()
        .Where(x => x.PrincipalKind == request.PrincipalKind && x.PrincipalId == request.PrincipalId)
        .Select(x => new { x.PermissionName, x.ScopeKind })
        .ToListAsync(cancellationToken);
      var existingKeySet = existingKeys
        .Select(x => (x.PermissionName, x.ScopeKind))
        .ToHashSet();
      assignments = assignments
        .Where(x => !existingKeySet.Contains((x.PermissionName, x.ScopeKind)))
        .ToList();

      if (assignments.Count == 0)
      {
        return HttpResult.Ok(0);
      }
    }

    async Task<HttpResult<int>> Apply()
    {
      HttpResult result;
      if (request.ReplaceExisting)
      {
        result = await ReplaceForPrincipal(
          request.PrincipalKind,
          request.PrincipalId,
          tenantId,
          actor,
          assignments,
          cancellationToken);
      }
      else
      {
        result = await CreateMany(assignments, tenantId, actor, cancellationToken);
      }

      return result.IsSuccess
        ? HttpResult.Ok(assignments.Count)
        : HttpResult.Fail<int>(result.ErrorCode, result.Reason);
    }

    if (!_appDb.Database.IsRelational())
    {
      return await Apply();
    }

    await using var transaction = await _appDb.Database.BeginTransactionAsync(cancellationToken);
    var applyResult = await Apply();
    if (!applyResult.IsSuccess)
    {
      return applyResult;
    }

    await transaction.CommitAsync(cancellationToken);
    return applyResult;
  }

  public async Task<HttpResult<InternalDtos.PermissionAssignmentDto>> Create(
    InternalDtos.CreatePermissionAssignmentRequestDto request,
    Guid tenantId,
    PrincipalDescriptor actor,
    CancellationToken cancellationToken = default)
  {
    var principalExists = await ValidatePrincipalExists(
      request.PrincipalKind, request.PrincipalId, tenantId, cancellationToken);
    if (!principalExists)
    {
      return HttpResult.Fail<InternalDtos.PermissionAssignmentDto>(
        HttpResultErrorCode.BadRequest, $"Principal not found: {request.PrincipalKind}/{request.PrincipalId}");
    }

    var effectivePermissions = await GetEffectivePermissions(actor, cancellationToken);
    if (ValidateWriteAuthority(request.Effect, request.ScopeKind, effectivePermissions) is { } authorityError)
    {
      return HttpResult.Fail<InternalDtos.PermissionAssignmentDto>(
      authorityError.Code, authorityError.Reason);
    }

    if (await ValidatePermissionScope(request.PermissionName, request.ScopeKind, request.ScopeId, tenantId, cancellationToken) is { } scopeError)
    {
      return HttpResult.Fail<InternalDtos.PermissionAssignmentDto>(scopeError.Code, scopeError.Reason);
    }

    if (await ValidateCredentialPrincipalScope(
      request.PrincipalKind, request.PrincipalId, request.PermissionName,
      request.ScopeKind, request.ScopeId, cancellationToken) is { } credentialScopeError)
    {
      return HttpResult.Fail<InternalDtos.PermissionAssignmentDto>(HttpResultErrorCode.BadRequest, credentialScopeError);
    }

    var assignment = PermissionAssignment.CreateGrant(
      request.PrincipalKind,
      request.PrincipalId,
      request.PermissionName,
      request.ScopeKind,
      NormalizeScopeId(request.ScopeKind, request.ScopeId, tenantId),
      tenantId,
      AuthorizationChangeLogActorTypes.User,
      actor.PrincipalId.ToString(),
      request.Effect,
      request.Notes);

    _appDb.PermissionAssignments.Add(assignment);

    await _appDb.SaveChangesAsync(cancellationToken);

    _appDb.AuthorizationChangeLogs.Add(AuthorizationChangeLogFactory.Create(
      AuthorizationChangeLogActions.PermissionAssignmentCreated,
      AuthorizationChangeLogActorTypes.User,
      actor.PrincipalId,
      AuthorizationChangeLogTargetTypes.PermissionAssignment,
      assignment.Id,
      assignment.OwningTenantId,
      after: new PermissionAssignmentSnapshot(
        request.PermissionName, request.Effect, request.ScopeKind, request.ScopeId)));

    await _appDb.SaveChangesAsync(cancellationToken);

    return HttpResult.Ok(MapToDto(assignment));
  }

  public async Task<HttpResult> CreateMany(
    IReadOnlyList<InternalDtos.CreatePermissionAssignmentRequestDto> requests,
    Guid tenantId,
    PrincipalDescriptor actor,
    CancellationToken cancellationToken = default)
  {
    if (requests.Count == 0)
    {
      return HttpResult.Fail(HttpResultErrorCode.BadRequest, "No assignments were provided.");
    }

    if (requests.Any(request => request.PrincipalKind != requests[0].PrincipalKind || request.PrincipalId != requests[0].PrincipalId))
    {
      return HttpResult.Fail(HttpResultErrorCode.BadRequest, "All assignments must target the same principal.");
    }

    var principalExists = await ValidatePrincipalExists(
      requests[0].PrincipalKind, requests[0].PrincipalId, tenantId, cancellationToken);
    if (!principalExists)
    {
      return HttpResult.Fail(
        HttpResultErrorCode.BadRequest, $"Principal not found: {requests[0].PrincipalKind}/{requests[0].PrincipalId}");
    }

    var effectivePermissions = await GetEffectivePermissions(actor, cancellationToken);
    foreach (var request in requests)
    {
      if (ValidateWriteAuthority(request.Effect, request.ScopeKind, effectivePermissions) is { } authorityError)
      {
        return HttpResult.Fail(authorityError.Code, authorityError.Reason);
      }
    }

    var created = new List<PermissionAssignment>(requests.Count);

    foreach (var request in requests)
    {
      if (await ValidatePermissionScope(request.PermissionName, request.ScopeKind, request.ScopeId, tenantId, cancellationToken) is { } scopeError)
      {
        return HttpResult.Fail(scopeError.Code, scopeError.Reason);
      }

      if (await ValidateCredentialPrincipalScope(
        request.PrincipalKind, request.PrincipalId, request.PermissionName,
        request.ScopeKind, request.ScopeId, cancellationToken) is { } credentialScopeError)
      {
        return HttpResult.Fail(HttpResultErrorCode.BadRequest, credentialScopeError);
      }

      var assignment = PermissionAssignment.CreateGrant(
        request.PrincipalKind,
        request.PrincipalId,
        request.PermissionName,
        request.ScopeKind,
        NormalizeScopeId(request.ScopeKind, request.ScopeId, tenantId),
        tenantId,
        AuthorizationChangeLogActorTypes.User,
        actor.PrincipalId.ToString(),
        request.Effect,
        request.Notes);

      _appDb.PermissionAssignments.Add(assignment);
      created.Add(assignment);
    }

    await _appDb.SaveChangesAsync(cancellationToken);

    // Log after save so the assignment IDs are real (not Guid.Empty).
    for (var i = 0; i < requests.Count; i++)
    {
      var request = requests[i];
      var assignment = created[i];
      _appDb.AuthorizationChangeLogs.Add(AuthorizationChangeLogFactory.Create(
        AuthorizationChangeLogActions.PermissionAssignmentCreated,
        AuthorizationChangeLogActorTypes.User,
        actor.PrincipalId,
        AuthorizationChangeLogTargetTypes.PermissionAssignment,
        assignment.Id,
        assignment.OwningTenantId,
        after: new PermissionAssignmentSnapshot(
          request.PermissionName, request.Effect, request.ScopeKind, request.ScopeId)));
    }

    await _appDb.SaveChangesAsync(cancellationToken);

    return HttpResult.Ok();
  }

  public async Task<HttpResult> Delete(
    Guid assignmentId,
    Guid tenantId,
    PrincipalDescriptor actor,
    CancellationToken cancellationToken = default)
  {
    var assignment = await _appDb.PermissionAssignments
      .IgnoreQueryFilters()
      .FirstOrDefaultAsync(x => x.Id == assignmentId, cancellationToken);

    if (assignment is null)
    {
      return HttpResult.Fail(HttpResultErrorCode.NotFound, "Permission assignment not found.");
    }

    var effectivePermissions = await GetEffectivePermissions(actor, cancellationToken);
    if (!IsVisibleToTenant(assignment, tenantId, effectivePermissions))
    {
      return HttpResult.Fail(HttpResultErrorCode.NotFound, "Permission assignment not found.");
    }

    if (ValidateWriteAuthority(assignment.Effect, assignment.ScopeKind, effectivePermissions) is { } authorityError)
    {
      return HttpResult.Fail(authorityError.Code, authorityError.Reason);
    }

    if (IsSelf(assignment, actor.PrincipalId))
    {
      var grantedAfter = await _appDb.PermissionAssignments
        .IgnoreQueryFilters()
        .Where(x => x.PrincipalKind == PermissionPrincipalKind.User &&
                    x.PrincipalId == actor.PrincipalId &&
                    x.Id != assignmentId &&
                    x.Effect == PermissionEffect.Allow &&
                    x.IsEnabled)
        .Select(x => x.PermissionName)
        .ToListAsync(cancellationToken);

      var grantedBefore = new HashSet<string>(grantedAfter);
      if (assignment.Effect == PermissionEffect.Allow && assignment.IsEnabled)
      {
        grantedBefore.Add(assignment.PermissionName);
      }

      if (FindViolatedSelfProtected(grantedBefore, grantedAfter) is { } violation)
      {
        return HttpResult.Fail(HttpResultErrorCode.BadRequest, violation);
      }
    }

    _appDb.AuthorizationChangeLogs.Add(AuthorizationChangeLogFactory.Create(
      AuthorizationChangeLogActions.PermissionAssignmentDeleted,
      AuthorizationChangeLogActorTypes.User,
      actor.PrincipalId,
      AuthorizationChangeLogTargetTypes.PermissionAssignment,
      assignmentId,
      assignment.OwningTenantId,
      before: new PermissionAssignmentSnapshot(
        assignment.PermissionName, assignment.Effect, assignment.ScopeKind, assignment.ScopeId)));

    _appDb.PermissionAssignments.Remove(assignment);
    await _appDb.SaveChangesAsync(cancellationToken);

    return HttpResult.Ok();
  }

  public async Task<HttpResult<InternalDtos.DeleteManyPermissionAssignmentsResponseDto>> DeleteMany(
    IReadOnlyList<Guid> assignmentIds,
    Guid tenantId,
    PrincipalDescriptor actor,
    CancellationToken cancellationToken = default)
  {
    if (assignmentIds.Count == 0)
    {
      return HttpResult.Fail<InternalDtos.DeleteManyPermissionAssignmentsResponseDto>(
        HttpResultErrorCode.BadRequest, "No assignment IDs were provided.");
    }

    var foundAssignments = await _appDb.PermissionAssignments
      .IgnoreQueryFilters()
      .Where(x => assignmentIds.Contains(x.Id))
      .ToListAsync(cancellationToken);

    var effectivePermissions = await GetEffectivePermissions(actor, cancellationToken);

    var assignments = foundAssignments
      .Where(x => IsVisibleToTenant(x, tenantId, effectivePermissions))
      .ToList();

    foreach (var assignment in assignments)
    {
      if (ValidateWriteAuthority(assignment.Effect, assignment.ScopeKind, effectivePermissions) is { } authorityError)
      {
        return HttpResult.Fail<InternalDtos.DeleteManyPermissionAssignmentsResponseDto>(authorityError.Code, authorityError.Reason);
      }
    }

    var foundIds = assignments.Select(x => x.Id).ToHashSet();
    var successIds = new List<Guid>(assignments.Count);
    var failureIds = assignmentIds.Except(foundIds).ToList();

    if (assignments.Any(x => IsSelf(x, actor.PrincipalId)))
    {
      var grantedAfter = await _appDb.PermissionAssignments
        .IgnoreQueryFilters()
        .Where(x => x.PrincipalKind == PermissionPrincipalKind.User &&
                    x.PrincipalId == actor.PrincipalId &&
                    !assignmentIds.Contains(x.Id) &&
                    x.Effect == PermissionEffect.Allow &&
                    x.IsEnabled)
        .Select(x => x.PermissionName)
        .ToListAsync(cancellationToken);

      var grantedBefore = new HashSet<string>(grantedAfter);
      foreach (var selfAssignment in assignments.Where(x => IsSelf(x, actor.PrincipalId) && x.Effect == PermissionEffect.Allow && x.IsEnabled))
      {
        grantedBefore.Add(selfAssignment.PermissionName);
      }

      if (FindViolatedSelfProtected(grantedBefore, grantedAfter) is { } violation)
      {
        return HttpResult.Fail<InternalDtos.DeleteManyPermissionAssignmentsResponseDto>(
          HttpResultErrorCode.BadRequest, violation);
      }
    }

    foreach (var assignment in assignments)
    {
      _appDb.AuthorizationChangeLogs.Add(AuthorizationChangeLogFactory.Create(
        AuthorizationChangeLogActions.PermissionAssignmentDeleted,
        AuthorizationChangeLogActorTypes.User,
        actor.PrincipalId,
        AuthorizationChangeLogTargetTypes.PermissionAssignment,
        assignment.Id,
        assignment.OwningTenantId,
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
    PrincipalDescriptor actor,
    CancellationToken cancellationToken = default)
  {
    var effectivePermissions = await GetEffectivePermissions(actor, cancellationToken);

    var assignments = await _appDb.PermissionAssignments
      .IgnoreQueryFilters()
      .Where(x => x.PrincipalKind == principalKind &&
                  x.PrincipalId == principalId &&
                  (x.OwningTenantId == tenantId ||
                  (x.OwningTenantId == null && effectivePermissions.Contains(PermissionNames.ServerPermissionsRead))))
      .OrderBy(x => x.PermissionName)
      .ThenBy(x => x.ScopeKind)
      .ToListAsync(cancellationToken);

    return [.. assignments.Select(MapToDto)];
  }

  public async Task<HttpResult> ReplaceForPrincipal(
    PermissionPrincipalKind principalKind,
    Guid principalId,
    Guid tenantId,
    PrincipalDescriptor actor,
    IReadOnlyList<InternalDtos.CreatePermissionAssignmentRequestDto> assignments,
    CancellationToken cancellationToken = default)
  {
    var principalExists = await ValidatePrincipalExists(principalKind, principalId, tenantId, cancellationToken);
    if (!principalExists)
    {
      return HttpResult.Fail(
        HttpResultErrorCode.BadRequest, $"Principal not found: {principalKind}/{principalId}");
    }

    var effectivePermissions = await GetEffectivePermissions(actor, cancellationToken);
    var replacedScopeKinds = assignments
      .Select(x => x.ScopeKind)
      .ToHashSet();

    foreach (var request in assignments)
    {
      if (ValidateWriteAuthority(request.Effect, request.ScopeKind, effectivePermissions) is { } authorityError)
      {
        return HttpResult.Fail(authorityError.Code, authorityError.Reason);
      }
    }

    if (principalKind == PermissionPrincipalKind.User && principalId == actor.PrincipalId)
    {
      var grantedBefore = await _appDb.PermissionAssignments
        .IgnoreQueryFilters()
        .Where(x => x.PrincipalKind == PermissionPrincipalKind.User &&
                    x.PrincipalId == actor.PrincipalId &&
                    replacedScopeKinds.Contains(x.ScopeKind) &&
                    x.Effect == PermissionEffect.Allow &&
                    x.IsEnabled)
        .Select(x => x.PermissionName)
        .ToListAsync(cancellationToken);

      var grantedAfter = assignments
        .Where(r => replacedScopeKinds.Contains(r.ScopeKind))
        .Where(r => r.Effect == PermissionEffect.Allow)
        .Select(r => r.PermissionName)
        .ToList();

      if (FindViolatedSelfProtected(grantedBefore, grantedAfter) is { } violation)
      {
        return HttpResult.Fail(HttpResultErrorCode.BadRequest, violation);
      }
    }

    var existing = await _appDb.PermissionAssignments
      .IgnoreQueryFilters()
      .Where(x => x.PrincipalKind == principalKind && x.PrincipalId == principalId)
      .ToListAsync(cancellationToken);

    foreach (var existingAssignment in existing.Where(x =>
      IsVisibleToTenant(x, tenantId, effectivePermissions) &&
      replacedScopeKinds.Contains(x.ScopeKind)))
    {
      _appDb.AuthorizationChangeLogs.Add(AuthorizationChangeLogFactory.Create(
        AuthorizationChangeLogActions.PermissionAssignmentDeleted,
        AuthorizationChangeLogActorTypes.User,
        actor.PrincipalId,
        AuthorizationChangeLogTargetTypes.PermissionAssignment,
        existingAssignment.Id,
        existingAssignment.OwningTenantId,
        before: new PermissionAssignmentSnapshot(
          existingAssignment.PermissionName, existingAssignment.Effect,
          existingAssignment.ScopeKind, existingAssignment.ScopeId)));

      _appDb.PermissionAssignments.Remove(existingAssignment);
    }

    var created = new List<PermissionAssignment>(assignments.Count);

    foreach (var request in assignments)
    {
      if (await ValidatePermissionScope(request.PermissionName, request.ScopeKind, request.ScopeId, tenantId, cancellationToken) is { } scopeError)
      {
        return HttpResult.Fail(scopeError.Code, scopeError.Reason);
      }

      if (await ValidateCredentialPrincipalScope(
        principalKind, principalId, request.PermissionName,
        request.ScopeKind, request.ScopeId, cancellationToken) is { } credentialScopeError)
      {
        return HttpResult.Fail(HttpResultErrorCode.BadRequest, credentialScopeError);
      }

      var assignment = PermissionAssignment.CreateGrant(
        principalKind,
        principalId,
        request.PermissionName,
        request.ScopeKind,
        NormalizeScopeId(request.ScopeKind, request.ScopeId, tenantId),
        tenantId,
        AuthorizationChangeLogActorTypes.User,
        actor.PrincipalId.ToString(),
        request.Effect);

      _appDb.PermissionAssignments.Add(assignment);
      created.Add(assignment);
    }

    await _appDb.SaveChangesAsync(cancellationToken);

    // Log the created assignments after save so their IDs are real (not Guid.Empty).
    for (var i = 0; i < created.Count; i++)
    {
      var assignment = created[i];
      var request = assignments[i];
      _appDb.AuthorizationChangeLogs.Add(AuthorizationChangeLogFactory.Create(
        AuthorizationChangeLogActions.PermissionAssignmentCreated,
        AuthorizationChangeLogActorTypes.User,
        actor.PrincipalId,
        AuthorizationChangeLogTargetTypes.PermissionAssignment,
        assignment.Id,
        assignment.OwningTenantId,
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
    PrincipalDescriptor actor,
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

    var effectivePermissions = await GetEffectivePermissions(actor, cancellationToken);

    if (!IsVisibleToTenant(assignment, tenantId, effectivePermissions))
    {
      return HttpResult.Fail<InternalDtos.PermissionAssignmentDto>(
        HttpResultErrorCode.NotFound, "Permission assignment not found.");
    }

    if (ValidateWriteAuthority(assignment.Effect, assignment.ScopeKind, effectivePermissions) is { } existingAuthorityError)
    {
      return HttpResult.Fail<InternalDtos.PermissionAssignmentDto>(existingAuthorityError.Code, existingAuthorityError.Reason);
    }

    if (ValidateWriteAuthority(request.Effect, request.ScopeKind, effectivePermissions) is { } authorityError)
    {
      return HttpResult.Fail<InternalDtos.PermissionAssignmentDto>(authorityError.Code, authorityError.Reason);
    }

    if (await ValidatePermissionScope(request.PermissionName, request.ScopeKind, request.ScopeId, tenantId, cancellationToken) is { } scopeError)
    {
      return HttpResult.Fail<InternalDtos.PermissionAssignmentDto>(scopeError.Code, scopeError.Reason);
    }

    if (await ValidateCredentialPrincipalScope(
      assignment.PrincipalKind, assignment.PrincipalId, request.PermissionName,
      request.ScopeKind, request.ScopeId, cancellationToken) is { } credentialScopeError)
    {
      return HttpResult.Fail<InternalDtos.PermissionAssignmentDto>(HttpResultErrorCode.BadRequest, credentialScopeError);
    }

    if (IsSelf(assignment, actor.PrincipalId))
    {
      var others = await _appDb.PermissionAssignments
        .IgnoreQueryFilters()
        .Where(x => x.PrincipalKind == PermissionPrincipalKind.User &&
                    x.PrincipalId == actor.PrincipalId &&
                    x.Id != assignmentId &&
                    x.Effect == PermissionEffect.Allow &&
                    x.IsEnabled)
        .Select(x => x.PermissionName)
        .ToListAsync(cancellationToken);

      var grantedBefore = new HashSet<string>(others);
      if (assignment.Effect == PermissionEffect.Allow && assignment.IsEnabled)
      {
        grantedBefore.Add(assignment.PermissionName);
      }

      var grantedAfter = new HashSet<string>(others);
      if (request.Effect == PermissionEffect.Allow && request.IsEnabled)
      {
        grantedAfter.Add(request.PermissionName);
      }

      if (FindViolatedSelfProtected(grantedBefore, grantedAfter) is { } violation)
      {
        return HttpResult.Fail<InternalDtos.PermissionAssignmentDto>(HttpResultErrorCode.BadRequest, violation);
      }
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

    _appDb.AuthorizationChangeLogs.Add(AuthorizationChangeLogFactory.Create(
      AuthorizationChangeLogActions.PermissionAssignmentUpdated,
      AuthorizationChangeLogActorTypes.User,
      actor.PrincipalId,
      AuthorizationChangeLogTargetTypes.PermissionAssignment,
      assignment.Id,
      assignment.OwningTenantId,
      before: before,
      after: new PermissionAssignmentSnapshot(
        assignment.PermissionName, assignment.Effect, assignment.ScopeKind, assignment.ScopeId)));

    await _appDb.SaveChangesAsync(cancellationToken);

    return HttpResult.Ok(MapToDto(assignment));
  }

  /// <summary>
  /// Anti-lockout guard: returns an error if the operation drops any non-self-removable
  /// permission that the actor actually held before the operation (i.e. the last grant of a
  /// protected permission would be lost). Only the actor's own principal is guarded; another
  /// authorized holder may still revoke these.
  /// </summary>
  private static string? FindViolatedSelfProtected(
    IReadOnlyCollection<string> preOpGranted,
    IReadOnlyCollection<string> postOpGranted)
  {
    foreach (var lostPermission in new HashSet<string>(preOpGranted).Except(postOpGranted))
    {
      var metadata = PermissionCatalog.Get(lostPermission);
      if (metadata is not null && !metadata.SelfRemovable)
      {
        return $"You cannot remove '{metadata.DisplayName}' from yourself; retaining it is required to continue managing permissions.";
      }
    }

    return null;
  }

  private static bool IsSelf(PermissionAssignment assignment, Guid actorPrincipalId) =>
    assignment.PrincipalKind == PermissionPrincipalKind.User && assignment.PrincipalId == actorPrincipalId;

  /// <summary>
  /// Tenant isolation: tenant-owned rows are visible only to the owning tenant; server-scoped
  /// rows require the corresponding server read or write permission.
  /// </summary>
  private static bool IsVisibleToTenant(
    PermissionAssignment assignment,
    Guid tenantId,
    IReadOnlySet<string> effectivePermissions) =>
    assignment.OwningTenantId == tenantId ||
    (assignment.OwningTenantId is null &&
      (effectivePermissions.Contains(PermissionNames.ServerPermissionsRead) ||
       effectivePermissions.Contains(PermissionNames.ServerPermissionsWrite)));

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

  private static (HttpResultErrorCode Code, string Reason)? ValidateWriteAuthority(
    PermissionEffect effect,
    PermissionScopeKind scopeKind,
    IReadOnlySet<string> effectivePermissions)
  {
    var requiredPermission = scopeKind == PermissionScopeKind.Server
      ? PermissionNames.ServerPermissionsWrite
      : PermissionNames.TenantPermissionsWrite;
    if (!effectivePermissions.Contains(requiredPermission))
    {
      return (HttpResultErrorCode.Forbidden, $"The '{requiredPermission}' permission is required to manage {scopeKind.ToString().ToLowerInvariant()}-scoped assignments.");
    }

    if (effect == PermissionEffect.Allow)
    {
      return null;
    }

    if (!effectivePermissions.Contains(PermissionNames.TenantPermissionsDeny))
    {
      return (HttpResultErrorCode.Forbidden, $"The '{PermissionNames.TenantPermissionsDeny}' permission is required to manage {effect.ToString().ToLowerInvariant()} assignments.");
    }

    return null;
  }

  private Task<IReadOnlySet<string>> GetEffectivePermissions(
    PrincipalDescriptor actor,
    CancellationToken cancellationToken) =>
    _permissionEvaluator.GetEffectivePermissionNames(actor, cancellationToken);

  /// <summary>
  /// Credential principals (PATs, logon tokens) can never exceed their owning user's
  /// effective rights, so rows written for them are validated against the owner at write
  /// time rather than left to be silently discarded by evaluation-time bounding. Returns a
  /// user-facing error message, or <see langword="null"/> when valid or not applicable.
  /// </summary>
  private async Task<string?> ValidateCredentialPrincipalScope(
    PermissionPrincipalKind principalKind,
    Guid principalId,
    string permissionName,
    PermissionScopeKind scopeKind,
    Guid? scopeId,
    CancellationToken cancellationToken)
  {
    var ownerUserId = principalKind switch
    {
      PermissionPrincipalKind.PersonalAccessToken => await _appDb.PersonalAccessTokens
        .IgnoreQueryFilters()
        .Where(x => x.Id == principalId)
        .Select(x => (Guid?)x.UserId)
        .FirstOrDefaultAsync(cancellationToken),
      PermissionPrincipalKind.LogonToken => await _appDb.LogonTokens
        .IgnoreQueryFilters()
        .Where(x => x.Id == principalId)
        .Select(x => (Guid?)x.UserId)
        .FirstOrDefaultAsync(cancellationToken),
      _ => null
    };

    if (ownerUserId is null)
    {
      return null;
    }

    var owner = await _appDb.Users
      .IgnoreQueryFilters()
      .AsNoTracking()
      .FirstOrDefaultAsync(x => x.Id == ownerUserId, cancellationToken);
    if (owner is null || owner.TenantId == Guid.Empty)
    {
      return "Token owner not found.";
    }

    var ownerPrincipal = new PrincipalDescriptor(
      PrincipalType: PrincipalClaimTypes.User,
      PrincipalId: owner.Id,
      TenantId: owner.TenantId,
      AuthMethod: "credential-scope-validation");

    var validation = await _credentialScopeService.ValidateGrantableScopes(
      ownerPrincipal,
      owner.TenantId,
      [new InternalDtos.CredentialScopeDto(permissionName, scopeKind, scopeId)],
      cancellationToken);

    return validation.IsSuccess ? null : validation.Reason;
  }

  /// <summary>
  /// Validates that the permission exists in the catalog and that the requested scope kind is
  /// within its allowed whitelist. Returns a user-facing error message, or <see langword="null"/>
  /// when valid.
  /// </summary>
  private async Task<(HttpResultErrorCode Code, string Reason)?> ValidatePermissionScope(
    string permissionName,
    PermissionScopeKind scopeKind,
    Guid? scopeId,
    Guid tenantId,
    CancellationToken cancellationToken)
  {
    var metadata = PermissionCatalog.Get(permissionName);
    if (metadata is null)
    {
      return (HttpResultErrorCode.BadRequest, $"Unknown permission name: {permissionName}");
    }

    if (metadata.AllowedScopeKinds is not { } allowed || !allowed.Contains(scopeKind))
    {
      return (HttpResultErrorCode.BadRequest, $"Permission '{metadata.DisplayName}' cannot be assigned at {scopeKind} scope.");
    }

    if (scopeKind is PermissionScopeKind.Device or PermissionScopeKind.DeviceGroup or PermissionScopeKind.CustomerTenant or PermissionScopeKind.UserGroup && !scopeId.HasValue)
    {
      return (HttpResultErrorCode.BadRequest, $"ScopeId is required for scope kind: {scopeKind}");
    }

    if (scopeKind == PermissionScopeKind.Device && !await _appDb.Devices.AnyAsync(x => x.Id == scopeId && x.TenantId == tenantId, cancellationToken))
    {
      return (HttpResultErrorCode.BadRequest, "The selected device does not belong to the current tenant.");
    }

    if (scopeKind == PermissionScopeKind.DeviceGroup && !await _appDb.DeviceGroups.AnyAsync(x => x.Id == scopeId && x.TenantId == tenantId, cancellationToken))
    {
      return (HttpResultErrorCode.BadRequest, "The selected device group does not belong to the current tenant.");
    }

    if (scopeKind == PermissionScopeKind.CustomerTenant && !await _appDb.Customers.AnyAsync(x => x.Id == scopeId && x.TenantId == tenantId, cancellationToken))
    {
      return (HttpResultErrorCode.BadRequest, "The selected customer does not belong to the current tenant.");
    }

    if (scopeKind == PermissionScopeKind.UserGroup && !await _appDb.UserGroups.AnyAsync(x => x.Id == scopeId && x.TenantId == tenantId, cancellationToken))
    {
      return (HttpResultErrorCode.BadRequest, "The selected user group does not belong to the current tenant.");
    }

    return null;
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
        .AnyAsync(x => x.Id == principalId &&
                       (x.Kind == ServiceAccountKind.Server ||
                        x.TenantId == tenantId && x.Kind == ServiceAccountKind.Tenant), cancellationToken),
      PermissionPrincipalKind.PersonalAccessToken => await _appDb.PersonalAccessTokens
        .AnyAsync(x => x.Id == principalId && x.User!.TenantId == tenantId, cancellationToken),
      PermissionPrincipalKind.LogonToken => await _appDb.LogonTokens
        .AnyAsync(x => x.Id == principalId && x.TenantId == tenantId, cancellationToken),
      _ => false
    };
  }
}
