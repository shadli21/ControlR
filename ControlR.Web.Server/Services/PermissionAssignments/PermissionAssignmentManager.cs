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
  Task<HttpResult<InternalDtos.PermissionAssignmentDto>> Create(
    InternalDtos.CreatePermissionAssignmentRequestDto request,
    Guid tenantId,
    Guid actorPrincipalId,
    CancellationToken cancellationToken = default,
    PermissionAssignmentAuthority authority = PermissionAssignmentAuthority.Tenant);
  Task<HttpResult> CreateMany(
    IReadOnlyList<InternalDtos.CreatePermissionAssignmentRequestDto> requests,
    Guid tenantId,
    Guid actorPrincipalId,
    CancellationToken cancellationToken = default,
    PermissionAssignmentAuthority authority = PermissionAssignmentAuthority.Tenant);
  Task<HttpResult> Delete(
    Guid assignmentId,
    Guid tenantId,
    Guid actorPrincipalId,
    CancellationToken cancellationToken = default,
    PermissionAssignmentAuthority authority = PermissionAssignmentAuthority.Tenant);
  Task<HttpResult<InternalDtos.DeleteManyPermissionAssignmentsResponseDto>> DeleteMany(
    IReadOnlyList<Guid> assignmentIds,
    Guid tenantId,
    Guid actorPrincipalId,
    CancellationToken cancellationToken = default,
    PermissionAssignmentAuthority authority = PermissionAssignmentAuthority.Tenant);
  Task<IReadOnlyList<InternalDtos.PermissionAssignmentDto>> GetByPrincipal(
    PermissionPrincipalKind principalKind,
    Guid principalId,
    Guid tenantId,
    Guid actorPrincipalId,
    CancellationToken cancellationToken = default,
    PermissionAssignmentAuthority authority = PermissionAssignmentAuthority.Tenant);
  /// <summary>
  /// Replaces a principal's assignments with the given set. Deletes every assignment visible
  /// to the actor, then creates the new ones; server-scoped permission holders therefore
  /// rewrite tenant-owned and server-scoped rows alike, while tenant actors rewrite only
  /// their own tenant's rows. All removals and creations are change-logged.
  /// </summary>
  Task<HttpResult> ReplaceForPrincipal(
    PermissionPrincipalKind principalKind,
    Guid principalId,
    Guid tenantId,
    Guid actorPrincipalId,
    IReadOnlyList<InternalDtos.CreatePermissionAssignmentRequestDto> assignments,
    CancellationToken cancellationToken = default,
    PermissionAssignmentAuthority authority = PermissionAssignmentAuthority.Tenant);
  Task<HttpResult<InternalDtos.PermissionAssignmentDto>> Update(
    Guid assignmentId,
    InternalDtos.UpdatePermissionAssignmentRequestDto request,
    Guid tenantId,
    Guid actorPrincipalId,
    CancellationToken cancellationToken = default,
    PermissionAssignmentAuthority authority = PermissionAssignmentAuthority.Tenant);
}

public class PermissionAssignmentManager(
  AppDb appDb,
  IPermissionEvaluator permissionEvaluator,
  ICredentialScopeService credentialScopeService) : IPermissionAssignmentManager
{
  private readonly AppDb _appDb = appDb;
  private readonly ICredentialScopeService _credentialScopeService = credentialScopeService;
  private readonly IPermissionEvaluator _permissionEvaluator = permissionEvaluator;

  public async Task<HttpResult<InternalDtos.PermissionAssignmentDto>> Create(
    InternalDtos.CreatePermissionAssignmentRequestDto request,
    Guid tenantId,
    Guid actorPrincipalId,
    CancellationToken cancellationToken = default,
    PermissionAssignmentAuthority authority = PermissionAssignmentAuthority.Tenant)
  {
    var principalExists = await ValidatePrincipalExists(
      request.PrincipalKind, request.PrincipalId, tenantId, authority, cancellationToken);
    if (!principalExists)
    {
      return HttpResult.Fail<InternalDtos.PermissionAssignmentDto>(
        HttpResultErrorCode.BadRequest, $"Principal not found: {request.PrincipalKind}/{request.PrincipalId}");
    }

    if (await ValidateWriteAuthority(request.Effect, request.ScopeKind, actorPrincipalId, tenantId, authority, cancellationToken) is { } authorityError)
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
      actorPrincipalId.ToString(),
      request.Effect,
      request.Notes);

    _appDb.PermissionAssignments.Add(assignment);

    await _appDb.SaveChangesAsync(cancellationToken);

    _appDb.AuthorizationChangeLogs.Add(AuthorizationChangeLogFactory.Create(
      AuthorizationChangeLogActions.PermissionAssignmentCreated,
      AuthorizationChangeLogActorTypes.User,
      actorPrincipalId,
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
    Guid actorPrincipalId,
    CancellationToken cancellationToken = default,
    PermissionAssignmentAuthority authority = PermissionAssignmentAuthority.Tenant)
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
      requests[0].PrincipalKind, requests[0].PrincipalId, tenantId, authority, cancellationToken);
    if (!principalExists)
    {
      return HttpResult.Fail(
        HttpResultErrorCode.BadRequest, $"Principal not found: {requests[0].PrincipalKind}/{requests[0].PrincipalId}");
    }

    foreach (var request in requests)
    {
      if (await ValidateWriteAuthority(request.Effect, request.ScopeKind, actorPrincipalId, tenantId, authority, cancellationToken) is { } authorityError)
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
        actorPrincipalId.ToString(),
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
        actorPrincipalId,
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
    Guid actorPrincipalId,
    CancellationToken cancellationToken = default,
    PermissionAssignmentAuthority authority = PermissionAssignmentAuthority.Tenant)
  {
    var assignment = await _appDb.PermissionAssignments
      .IgnoreQueryFilters()
      .FirstOrDefaultAsync(x => x.Id == assignmentId, cancellationToken);

    if (assignment is null)
    {
      return HttpResult.Fail(HttpResultErrorCode.NotFound, "Permission assignment not found.");
    }

    if (assignment.OwningTenantId != tenantId)
    {
      var actorHoldsServerPermission = authority == PermissionAssignmentAuthority.Server &&
          assignment.OwningTenantId is null;

      if (!IsVisibleToTenant(assignment, tenantId, actorHoldsServerPermission))
      {
        return HttpResult.Fail(HttpResultErrorCode.NotFound, "Permission assignment not found.");
      }
    }

    if (await ValidateWriteAuthority(assignment.Effect, assignment.ScopeKind, actorPrincipalId, tenantId, authority, cancellationToken) is { } authorityError)
    {
      return HttpResult.Fail(authorityError.Code, authorityError.Reason);
    }

    if (IsSelf(assignment, actorPrincipalId))
    {
      var grantedAfter = await _appDb.PermissionAssignments
        .IgnoreQueryFilters()
        .Where(x => x.PrincipalKind == PermissionPrincipalKind.User &&
                    x.PrincipalId == actorPrincipalId &&
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
      actorPrincipalId,
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
    Guid actorPrincipalId,
    CancellationToken cancellationToken = default,
    PermissionAssignmentAuthority authority = PermissionAssignmentAuthority.Tenant)
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

    var actorHoldsServerPermission = authority == PermissionAssignmentAuthority.Server &&
      foundAssignments.Any(x => x.OwningTenantId is null);

    var assignments = foundAssignments
      .Where(x => IsVisibleToTenant(x, tenantId, actorHoldsServerPermission))
      .ToList();

    foreach (var assignment in assignments)
    {
      if (await ValidateWriteAuthority(assignment.Effect, assignment.ScopeKind, actorPrincipalId, tenantId, authority, cancellationToken) is { } authorityError)
      {
        return HttpResult.Fail<InternalDtos.DeleteManyPermissionAssignmentsResponseDto>(authorityError.Code, authorityError.Reason);
      }
    }

    var foundIds = assignments.Select(x => x.Id).ToHashSet();
    var successIds = new List<Guid>(assignments.Count);
    var failureIds = assignmentIds.Except(foundIds).ToList();

    if (assignments.Any(x => IsSelf(x, actorPrincipalId)))
    {
      var grantedAfter = await _appDb.PermissionAssignments
        .IgnoreQueryFilters()
        .Where(x => x.PrincipalKind == PermissionPrincipalKind.User &&
                    x.PrincipalId == actorPrincipalId &&
                    !assignmentIds.Contains(x.Id) &&
                    x.Effect == PermissionEffect.Allow &&
                    x.IsEnabled)
        .Select(x => x.PermissionName)
        .ToListAsync(cancellationToken);

      var grantedBefore = new HashSet<string>(grantedAfter);
      foreach (var selfAssignment in assignments.Where(x => IsSelf(x, actorPrincipalId) && x.Effect == PermissionEffect.Allow && x.IsEnabled))
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
        actorPrincipalId,
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
    Guid actorPrincipalId,
    CancellationToken cancellationToken = default,
    PermissionAssignmentAuthority authority = PermissionAssignmentAuthority.Tenant)
  {
    var actorHoldsServerPermission = authority == PermissionAssignmentAuthority.Server;

    var assignments = await _appDb.PermissionAssignments
      .IgnoreQueryFilters()
      .Where(x => x.PrincipalKind == principalKind &&
                  x.PrincipalId == principalId &&
                  (x.OwningTenantId == tenantId ||
                  (actorHoldsServerPermission && x.OwningTenantId == null)))
      .OrderBy(x => x.PermissionName)
      .ThenBy(x => x.ScopeKind)
      .ToListAsync(cancellationToken);

    return [.. assignments.Select(MapToDto)];
  }

  public async Task<HttpResult> ReplaceForPrincipal(
    PermissionPrincipalKind principalKind,
    Guid principalId,
    Guid tenantId,
    Guid actorPrincipalId,
    IReadOnlyList<InternalDtos.CreatePermissionAssignmentRequestDto> assignments,
    CancellationToken cancellationToken = default,
    PermissionAssignmentAuthority authority = PermissionAssignmentAuthority.Tenant)
  {
    var principalExists = await ValidatePrincipalExists(principalKind, principalId, tenantId, authority, cancellationToken);
    if (!principalExists)
    {
      return HttpResult.Fail(
        HttpResultErrorCode.BadRequest, $"Principal not found: {principalKind}/{principalId}");
    }

    var actorHoldsServerPermission = authority == PermissionAssignmentAuthority.Server;

    foreach (var request in assignments)
    {
      if (await ValidateWriteAuthority(request.Effect, request.ScopeKind, actorPrincipalId, tenantId, authority, cancellationToken) is { } authorityError)
      {
        return HttpResult.Fail(authorityError.Code, authorityError.Reason);
      }
    }

    if (principalKind == PermissionPrincipalKind.User && principalId == actorPrincipalId)
    {
      var grantedBefore = await _appDb.PermissionAssignments
        .IgnoreQueryFilters()
        .Where(x => x.PrincipalKind == PermissionPrincipalKind.User &&
                    x.PrincipalId == actorPrincipalId &&
                    x.Effect == PermissionEffect.Allow &&
                    x.IsEnabled)
        .Select(x => x.PermissionName)
        .ToListAsync(cancellationToken);

      var grantedAfter = assignments
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

    foreach (var existingAssignment in existing.Where(x => IsVisibleToTenant(x, tenantId, actorHoldsServerPermission)))
    {
      _appDb.AuthorizationChangeLogs.Add(AuthorizationChangeLogFactory.Create(
        AuthorizationChangeLogActions.PermissionAssignmentDeleted,
        AuthorizationChangeLogActorTypes.User,
        actorPrincipalId,
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
        actorPrincipalId.ToString(),
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
        actorPrincipalId,
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
    Guid actorPrincipalId,
    CancellationToken cancellationToken = default,
    PermissionAssignmentAuthority authority = PermissionAssignmentAuthority.Tenant)
  {
    var assignment = await _appDb.PermissionAssignments
      .IgnoreQueryFilters()
      .FirstOrDefaultAsync(x => x.Id == assignmentId, cancellationToken);

    if (assignment is null)
    {
      return HttpResult.Fail<InternalDtos.PermissionAssignmentDto>(
        HttpResultErrorCode.NotFound, "Permission assignment not found.");
    }

    var actorHoldsServerPermission = authority == PermissionAssignmentAuthority.Server;

    if (!IsVisibleToTenant(assignment, tenantId, actorHoldsServerPermission))
    {
      return HttpResult.Fail<InternalDtos.PermissionAssignmentDto>(
        HttpResultErrorCode.NotFound, "Permission assignment not found.");
    }

    if (await ValidateWriteAuthority(request.Effect, request.ScopeKind, actorPrincipalId, tenantId, authority, cancellationToken) is { } authorityError)
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

    if (IsSelf(assignment, actorPrincipalId))
    {
      var others = await _appDb.PermissionAssignments
        .IgnoreQueryFilters()
        .Where(x => x.PrincipalKind == PermissionPrincipalKind.User &&
                    x.PrincipalId == actorPrincipalId &&
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
      actorPrincipalId,
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
  /// Tenant isolation: an assignment row is visible to a tenant actor when it is owned by
  /// their tenant, or when it is server-scoped (no owning tenant) and the actor holds
  /// server.permissions.write. Rows owned by other tenants are never visible.
  /// </summary>
  private static bool IsVisibleToTenant(PermissionAssignment assignment, Guid tenantId, bool actorHoldsServerPermission) =>
    assignment.OwningTenantId == tenantId || (assignment.OwningTenantId is null && actorHoldsServerPermission);

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

  private async Task<bool> ActorHoldsServerPermissionsWrite(
    Guid actorPrincipalId,
    Guid tenantId,
    CancellationToken cancellationToken)
  {
    var principal = new PrincipalDescriptor(
      PrincipalType: PrincipalClaimTypes.User,
      PrincipalId: actorPrincipalId,
      TenantId: tenantId,
      AuthMethod: "permission-assignment-management");

    var effectivePermissions = await _permissionEvaluator.GetEffectivePermissionNames(principal, cancellationToken);
    return effectivePermissions.Contains(PermissionNames.ServerPermissionsWrite);
  }

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
    PermissionAssignmentAuthority authority,
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
                       (authority == PermissionAssignmentAuthority.Server
                         ? x.Kind == ServiceAccountKind.Server
                         : x.TenantId == tenantId && x.Kind == ServiceAccountKind.Tenant), cancellationToken),
      PermissionPrincipalKind.PersonalAccessToken => await _appDb.PersonalAccessTokens
        .AnyAsync(x => x.Id == principalId && x.User!.TenantId == tenantId, cancellationToken),
      PermissionPrincipalKind.LogonToken => await _appDb.LogonTokens
        .AnyAsync(x => x.Id == principalId && x.TenantId == tenantId, cancellationToken),
      _ => false
    };
  }

  private async Task<(HttpResultErrorCode Code, string Reason)?> ValidateWriteAuthority(
    PermissionEffect effect,
    PermissionScopeKind scopeKind,
    Guid actorPrincipalId,
    Guid tenantId,
    PermissionAssignmentAuthority authority,
    CancellationToken cancellationToken)
  {
    if (authority == PermissionAssignmentAuthority.Server)
    {
      if (!await ActorHoldsServerPermissionsWrite(actorPrincipalId, tenantId, cancellationToken))
      {
        return (HttpResultErrorCode.Forbidden, "Server-scoped assignments can only be managed by a server permissions manager.");
      }

      return null;
    }

    if (scopeKind == PermissionScopeKind.Server)
    {
      return (HttpResultErrorCode.BadRequest, "Server-scoped assignments must be managed through the server permission assignments endpoint.");
    }

    if (effect == PermissionEffect.Allow)
    {
      return null;
    }

    var permission = PermissionNames.TenantPermissionsDeny;
    var principal = new PrincipalDescriptor(
      PrincipalType: PrincipalClaimTypes.User,
      PrincipalId: actorPrincipalId,
      TenantId: tenantId,
      AuthMethod: "permission-assignment-management");
    var effectivePermissions = await _permissionEvaluator.GetEffectivePermissionNames(principal, cancellationToken);
    if (!effectivePermissions.Contains(permission))
    {
      return (HttpResultErrorCode.Forbidden, $"The '{permission}' permission is required to manage {effect.ToString().ToLowerInvariant()} assignments.");
    }

    return null;
  }
}
