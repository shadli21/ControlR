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
    Guid actorPrincipalId,
    CancellationToken cancellationToken = default);
  /// <summary>
  /// Replaces a principal's assignments with the given set. Deletes every assignment visible
  /// to the actor, then creates the new ones; server.admin holders therefore rewrite
  /// tenant-owned and server-scoped rows alike, while tenant actors rewrite only their own
  /// tenant's rows. All removals and creations are change-logged.
  /// </summary>
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
    CancellationToken cancellationToken = default)
  {
    var principalExists = await ValidatePrincipalExists(request.PrincipalKind, request.PrincipalId, tenantId, cancellationToken);
    if (!principalExists)
    {
      return HttpResult.Fail<InternalDtos.PermissionAssignmentDto>(
        HttpResultErrorCode.BadRequest, $"Principal not found: {request.PrincipalKind}/{request.PrincipalId}");
    }

    if (request.ScopeKind == PermissionScopeKind.Server &&
        !await ActorHoldsServerAdmin(actorPrincipalId, tenantId, cancellationToken))
    {
      return HttpResult.Fail<InternalDtos.PermissionAssignmentDto>(
        HttpResultErrorCode.Forbidden, "Server-scoped assignments can only be granted by a server administrator.");
    }

    if (ValidatePermissionScope(request.PermissionName, request.ScopeKind, request.ScopeId) is { } scopeError)
    {
      return HttpResult.Fail<InternalDtos.PermissionAssignmentDto>(HttpResultErrorCode.BadRequest, scopeError);
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

    if (requests.Any(r => r.ScopeKind == PermissionScopeKind.Server) &&
        !await ActorHoldsServerAdmin(actorPrincipalId, tenantId, cancellationToken))
    {
      return HttpResult.Fail(
        HttpResultErrorCode.Forbidden, "Server-scoped assignments can only be granted by a server administrator.");
    }

    var created = new List<PermissionAssignment>(requests.Count);

    foreach (var request in requests)
    {
      if (ValidatePermissionScope(request.PermissionName, request.ScopeKind, request.ScopeId) is { } scopeError)
      {
        return HttpResult.Fail(HttpResultErrorCode.BadRequest, scopeError);
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

    if (assignment.OwningTenantId != tenantId)
    {
      var actorHoldsServerAdmin = assignment.OwningTenantId is null &&
          await ActorHoldsServerAdmin(actorPrincipalId, tenantId, cancellationToken);

      if (!IsVisibleToTenant(assignment, tenantId, actorHoldsServerAdmin))
      {
        return HttpResult.Fail(HttpResultErrorCode.NotFound, "Permission assignment not found.");
      }
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

    var foundAssignments = await _appDb.PermissionAssignments
      .IgnoreQueryFilters()
      .Where(x => assignmentIds.Contains(x.Id))
      .ToListAsync(cancellationToken);

    var actorHoldsServerAdmin = foundAssignments.Any(x => x.OwningTenantId is null) &&
        await ActorHoldsServerAdmin(actorPrincipalId, tenantId, cancellationToken);

    var assignments = foundAssignments
      .Where(x => IsVisibleToTenant(x, tenantId, actorHoldsServerAdmin))
      .ToList();

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
    Guid actorPrincipalId,
    CancellationToken cancellationToken = default)
  {
    var actorHoldsServerAdmin = await ActorHoldsServerAdmin(actorPrincipalId, tenantId, cancellationToken);

    var assignments = await _appDb.PermissionAssignments
      .IgnoreQueryFilters()
      .Where(x => x.PrincipalKind == principalKind &&
                  x.PrincipalId == principalId &&
                  (x.OwningTenantId == tenantId ||
                   (actorHoldsServerAdmin && x.OwningTenantId == null)))
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
    CancellationToken cancellationToken = default)
  {
    var principalExists = await ValidatePrincipalExists(principalKind, principalId, tenantId, cancellationToken);
    if (!principalExists)
    {
      return HttpResult.Fail(
        HttpResultErrorCode.BadRequest, $"Principal not found: {principalKind}/{principalId}");
    }

    var actorHoldsServerAdmin = await ActorHoldsServerAdmin(actorPrincipalId, tenantId, cancellationToken);

    if (assignments.Any(r => r.ScopeKind == PermissionScopeKind.Server) && !actorHoldsServerAdmin)
    {
      return HttpResult.Fail(
        HttpResultErrorCode.Forbidden, "Server-scoped assignments can only be granted by a server administrator.");
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

    foreach (var existingAssignment in existing.Where(x => IsVisibleToTenant(x, tenantId, actorHoldsServerAdmin)))
    {
      _appDb.AuthorizationChangeLogs.Add(AuthorizationChangeLogFactory.Create(
        AuthorizationChangeLogActions.PermissionAssignmentDeleted,
        AuthorizationChangeLogActorTypes.User,
        actorPrincipalId,
        AuthorizationChangeLogTargetTypes.PermissionAssignment,
        existingAssignment.Id,
        tenantId,
        before: new PermissionAssignmentSnapshot(
          existingAssignment.PermissionName, existingAssignment.Effect,
          existingAssignment.ScopeKind, existingAssignment.ScopeId)));

      _appDb.PermissionAssignments.Remove(existingAssignment);
    }

    var created = new List<PermissionAssignment>(assignments.Count);

    foreach (var request in assignments)
    {
      if (ValidatePermissionScope(request.PermissionName, request.ScopeKind, request.ScopeId) is { } scopeError)
      {
        return HttpResult.Fail(HttpResultErrorCode.BadRequest, scopeError);
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

    var actorHoldsServerAdmin = (assignment.OwningTenantId is null || request.ScopeKind == PermissionScopeKind.Server) &&
        await ActorHoldsServerAdmin(actorPrincipalId, tenantId, cancellationToken);

    if (!IsVisibleToTenant(assignment, tenantId, actorHoldsServerAdmin))
    {
      return HttpResult.Fail<InternalDtos.PermissionAssignmentDto>(
        HttpResultErrorCode.NotFound, "Permission assignment not found.");
    }

    if (request.ScopeKind == PermissionScopeKind.Server && !actorHoldsServerAdmin)
    {
      return HttpResult.Fail<InternalDtos.PermissionAssignmentDto>(
        HttpResultErrorCode.Forbidden, "Server-scoped assignments can only be modified by a server administrator.");
    }

    if (ValidatePermissionScope(request.PermissionName, request.ScopeKind, request.ScopeId) is { } scopeError)
    {
      return HttpResult.Fail<InternalDtos.PermissionAssignmentDto>(HttpResultErrorCode.BadRequest, scopeError);
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
      tenantId,
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
  /// server.admin. Rows owned by other tenants are never visible.
  /// </summary>
  private static bool IsVisibleToTenant(PermissionAssignment assignment, Guid tenantId, bool actorHoldsServerAdmin) =>
    assignment.OwningTenantId == tenantId || (assignment.OwningTenantId is null && actorHoldsServerAdmin);

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

  /// <summary>
  /// Validates that the permission exists in the catalog and that the requested scope kind is
  /// within its allowed whitelist. Returns a user-facing error message, or <see langword="null"/>
  /// when valid.
  /// </summary>
  private static string? ValidatePermissionScope(string permissionName, PermissionScopeKind scopeKind, Guid? scopeId)
  {
    var metadata = PermissionCatalog.Get(permissionName);
    if (metadata is null)
    {
      return $"Unknown permission name: {permissionName}";
    }

    if (metadata.AllowedScopeKinds is not { } allowed || !allowed.Contains(scopeKind))
    {
      return $"Permission '{metadata.DisplayName}' cannot be assigned at {scopeKind} scope.";
    }

    if (scopeKind is PermissionScopeKind.Device or PermissionScopeKind.DeviceGroup or PermissionScopeKind.CustomerTenant && !scopeId.HasValue)
    {
      return $"ScopeId is required for scope kind: {scopeKind}";
    }

    return null;
  }

  private async Task<bool> ActorHoldsServerAdmin(
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
    return effectivePermissions.Contains(PermissionNames.ServerAdmin);
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
        .AnyAsync(x => x.Id == principalId && x.TenantId == tenantId, cancellationToken),
      PermissionPrincipalKind.PersonalAccessToken => await _appDb.PersonalAccessTokens
        .AnyAsync(x => x.Id == principalId && x.User!.TenantId == tenantId, cancellationToken),
      PermissionPrincipalKind.LogonToken => await _appDb.LogonTokens
        .AnyAsync(x => x.Id == principalId && x.TenantId == tenantId, cancellationToken),
      _ => false
    };
  }
}
