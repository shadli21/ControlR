using ControlR.Web.Server.Data.Enums;
using ControlR.Web.Server.Primitives;
using ControlR.Web.Server.Services.Authorization;

namespace ControlR.Web.Server.Services.UserGroups;

/// <summary>
/// Manages user groups: CRUD, membership add/remove, and cascade cleanup of
/// PermissionAssignment rows on group delete. All writes emit AuthorizationChangeLog entries.
/// </summary>
public interface IUserGroupManager
{
  Task<HttpResult> AddMembers(
    Guid userGroupId, List<Guid> userIds, Guid tenantId, Guid actorPrincipalId, CancellationToken cancellationToken = default);

  Task<HttpResult<InternalDtos.UserGroupDetailDto>> Create(
    string name, string? description, Guid tenantId, Guid actorPrincipalId, CancellationToken cancellationToken = default);

  Task<HttpResult> Delete(
    Guid userGroupId, Guid tenantId, Guid actorPrincipalId, CancellationToken cancellationToken = default);

  Task<HttpResult<InternalDtos.UserGroupDetailDto>> Get(
    Guid userGroupId, Guid tenantId, CancellationToken cancellationToken = default);

  Task<IReadOnlyList<InternalDtos.UserGroupDto>> GetAll(Guid tenantId, CancellationToken cancellationToken = default);

  Task<HttpResult> RemoveMembers(
    Guid userGroupId, List<Guid> userIds, Guid tenantId, Guid actorPrincipalId, CancellationToken cancellationToken = default);

  Task<HttpResult<InternalDtos.UserGroupDetailDto>> Update(
    Guid userGroupId, string name, string? description, Guid tenantId, Guid actorPrincipalId, CancellationToken cancellationToken = default);
}

public class UserGroupManager(AppDb appDb) : IUserGroupManager
{
  private readonly AppDb _appDb = appDb;

  public async Task<HttpResult> AddMembers(
    Guid userGroupId, List<Guid> userIds, Guid tenantId, Guid actorPrincipalId, CancellationToken cancellationToken = default)
  {
    var group = await _appDb.UserGroups
      .Include(x => x.Members)
      .FirstOrDefaultAsync(x => x.Id == userGroupId && x.TenantId == tenantId, cancellationToken);

    if (group is null)
    {
      return HttpResult.Fail(HttpResultErrorCode.NotFound, "User group not found.");
    }

    var existingUserIds = (group.Members ?? []).Select(m => m.UserId).ToHashSet();
    var newUserIds = userIds.Where(id => !existingUserIds.Contains(id)).ToList();

    if (newUserIds.Count == 0)
    {
      return HttpResult.Ok();
    }

    var validUserCount = await _appDb.Users
      .CountAsync(x => x.TenantId == tenantId && newUserIds.Contains(x.Id), cancellationToken);

    if (validUserCount != newUserIds.Count)
    {
      return HttpResult.Fail(HttpResultErrorCode.BadRequest, "One or more users were not found in this tenant.");
    }

    foreach (var userId in newUserIds)
    {
      _appDb.UserGroupMembers.Add(new UserGroupMember
      {
        UserGroupId = userGroupId,
        UserId = userId
      });
    }

    _appDb.AuthorizationChangeLogs.Add(AuthorizationChangeLogEntry.Create(
      AuthorizationChangeLogActions.UserGroupMembersAdded,
      AuthorizationChangeLogActorTypes.User,
      actorPrincipalId.ToString(),
      AuthorizationChangeLogTargetTypes.UserGroup,
      userGroupId.ToString(),
      tenantId,
      after: new UserGroupMembershipChange(newUserIds.Count)));

    await _appDb.SaveChangesAsync(cancellationToken);

    return HttpResult.Ok();
  }

  public async Task<HttpResult<InternalDtos.UserGroupDetailDto>> Create(
    string name, string? description, Guid tenantId, Guid actorPrincipalId, CancellationToken cancellationToken = default)
  {
    if (string.IsNullOrWhiteSpace(name))
    {
      return HttpResult.Fail<InternalDtos.UserGroupDetailDto>(HttpResultErrorCode.BadRequest, "Name is required.");
    }

    var nameConflict = await _appDb.UserGroups
      .AnyAsync(x => x.TenantId == tenantId && x.Name == name, cancellationToken);

    if (nameConflict)
    {
      return HttpResult.Fail<InternalDtos.UserGroupDetailDto>(HttpResultErrorCode.Conflict, "A user group with that name already exists.");
    }

    var group = new UserGroup
    {
      Name = name,
      Description = description,
      TenantId = tenantId,
      Members = []
    };

    _appDb.UserGroups.Add(group);

    _appDb.AuthorizationChangeLogs.Add(AuthorizationChangeLogEntry.Create(
      AuthorizationChangeLogActions.UserGroupCreated,
      AuthorizationChangeLogActorTypes.User,
      actorPrincipalId.ToString(),
      AuthorizationChangeLogTargetTypes.UserGroup,
      group.Id.ToString(),
      tenantId,
      after: new UserGroupSnapshot(name, description)));

    await _appDb.SaveChangesAsync(cancellationToken);

    return HttpResult.Ok(await MapToDetailDto(group, cancellationToken));
  }

  public async Task<HttpResult> Delete(
    Guid userGroupId, Guid tenantId, Guid actorPrincipalId, CancellationToken cancellationToken = default)
  {
    var group = await _appDb.UserGroups
      .Include(x => x.Members)
      .FirstOrDefaultAsync(x => x.Id == userGroupId && x.TenantId == tenantId, cancellationToken);

    if (group is null)
    {
      return HttpResult.Fail(HttpResultErrorCode.NotFound, "User group not found.");
    }

    // Cascade: remove PermissionAssignment rows where this user group is the principal.
    var principalAssignments = await _appDb.PermissionAssignments
      .IgnoreQueryFilters()
      .Where(x => x.PrincipalKind == PermissionPrincipalKind.UserGroup && x.PrincipalId == userGroupId)
      .ToListAsync(cancellationToken);

    _appDb.PermissionAssignments.RemoveRange(principalAssignments);

    _appDb.UserGroupMembers.RemoveRange(group.Members ?? []);

    _appDb.AuthorizationChangeLogs.Add(AuthorizationChangeLogEntry.Create(
      AuthorizationChangeLogActions.UserGroupDeleted,
      AuthorizationChangeLogActorTypes.User,
      actorPrincipalId.ToString(),
      AuthorizationChangeLogTargetTypes.UserGroup,
      userGroupId.ToString(),
      tenantId,
      before: new UserGroupSnapshot(group.Name, group.Description)));

    _appDb.UserGroups.Remove(group);
    await _appDb.SaveChangesAsync(cancellationToken);

    return HttpResult.Ok();
  }

  public async Task<HttpResult<InternalDtos.UserGroupDetailDto>> Get(
    Guid userGroupId, Guid tenantId, CancellationToken cancellationToken = default)
  {
    var group = await _appDb.UserGroups
      .Include(x => x.Members!)
        .ThenInclude(m => m.User)
      .FirstOrDefaultAsync(x => x.Id == userGroupId && x.TenantId == tenantId, cancellationToken);

    if (group is null)
    {
      return HttpResult.Fail<InternalDtos.UserGroupDetailDto>(HttpResultErrorCode.NotFound, "User group not found.");
    }

    return HttpResult.Ok(await MapToDetailDto(group, cancellationToken));
  }

  public async Task<IReadOnlyList<InternalDtos.UserGroupDto>> GetAll(Guid tenantId, CancellationToken cancellationToken = default)
  {
    var groups = await _appDb.UserGroups
      .Where(x => x.TenantId == tenantId)
      .Include(x => x.Members)
      .AsNoTracking()
      .OrderBy(x => x.Name)
      .ToListAsync(cancellationToken);

    return [.. groups.Select(g => new InternalDtos.UserGroupDto(
      g.Id, g.Name, g.Description, g.CreatedAt, g.Members?.Count ?? 0))];
  }

  public async Task<HttpResult> RemoveMembers(
    Guid userGroupId, List<Guid> userIds, Guid tenantId, Guid actorPrincipalId, CancellationToken cancellationToken = default)
  {
    var group = await _appDb.UserGroups
      .Include(x => x.Members)
      .FirstOrDefaultAsync(x => x.Id == userGroupId && x.TenantId == tenantId, cancellationToken);

    if (group is null)
    {
      return HttpResult.Fail(HttpResultErrorCode.NotFound, "User group not found.");
    }

    var membersToRemove = (group.Members ?? [])
      .Where(m => userIds.Contains(m.UserId))
      .ToList();

    if (membersToRemove.Count == 0)
    {
      return HttpResult.Ok();
    }

    _appDb.UserGroupMembers.RemoveRange(membersToRemove);

    _appDb.AuthorizationChangeLogs.Add(AuthorizationChangeLogEntry.Create(
      AuthorizationChangeLogActions.UserGroupMembersRemoved,
      AuthorizationChangeLogActorTypes.User,
      actorPrincipalId.ToString(),
      AuthorizationChangeLogTargetTypes.UserGroup,
      userGroupId.ToString(),
      tenantId,
      after: new UserGroupMembershipChange(membersToRemove.Count)));

    await _appDb.SaveChangesAsync(cancellationToken);

    return HttpResult.Ok();
  }

  public async Task<HttpResult<InternalDtos.UserGroupDetailDto>> Update(
    Guid userGroupId, string name, string? description, Guid tenantId, Guid actorPrincipalId, CancellationToken cancellationToken = default)
  {
    if (string.IsNullOrWhiteSpace(name))
    {
      return HttpResult.Fail<InternalDtos.UserGroupDetailDto>(HttpResultErrorCode.BadRequest, "Name is required.");
    }

    var group = await _appDb.UserGroups
      .Include(x => x.Members!)
        .ThenInclude(m => m.User)
      .FirstOrDefaultAsync(x => x.Id == userGroupId && x.TenantId == tenantId, cancellationToken);

    if (group is null)
    {
      return HttpResult.Fail<InternalDtos.UserGroupDetailDto>(HttpResultErrorCode.NotFound, "User group not found.");
    }

    var nameConflict = await _appDb.UserGroups
      .AnyAsync(x => x.TenantId == tenantId && x.Name == name && x.Id != userGroupId, cancellationToken);

    if (nameConflict)
    {
      return HttpResult.Fail<InternalDtos.UserGroupDetailDto>(HttpResultErrorCode.Conflict, "A user group with that name already exists.");
    }

    var before = new UserGroupSnapshot(group.Name, group.Description);

    group.Name = name;
    group.Description = description;

    _appDb.AuthorizationChangeLogs.Add(AuthorizationChangeLogEntry.Create(
      AuthorizationChangeLogActions.UserGroupUpdated,
      AuthorizationChangeLogActorTypes.User,
      actorPrincipalId.ToString(),
      AuthorizationChangeLogTargetTypes.UserGroup,
      userGroupId.ToString(),
      tenantId,
      before: before,
      after: new UserGroupSnapshot(name, description)));

    await _appDb.SaveChangesAsync(cancellationToken);

    return HttpResult.Ok(await MapToDetailDto(group, cancellationToken));
  }

  private async Task<InternalDtos.UserGroupDetailDto> MapToDetailDto(UserGroup group, CancellationToken cancellationToken)
  {
    var members = (group.Members ?? []).OrderBy(m => m.User?.UserName ?? string.Empty).ToList();

    var memberIds = members.Select(m => m.UserId).ToList();

    var displayNames = await _appDb.UserPreferences
      .Where(x => memberIds.Contains(x.UserId) && x.Name == UserPreferenceNames.UserDisplayName)
      .Select(x => new { x.UserId, x.Value })
      .ToListAsync(cancellationToken);

    var displayNamesLookup = displayNames.ToDictionary(x => x.UserId, x => x.Value);

    var memberDtos = members
      .Select(m => new InternalDtos.UserGroupMemberDto(
        m.UserId,
        m.User?.UserName ?? string.Empty,
        displayNamesLookup.GetValueOrDefault(m.UserId),
        m.User?.LastLogin))
      .ToList();

    return new InternalDtos.UserGroupDetailDto(
      group.Id, group.Name, group.Description, group.CreatedAt, memberDtos);
  }
}
