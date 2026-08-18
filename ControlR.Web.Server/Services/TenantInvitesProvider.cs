using ControlR.Libraries.Shared.Helpers;
using ControlR.Web.Client;
using ControlR.Web.Server.Data.Enums;
using ControlR.Web.Server.Primitives;
using ControlR.Web.Server.Services.Authorization;
using ControlR.Web.Server.Services.Users;

namespace ControlR.Web.Server.Services;

public interface ITenantInvitesProvider
{
  Task<HttpResult<InternalDtos.AcceptInvitationResponseDto>> AcceptInvite(
    InternalDtos.AcceptInvitationRequestDto dto);

  Task<HttpResult<InternalDtos.TenantInviteResponseDto>> CreateInvite(
    string inviteeEmail,
    Guid tenantId,
    Uri origin,
    CancellationToken cancellationToken = default);

  Task<HttpResult> DeleteInvite(
    Guid inviteId,
    Guid tenantId);

  Task<InternalDtos.TenantInviteResponseDto[]> GetAllInvites(
    Guid tenantId,
    Uri origin);
}

public class TenantInvitesProvider(
  IDbContextFactory<AppDb> dbContextFactory,
  UserManager<AppUser> userManager,
  IUserCreator userCreator,
  IAuthorizationChangeLogFactory changeLogFactory,
  ILogger<TenantInvitesProvider> logger) : ITenantInvitesProvider
{
  private readonly IAuthorizationChangeLogFactory _changeLogFactory = changeLogFactory;
  private readonly IDbContextFactory<AppDb> _dbContextFactory = dbContextFactory;
  private readonly ILogger<TenantInvitesProvider> _logger = logger;
  private readonly IUserCreator _userCreator = userCreator;
  private readonly UserManager<AppUser> _userManager = userManager;

  public async Task<HttpResult<InternalDtos.AcceptInvitationResponseDto>> AcceptInvite(
    InternalDtos.AcceptInvitationRequestDto dto)
  {
    _logger.LogInformation("Accepting invitation for email: {Email}", dto.Email);

    await using var appDb = await _dbContextFactory.CreateDbContextAsync();

    var normalizedEmail = dto.Email.Trim().ToLower();

    var invite = await appDb.TenantInvites
      .IgnoreQueryFilters()
      .FirstOrDefaultAsync(x =>
        x.ActivationCode == dto.ActivationCode &&
        x.InviteeEmail == normalizedEmail);

    if (invite is null)
    {
      _logger.LogWarning(
        "Invitation not found for activation code: {ActivationCode} and email: {Email}",
        dto.ActivationCode,
        normalizedEmail);
      return HttpResult.Fail<InternalDtos.AcceptInvitationResponseDto>(HttpResultErrorCode.NotFound, "Invitation not found.");
    }

    var invitee = await _userManager.FindByEmailAsync(dto.Email);
    if (invitee is null)
    {
      _logger.LogWarning("Invitee user account not found for email: {Email}", dto.Email);
      return HttpResult.Fail<InternalDtos.AcceptInvitationResponseDto>(HttpResultErrorCode.NotFound, "Invitee user account not found.");
    }

    var resetCode = await _userManager.GeneratePasswordResetTokenAsync(invitee);
    var idResult = await _userManager.ResetPasswordAsync(invitee, resetCode, dto.Password);
    if (!idResult.Succeeded)
    {
      foreach (var error in idResult.Errors)
      {
        _logger.LogWarning("Password reset error: {Code} - {Description}", error.Code, error.Description);
      }
      return HttpResult.Fail<InternalDtos.AcceptInvitationResponseDto>(HttpResultErrorCode.BadRequest, "Failed to set new password");
    }

    // Track the user entity so its tenant can be updated below.
    var trackedUser = await GetTrackedUser(appDb, invitee.Id);

    // Update tenant ID on the tracked entity
    trackedUser.TenantId = invite.TenantId;

    // The move invalidates the user's former-tenant authorization state: remove their
    // permission assignments and user-group memberships so no stale grants survive.
    // (The rule resolver's tenant-ownership boundary already keeps stale rows inert; this
    // cleanup removes the residue and records the removals in the change log.)
    var staleAssignments = await appDb.PermissionAssignments
      .IgnoreQueryFilters()
      .Where(x => x.PrincipalKind == PermissionPrincipalKind.User && x.PrincipalId == invitee.Id)
      .ToListAsync();

    foreach (var assignment in staleAssignments)
    {
      appDb.AuthorizationChangeLogs.Add(_changeLogFactory.Create(
        AuthorizationChangeLogActions.PermissionAssignmentDeleted,
        AuthorizationChangeLogActorTypes.System,
        actorPrincipalId: null,
        AuthorizationChangeLogTargetTypes.PermissionAssignment,
        assignment.Id,
        invite.TenantId,
        before: new PermissionAssignmentSnapshot(
          assignment.PermissionName, assignment.Effect, assignment.ScopeKind, assignment.ScopeId)));
    }

    appDb.PermissionAssignments.RemoveRange(staleAssignments);

    var staleMemberships = await appDb.UserGroupMembers
      .IgnoreQueryFilters()
      .Where(x => x.UserId == invitee.Id)
      .ToListAsync();
    appDb.UserGroupMembers.RemoveRange(staleMemberships);

    // The user's personal access tokens also carry scope rows keyed to the token principal,
    // tied to the former tenant. Remove them so no credential scope rows survive the move;
    // evaluation-time bounding would keep them inert, but this clears the residue (and the
    // pat-scope-trim scan) rather than leaving orphaned grants for a moved user's tokens.
    var stalePatTokenIds = appDb.PersonalAccessTokens
      .IgnoreQueryFilters()
      .Where(x => x.UserId == invitee.Id)
      .Select(x => x.Id);

    var stalePatScopeRows = await appDb.PermissionAssignments
      .IgnoreQueryFilters()
      .Where(x => x.PrincipalKind == PermissionPrincipalKind.PersonalAccessToken &&
                  stalePatTokenIds.Contains(x.PrincipalId))
      .ToListAsync();

    foreach (var assignment in stalePatScopeRows)
    {
      appDb.AuthorizationChangeLogs.Add(_changeLogFactory.Create(
        AuthorizationChangeLogActions.PermissionAssignmentDeleted,
        AuthorizationChangeLogActorTypes.System,
        actorPrincipalId: null,
        AuthorizationChangeLogTargetTypes.PermissionAssignment,
        assignment.Id,
        assignment.OwningTenantId,
        before: new PermissionAssignmentSnapshot(
          assignment.PermissionName, assignment.Effect, assignment.ScopeKind, assignment.ScopeId)));
    }

    appDb.PermissionAssignments.RemoveRange(stalePatScopeRows);

    appDb.TenantInvites.Remove(invite);
    await appDb.SaveChangesAsync();

    _logger.LogInformation(
      "User {UserId} moved to tenant {TenantId}: removed {AssignmentCount} assignment(s), {PatScopeCount} PAT scope row(s), and {MembershipCount} group membership(s).",
      invitee.Id, invite.TenantId, staleAssignments.Count, stalePatScopeRows.Count, staleMemberships.Count);

    var response = new InternalDtos.AcceptInvitationResponseDto(true);
    return HttpResult.Ok(response);
  }

  public async Task<HttpResult<InternalDtos.TenantInviteResponseDto>> CreateInvite(
    string inviteeEmail,
    Guid tenantId,
    Uri origin,
    CancellationToken cancellationToken = default)
  {
    var normalizedEmail = inviteeEmail.Trim().ToLower();

    await using var appDb = await _dbContextFactory.CreateDbContextAsync(cancellationToken);

    if (await appDb.TenantInvites.AnyAsync(x => x.InviteeEmail == normalizedEmail, cancellationToken: cancellationToken))
    {
      return HttpResult.Fail<InternalDtos.TenantInviteResponseDto>(HttpResultErrorCode.Conflict, "Invitee already has a pending invite.");
    }

#pragma warning disable CA1862 // Use the 'StringComparison' method overloads to perform case-insensitive string comparisons
    if (await appDb.Users.AnyAsync(x => x.Email!.ToLower() == normalizedEmail, cancellationToken: cancellationToken))
    {
      return HttpResult.Fail<InternalDtos.TenantInviteResponseDto>(HttpResultErrorCode.Conflict, "User already exists in the database.");
    }
#pragma warning restore CA1862 // Use the 'StringComparison' method overloads to perform case-insensitive string comparisons

    var randomPassword = RandomGenerator.GenerateString(64);
    var createResult = await _userCreator.CreateUser(
      inviteeEmail,
      password: randomPassword,
      tenantId: tenantId,
      cancellationToken: cancellationToken);

    if (!createResult.Succeeded)
    {
      var firstError = createResult.IdentityResult.Errors.FirstOrDefault();

      if (firstError is { Code: nameof(IdentityErrorDescriber.DuplicateUserName) })
      {
        return HttpResult.Fail<InternalDtos.TenantInviteResponseDto>(HttpResultErrorCode.Conflict, "User already exists.");
      }

      return HttpResult.Fail<InternalDtos.TenantInviteResponseDto>(HttpResultErrorCode.InternalServerError, "Failed to create user.");
    }

    var invite = new TenantInvite()
    {
      ActivationCode = RandomGenerator.GenerateString(64),
      InviteeEmail = normalizedEmail,
      TenantId = tenantId,
    };
    await appDb.TenantInvites.AddAsync(invite, cancellationToken);
    await appDb.SaveChangesAsync(cancellationToken);

    var inviteUrl = new Uri(origin, $"{ClientRoutes.InviteConfirmationBase}/{invite.ActivationCode}");
    var retDto = new InternalDtos.TenantInviteResponseDto(invite.Id, invite.CreatedAt, normalizedEmail, inviteUrl);
    return HttpResult.Ok(retDto);
  }

  public async Task<HttpResult> DeleteInvite(Guid inviteId, Guid tenantId)
  {
    await using var appDb = await _dbContextFactory.CreateDbContextAsync();

    var invite = await appDb.TenantInvites.FindAsync(inviteId);
    if (invite is null)
    {
      return HttpResult.Fail(HttpResultErrorCode.NotFound, "Invitation not found.");
    }

    if (invite.TenantId != tenantId)
    {
      return HttpResult.Fail(HttpResultErrorCode.Forbidden, "Invitation does not belong to the specified tenant.");
    }

    var user = await _userManager.FindByEmailAsync(invite.InviteeEmail);
    appDb.TenantInvites.Remove(invite);
    await appDb.SaveChangesAsync();

    if (user is not null)
    {
      await _userManager.DeleteAsync(user);
    }

    return HttpResult.Ok();
  }

  public async Task<InternalDtos.TenantInviteResponseDto[]> GetAllInvites(Guid tenantId, Uri origin)
  {
    await using var appDb = await _dbContextFactory.CreateDbContextAsync();

    return await appDb.TenantInvites
      .Where(x => x.TenantId == tenantId)
      .Select(x => new InternalDtos.TenantInviteResponseDto(
        x.Id,
        x.CreatedAt,
        x.InviteeEmail,
        new Uri(origin, $"{ClientRoutes.InviteConfirmationBase}/{x.ActivationCode}")))
      .ToArrayAsync();
  }

  private async Task<AppUser> GetTrackedUser(AppDb appDb, Guid userId)
  {
    var user = await appDb.Users
      .IgnoreQueryFilters()
      .FirstOrDefaultAsync(u => u.Id == userId);

    if (user is null)
    {
      throw new InvalidOperationException($"User with ID {userId} not found.");
    }

    return user;
  }
}
