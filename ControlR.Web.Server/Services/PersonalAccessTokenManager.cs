using ControlR.Libraries.Shared.Helpers;
using ControlR.Web.Server.Data.Enums;
using ControlR.Web.Server.Services.Authorization;

namespace ControlR.Web.Server.Services;

/// <summary>
/// Manages personal access tokens: creation, deletion, retrieval, update, validation,
/// and credential scope management.
/// </summary>
public interface IPersonalAccessTokenManager
{
  /// <summary>
  /// Creates a new personal access token with a randomly generated secret.
  /// Returns the created token and its plaintext secret value.
  /// </summary>
  /// <param name="request">The request containing the token name.</param>
  /// <param name="userId">The ID of the user who owns the token.</param>
  /// <returns>The created token and its plaintext secret, or a failure result.</returns>
  Task<Result<InternalDtos.CreatePersonalAccessTokenResponseDto>> CreateToken(InternalDtos.CreatePersonalAccessTokenRequestDto request, Guid userId);

  /// <summary>
  /// Creates a personal access token with a pre-specified secret and entity ID.
  /// Used for bootstrap scenarios where the token must be known ahead of time.
  /// The caller is responsible for logging the full token string.
  /// </summary>
  /// <param name="tokenId">The GUID to use as the token's ID.</param>
  /// <param name="secret">The plaintext secret to hash and store.</param>
  /// <param name="name">The display name for the token.</param>
  /// <param name="userId">The ID of the user who owns the token.</param>
  /// <returns>The created token, or a failure result.</returns>
  Task<Result<InternalDtos.PersonalAccessTokenResponseDto>> CreateTokenWithKey(Guid tokenId, string secret, string name, Guid userId);

  /// <summary>
  /// Deletes a personal access token.
  /// </summary>
  /// <param name="id">The ID of the token to delete.</param>
  /// <param name="userId">The ID of the user who owns the token.</param>
  /// <returns>A success or failure result.</returns>
  Task<Result> Delete(Guid id, Guid userId);

  /// <summary>
  /// Retrieves all personal access tokens for a user.
  /// </summary>
  /// <param name="userId">The ID of the user whose tokens to retrieve.</param>
  /// <returns>A collection of token DTOs.</returns>
  Task<IEnumerable<InternalDtos.PersonalAccessTokenResponseDto>> GetForUser(Guid userId);

  /// <summary>
  /// Retrieves the current scopes for a personal access token.
  /// </summary>
  Task<Result<IReadOnlyList<InternalDtos.CredentialScopeDto>>> GetScopes(Guid tokenId, Guid userId);

  /// <summary>
  /// Replaces the scopes on a personal access token. Validates that all
  /// requested scopes are within the owning user's effective permissions.
  /// Writes AuthorizationChangeLog entries for added and removed rows.
  /// </summary>
  Task<Result> SetScopes(Guid tokenId, Guid userId, List<InternalDtos.CredentialScopeDto> scopes);

  /// <summary>
  /// Updates a personal access token's name.
  /// </summary>
  /// <param name="id">The ID of the token to update.</param>
  /// <param name="request">The request containing the new name.</param>
  /// <param name="userId">The ID of the user who owns the token.</param>
  /// <returns>The updated token, or a failure result.</returns>
  Task<Result<InternalDtos.PersonalAccessTokenResponseDto>> Update(Guid id, InternalDtos.UpdatePersonalAccessTokenRequestDto request, Guid userId);

  /// <summary>
  /// Validates the provided personal access token and returns the associated user and tenant ID if valid.
  /// </summary>
  /// <param name="token">The personal access token to validate (format: {hex-guid}:{secret}).</param>
  /// <returns>The associated user and tenant ID if valid, otherwise an error.</returns>
  Task<Result<PersonalAccessTokenValidationResult>> ValidateToken(string token);
}

public class PersonalAccessTokenManager(
  AppDb appDb,
  TimeProvider timeProvider,
  IPasswordHasher<string> passwordHasher) : IPersonalAccessTokenManager
{
  private readonly AppDb _appDb = appDb;
  private readonly IPasswordHasher<string> _passwordHasher = passwordHasher;
  private readonly TimeProvider _timeProvider = timeProvider;

  public async Task<Result<InternalDtos.CreatePersonalAccessTokenResponseDto>> CreateToken(InternalDtos.CreatePersonalAccessTokenRequestDto request, Guid userId)
  {
    try
    {
      var plainTextKey = RandomGenerator.CreateApiKey();
      var hashedKey = _passwordHasher.HashPassword(string.Empty, plainTextKey);

      var personalAccessToken = new PersonalAccessToken
      {
        Name = request.Name,
        HashedKey = hashedKey,
        UserId = userId
      };

      _appDb.PersonalAccessTokens.Add(personalAccessToken);
      await _appDb.SaveChangesAsync();

      var hexId = Convert.ToHexString(personalAccessToken.Id.ToByteArray());
      var combinedKey = $"{hexId}:{plainTextKey}";
      var response = new InternalDtos.CreatePersonalAccessTokenResponseDto(MapToDto(personalAccessToken), combinedKey);
      return Result.Ok(response);
    }
    catch (Exception ex)
    {
      return Result.Fail<InternalDtos.CreatePersonalAccessTokenResponseDto>(ex, "Failed to create personal access token.");
    }
  }

  public async Task<Result<InternalDtos.PersonalAccessTokenResponseDto>> CreateTokenWithKey(Guid tokenId, string secret, string name, Guid userId)
  {
    if (tokenId == Guid.Empty)
    {
      return Result.Fail<InternalDtos.PersonalAccessTokenResponseDto>("Token ID cannot be empty.");
    }

    if (string.IsNullOrWhiteSpace(secret))
    {
      return Result.Fail<InternalDtos.PersonalAccessTokenResponseDto>("Secret cannot be empty.");
    }

    if (secret.Length < 32)
    {
      return Result.Fail<InternalDtos.PersonalAccessTokenResponseDto>("PAT secret must be at least 32 characters.");
    }

    try
    {
      var hashedKey = _passwordHasher.HashPassword(string.Empty, secret);
      var personalAccessToken = new PersonalAccessToken
      {
        Id = tokenId,
        Name = name,
        HashedKey = hashedKey,
        UserId = userId
      };

      _appDb.PersonalAccessTokens.Add(personalAccessToken);
      await _appDb.SaveChangesAsync();

      return Result.Ok(MapToDto(personalAccessToken));
    }
    catch (Exception ex)
    {
      return Result.Fail<InternalDtos.PersonalAccessTokenResponseDto>(ex, "Failed to create personal access token with pre-keyed secret.");
    }
  }

  public async Task<Result> Delete(Guid id, Guid userId)
  {
    try
    {
      var personalAccessToken = await _appDb.PersonalAccessTokens
        .IgnoreQueryFilters()
        .FirstOrDefaultAsync(x => x.Id == id && x.UserId == userId);

      if (personalAccessToken is null)
      {
        return Result.Fail("Personal access token not found.");
      }

      _appDb.PersonalAccessTokens.Remove(personalAccessToken);
      await _appDb.SaveChangesAsync();

      return Result.Ok();
    }
    catch (Exception ex)
    {
      return Result.Fail(ex, "Failed to delete personal access token.");
    }
  }

  public async Task<IEnumerable<InternalDtos.PersonalAccessTokenResponseDto>> GetForUser(Guid userId)
  {
    var personalAccessTokens = await _appDb.PersonalAccessTokens
      .IgnoreQueryFilters()
      .Where(x => x.UserId == userId)
      .OrderByDescending(x => x.CreatedAt)
      .ToListAsync();

    return personalAccessTokens.Select(MapToDto);
  }

  public async Task<Result<IReadOnlyList<InternalDtos.CredentialScopeDto>>> GetScopes(Guid tokenId, Guid userId)
  {
    var tokenExists = await _appDb.PersonalAccessTokens
      .IgnoreQueryFilters()
      .AnyAsync(x => x.Id == tokenId && x.UserId == userId);

    if (!tokenExists)
    {
      return Result.Fail<IReadOnlyList<InternalDtos.CredentialScopeDto>>("Personal access token not found.");
    }

    var rows = await _appDb.PermissionAssignments
      .IgnoreQueryFilters()
      .Where(x => x.PrincipalKind == PermissionPrincipalKind.PersonalAccessToken &&
                  x.PrincipalId == tokenId &&
                  x.IsEnabled)
      .ToListAsync();

    var dtos = rows
      .Select(x => new InternalDtos.CredentialScopeDto(
        x.PermissionName, x.ScopeKind, x.ScopeId))
      .ToList();

    return Result.Ok<IReadOnlyList<InternalDtos.CredentialScopeDto>>(dtos);
  }

  public async Task<Result> SetScopes(Guid tokenId, Guid userId, List<InternalDtos.CredentialScopeDto> scopes)
  {
    var token = await _appDb.PersonalAccessTokens
      .IgnoreQueryFilters()
      .FirstOrDefaultAsync(x => x.Id == tokenId && x.UserId == userId);

    if (token is null)
    {
      return Result.Fail("Personal access token not found.");
    }

    var userEffectivePermissions = await ResolveUserEffectivePermissions(userId);

    var invalidScopes = scopes
      .Where(g => !userEffectivePermissions.Contains(g.PermissionName))
      .Select(g => g.PermissionName)
      .Distinct()
      .ToList();

    if (invalidScopes.Count > 0)
    {
      return Result.Fail(
        $"The following permissions are outside the user's effective permissions: {string.Join(", ", invalidScopes)}");
    }

    var existingRows = await _appDb.PermissionAssignments
      .IgnoreQueryFilters()
      .Where(x => x.PrincipalKind == PermissionPrincipalKind.PersonalAccessToken &&
                  x.PrincipalId == tokenId)
      .ToListAsync();

    var user = await _appDb.Users
      .IgnoreQueryFilters()
      .Where(x => x.Id == userId)
      .Select(x => new { x.TenantId })
      .FirstOrDefaultAsync();

    foreach (var row in existingRows)
    {
      _appDb.AuthorizationChangeLogs.Add(new AuthorizationChangeLog
      {
        ActionType = "credential-scope-removed",
        ActorPrincipalType = "user",
        ActorPrincipalId = userId.ToString(),
        TargetType = "PermissionAssignment",
        TargetId = row.Id.ToString(),
        OwningTenantId = user?.TenantId,
        BeforeJson = $"{{\"permission\":\"{row.PermissionName}\",\"scope\":\"{row.ScopeKind}\",\"scopeId\":\"{row.ScopeId}\"}}"
      });
    }

    _appDb.PermissionAssignments.RemoveRange(existingRows);

    foreach (var scope in scopes)
    {
      _appDb.PermissionAssignments.Add(new PermissionAssignment
      {
        PrincipalKind = PermissionPrincipalKind.PersonalAccessToken,
        PrincipalId = tokenId,
        PermissionName = scope.PermissionName,
        Effect = PermissionEffect.Allow,
        ScopeKind = scope.ScopeKind,
        ScopeId = scope.ScopeId,
        IsEnabled = true,
        OwningTenantId = user?.TenantId,
        CreatedByPrincipalType = "user",
        CreatedByPrincipalId = userId.ToString()
      });
    }

    if (scopes.Count > 0)
    {
      _appDb.AuthorizationChangeLogs.Add(new AuthorizationChangeLog
      {
        ActionType = "credential-scope-set",
        ActorPrincipalType = "user",
        ActorPrincipalId = userId.ToString(),
        TargetType = "PersonalAccessToken",
        TargetId = tokenId.ToString(),
        OwningTenantId = user?.TenantId,
        AfterJson = $"{{\"scopeCount\":{scopes.Count}}}"
      });
    }

    await _appDb.SaveChangesAsync();
    return Result.Ok();
  }

  public async Task<Result<InternalDtos.PersonalAccessTokenResponseDto>> Update(Guid id, InternalDtos.UpdatePersonalAccessTokenRequestDto request, Guid userId)
  {
    try
    {
      var personalAccessToken = await _appDb.PersonalAccessTokens
        .IgnoreQueryFilters()
        .FirstOrDefaultAsync(x => x.Id == id && x.UserId == userId);

      if (personalAccessToken is null)
      {
        return Result.Fail<InternalDtos.PersonalAccessTokenResponseDto>("Personal access token not found.");
      }

      personalAccessToken.Name = request.Name;
      await _appDb.SaveChangesAsync();

      return Result.Ok(MapToDto(personalAccessToken));
    }
    catch (Exception ex)
    {
      return Result.Fail<InternalDtos.PersonalAccessTokenResponseDto>(ex, "Failed to update personal access token.");
    }
  }

  public async Task<Result<PersonalAccessTokenValidationResult>> ValidateToken(string token)
  {
    try
    {
      var parts = token.Split(':', 2);
      if (parts.Length != 2)
      {
        return Result.Fail<PersonalAccessTokenValidationResult>("Invalid personal access token format.");
      }

      var tokenIdBytes = Convert.FromHexString(parts[0]);
      var tokenId = new Guid(tokenIdBytes);
      
      var storedToken = await _appDb.PersonalAccessTokens
        .IgnoreQueryFilters()
        .FirstOrDefaultAsync(x => x.Id == tokenId);

      if (storedToken is null)
      {
        return Result.Fail<PersonalAccessTokenValidationResult>("Invalid personal access token.");
      }

      var verification = _passwordHasher.VerifyHashedPassword(string.Empty, storedToken.HashedKey, parts[1]);

      if (verification == PasswordVerificationResult.Failed)
      {
        return Result.Fail<PersonalAccessTokenValidationResult>("Invalid personal access token.");
      }

      if (verification == PasswordVerificationResult.SuccessRehashNeeded)
      {
        storedToken.HashedKey = _passwordHasher.HashPassword(string.Empty, parts[1]);
      }

      // Update last used timestamp
      storedToken.LastUsed = _timeProvider.GetUtcNow();
      await _appDb.SaveChangesAsync();

      var result = PersonalAccessTokenValidationResult.Success(storedToken.Id, storedToken.UserId);
      return Result.Ok(result);
    }
    catch (Exception ex)
    {
      return Result.Fail<PersonalAccessTokenValidationResult>(ex, "Failed to validate personal access token.");
    }
  }

  private static InternalDtos.PersonalAccessTokenResponseDto MapToDto(PersonalAccessToken personalAccessToken)
  {
    return new InternalDtos.PersonalAccessTokenResponseDto(
      personalAccessToken.Id,
      personalAccessToken.Name,
      personalAccessToken.CreatedAt,
      personalAccessToken.LastUsed);
  }

  private async Task<HashSet<string>> ResolveUserEffectivePermissions(Guid userId)
  {
    var permissions = new HashSet<string>();

    var directAssignments = await _appDb.PermissionAssignments
      .IgnoreQueryFilters()
      .Where(x => x.PrincipalKind == PermissionPrincipalKind.User &&
                  x.PrincipalId == userId &&
                  x.IsEnabled &&
                  x.Effect == PermissionEffect.Allow)
      .Select(x => x.PermissionName)
      .ToListAsync();

    permissions.UnionWith(directAssignments);

    var userGroupIds = await _appDb.UserGroupMembers
      .IgnoreQueryFilters()
      .Where(x => x.UserId == userId)
      .Select(x => x.UserGroupId)
      .ToListAsync();

    if (userGroupIds.Count > 0)
    {
      var groupPermissions = await _appDb.PermissionAssignments
        .IgnoreQueryFilters()
        .Where(x => x.PrincipalKind == PermissionPrincipalKind.UserGroup &&
                    userGroupIds.Contains(x.PrincipalId) &&
                    x.IsEnabled &&
                    x.Effect == PermissionEffect.Allow)
        .Select(x => x.PermissionName)
        .ToListAsync();

      permissions.UnionWith(groupPermissions);
    }

    return permissions;
  }
}
