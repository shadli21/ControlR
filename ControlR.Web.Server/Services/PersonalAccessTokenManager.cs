using ControlR.Libraries.Shared.Helpers;
using ControlR.Web.Server.Authn;
using ControlR.Web.Server.Authz.Permissions;
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
  IPasswordHasher<string> passwordHasher,
  ICredentialScopeService credentialScopeService,
  IAuthorizationChangeLogFactory changeLogFactory) : IPersonalAccessTokenManager
{
  private readonly AppDb _appDb = appDb;
  private readonly IAuthorizationChangeLogFactory _changeLogFactory = changeLogFactory;
  private readonly ICredentialScopeService _credentialScopeService = credentialScopeService;
  private readonly IPasswordHasher<string> _passwordHasher = passwordHasher;
  private readonly TimeProvider _timeProvider = timeProvider;

  public async Task<Result<InternalDtos.CreatePersonalAccessTokenResponseDto>> CreateToken(InternalDtos.CreatePersonalAccessTokenRequestDto request, Guid userId)
  {
    try
    {
      Guid? ownerTenantId = null;

      if (request.Scopes is { Count: > 0 })
      {
        var owner = await _appDb.Users
          .IgnoreQueryFilters()
          .AsNoTracking()
          .FirstOrDefaultAsync(x => x.Id == userId);
        if (owner is null || owner.TenantId == Guid.Empty)
        {
          return Result.Fail<InternalDtos.CreatePersonalAccessTokenResponseDto>("Token owner not found.");
        }

        ownerTenantId = owner.TenantId;

        var ownerPrincipal = new PrincipalDescriptor(
          PrincipalType: PrincipalClaimTypes.User,
          PrincipalId: userId,
          TenantId: owner.TenantId,
          AuthMethod: "pat-scope-validation");

        var scopeValidation = await _credentialScopeService.ValidateGrantableScopes(
          ownerPrincipal, owner.TenantId, request.Scopes);
        if (!scopeValidation.IsSuccess)
        {
          return Result.Fail<InternalDtos.CreatePersonalAccessTokenResponseDto>(scopeValidation.Reason);
        }
      }

      var plainTextKey = RandomGenerator.CreateApiKey();
      var hashedKey = _passwordHasher.HashPassword(string.Empty, plainTextKey);

      var personalAccessToken = new PersonalAccessToken
      {
        Name = request.Name,
        HashedKey = hashedKey,
        UserId = userId
      };

      _appDb.PersonalAccessTokens.Add(personalAccessToken);

      // Wrap the token, scope rows, and change log in a transaction (relational providers
      // only) so they commit atomically. The token Id is database-generated, so the scope
      // rows and change log can only reference it after the first save.
      await using var transaction = _appDb.Database.IsRelational()
        ? await _appDb.Database.BeginTransactionAsync()
        : null;

      await _appDb.SaveChangesAsync();

      var hasScopes = request.Scopes is { Count: > 0 };
      var tenantId = hasScopes ? ownerTenantId : null;

      if (hasScopes && tenantId is { } scopeTenantId)
      {
        foreach (var scope in request.Scopes!)
        {
          _appDb.PermissionAssignments.Add(PermissionAssignment.CreateGrant(
            PermissionPrincipalKind.PersonalAccessToken,
            personalAccessToken.Id,
            scope.PermissionName,
            scope.ScopeKind,
            scope.ScopeId,
            scopeTenantId,
            AuthorizationChangeLogActorTypes.User,
            userId.ToString()));
        }

        _appDb.AuthorizationChangeLogs.Add(_changeLogFactory.Create(
          AuthorizationChangeLogActions.CredentialScopeSet,
          AuthorizationChangeLogActorTypes.User,
          userId,
          AuthorizationChangeLogTargetTypes.PersonalAccessToken,
          personalAccessToken.Id,
          scopeTenantId,
          after: new CredentialScopeSetSummary(request.Scopes!.Count)));

        await _appDb.SaveChangesAsync();
      }

      if (transaction is not null)
      {
        await transaction.CommitAsync();
      }

      var hexId = Convert.ToHexString(personalAccessToken.Id.ToByteArray());
      var combinedKey = $"{hexId}:{plainTextKey}";
      var permissionCount = request.Scopes?.Select(x => x.PermissionName).Distinct().Count() ?? 0;
      var response = new InternalDtos.CreatePersonalAccessTokenResponseDto(MapToDto(personalAccessToken, permissionCount), combinedKey);
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

      return Result.Ok(MapToDto(personalAccessToken, 0));
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

    var tokenIds = personalAccessTokens.Select(x => x.Id).ToList();
    var permissionCountsByToken = await GetPermissionCountLookup(tokenIds);

    return personalAccessTokens
      .Select(x => MapToDto(x, permissionCountsByToken.GetValueOrDefault(x.Id)))
      .ToList();
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

      var permissionsLookup = await GetPermissionCountLookup([id]);
      return Result.Ok(MapToDto(personalAccessToken, permissionsLookup.GetValueOrDefault(id)));
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

      if (storedToken.RevokedAt is not null)
      {
        return Result.Fail<PersonalAccessTokenValidationResult>("Personal access token has been revoked.");
      }

      if (storedToken.ExpiresAt is not null && storedToken.ExpiresAt <= _timeProvider.GetUtcNow())
      {
        return Result.Fail<PersonalAccessTokenValidationResult>("Personal access token has expired.");
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

  private static InternalDtos.PersonalAccessTokenResponseDto MapToDto(
    PersonalAccessToken personalAccessToken,
    int permissionCount)
  {
    return new InternalDtos.PersonalAccessTokenResponseDto(
      personalAccessToken.Id,
      personalAccessToken.Name,
      personalAccessToken.CreatedAt,
      personalAccessToken.LastUsed,
      permissionCount);
  }

  private async Task<Dictionary<Guid, int>> GetPermissionCountLookup(IReadOnlyCollection<Guid> tokenIds)
  {
    if (tokenIds.Count == 0)
    {
      return [];
    }

    var counts = await _appDb.PermissionAssignments
      .Where(x => tokenIds.Contains(x.PrincipalId) &&
                  x.PrincipalKind == PermissionPrincipalKind.PersonalAccessToken &&
                  x.Effect == PermissionEffect.Allow &&
                  x.IsEnabled)
      .GroupBy(x => x.PrincipalId)
      .Select(g => new
      {
        g.Key,
        Count = g.Select(x => x.PermissionName).Distinct().Count()
      })
      .ToDictionaryAsync(x => x.Key, x => x.Count);

    return counts;
  }
}
