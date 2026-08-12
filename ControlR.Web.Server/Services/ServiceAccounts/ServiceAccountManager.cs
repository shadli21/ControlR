using ControlR.Libraries.Shared.Helpers;
using ControlR.Web.Server.Primitives;
using ControlR.Web.Server.Services.Authorization;
using Microsoft.Extensions.Caching.Memory;

namespace ControlR.Web.Server.Services.ServiceAccounts;

/// <summary>
/// Manages service accounts and their credentials: bootstrap from configuration,
/// CRUD for both server-scoped and tenant-scoped accounts, credential creation/revocation,
/// and credential validation for the service-account authentication handler.
/// Returns business-layer records; controllers map to API DTOs at the boundary.
/// </summary>
public interface IServiceAccountManager
{
  /// <summary>
  /// Adds a new credential to an existing server service account. Returns the credential
  /// metadata and the plaintext secret, which is only exposed this once. Emits AuthorizationChangeLog.
  /// A null <paramref name="expiresAt"/> creates a credential that never expires.
  /// </summary>
  Task<HttpResult<CreateServiceAccountCredentialResult>> AddCredentialForServer(
    Guid serviceAccountId, string name, DateTimeOffset? expiresAt, Guid actorPrincipalId, CancellationToken cancellationToken);

  /// <summary>
  /// Adds a new credential to a tenant-scoped service account. Emits AuthorizationChangeLog.
  /// A null <paramref name="expiresAt"/> creates a credential that never expires.
  /// </summary>
  Task<HttpResult<CreateServiceAccountCredentialResult>> AddCredentialForTenant(
    Guid serviceAccountId, Guid tenantId, string name, DateTimeOffset? expiresAt, Guid actorPrincipalId, CancellationToken cancellationToken);

  /// <summary>
  /// Creates the bootstrapped server service account and its initial credential when the
  /// bootstrap options are fully supplied. Skips creation when the named account already exists.
  /// Throws when the bootstrap input is only partially configured.
  /// </summary>
  Task<HttpResult> BootstrapServerServiceAccount(CancellationToken cancellationToken);

  /// <summary>
  /// Creates a new server-scoped service account. The account is created without any credential;
  /// issue one via <see cref="AddCredentialForServer"/>.
  /// </summary>
  Task<HttpResult<ServiceAccountResult>> CreateForServer(string name, string? description, CancellationToken cancellationToken);

  /// <summary>
  /// Creates a new tenant-scoped service account. The account is created without any credential;
  /// issue one via <see cref="AddCredentialForTenant"/>. Emits AuthorizationChangeLog.
  /// </summary>
  Task<HttpResult<ServiceAccountResult>> CreateForTenant(
    string name, string? description, Guid tenantId, Guid actorPrincipalId, CancellationToken cancellationToken);

  /// <summary>
  /// Deletes a server service account. Credentials cascade-delete. Emits AuthorizationChangeLog
  /// and removes orphaned PermissionAssignment rows where this account is the principal.
  /// </summary>
  Task<HttpResult> DeleteForServer(Guid serviceAccountId, Guid requestingPrincipalId, CancellationToken cancellationToken);

  /// <summary>
  /// Deletes a tenant-scoped service account. Emits AuthorizationChangeLog and removes
  /// orphaned PermissionAssignment rows where this account is the principal.
  /// </summary>
  Task<HttpResult> DeleteForTenant(Guid serviceAccountId, Guid tenantId, Guid requestingPrincipalId, CancellationToken cancellationToken);

  /// <summary>
  /// Returns all server-scoped service accounts with their credential metadata.
  /// </summary>
  Task<IReadOnlyList<ServiceAccountResult>> GetAllForServer(CancellationToken cancellationToken);

  /// <summary>
  /// Returns all tenant-scoped service accounts for a given tenant.
  /// </summary>
  Task<IReadOnlyList<ServiceAccountResult>> GetAllForTenant(Guid tenantId, CancellationToken cancellationToken);

  /// <summary>
  /// Returns a single server-scoped service account with its credential metadata.
  /// </summary>
  Task<HttpResult<ServiceAccountResult>> GetForServer(Guid serviceAccountId, CancellationToken cancellationToken);

  /// <summary>
  /// Returns a single tenant-scoped service account with its credential metadata.
  /// </summary>
  Task<HttpResult<ServiceAccountResult>> GetForTenant(Guid serviceAccountId, Guid tenantId, CancellationToken cancellationToken);

  /// <summary>
  /// Revokes a credential by setting <see cref="ServiceAccountCredential.RevokedAt"/>.
  /// Emits AuthorizationChangeLog.
  /// </summary>
  Task<HttpResult> RevokeCredential(
    Guid serviceAccountId, Guid credentialId, Guid actorPrincipalId, CancellationToken cancellationToken);

  /// <summary>
  /// Revokes a credential on a tenant-scoped service account. Emits AuthorizationChangeLog.
  /// </summary>
  Task<HttpResult> RevokeCredentialForTenant(
    Guid serviceAccountId, Guid credentialId, Guid tenantId, Guid actorPrincipalId, CancellationToken cancellationToken);

  /// <summary>
  /// Updates a server-scoped service account's name, description, and enabled state. Emits AuthorizationChangeLog.
  /// </summary>
  Task<HttpResult<ServiceAccountResult>> UpdateForServer(
    Guid serviceAccountId, string name, string? description, bool isEnabled, Guid actorPrincipalId, CancellationToken cancellationToken);

  /// <summary>
  /// Updates a tenant-scoped service account's name, description, and enabled state. Emits AuthorizationChangeLog.
  /// </summary>
  Task<HttpResult<ServiceAccountResult>> UpdateForTenant(
    Guid serviceAccountId, Guid tenantId, string name, string? description, bool isEnabled, Guid actorPrincipalId, CancellationToken cancellationToken);

  /// <summary>
  /// Validates a <c>{hex_id}:{plaintext_secret}</c> API key against a service account credential.
  /// On success updates <see cref="ServiceAccountCredential.LastUsedAt"/> and returns the
  /// owning service account and the credential. Revoked, expired, disabled-account, and
  /// nonexistent-or-invalid credentials all fail.
  /// </summary>
  Task<HttpResult<ServiceAccountCredentialValidationResult>> ValidateCredential(string apiKey, CancellationToken cancellationToken);
}

public sealed record ServiceAccountCredentialValidationResult(
  ServiceAccount ServiceAccount,
  ServiceAccountCredential Credential);

public class ServiceAccountManager(
  AppDb appDb,
  TimeProvider timeProvider,
  IPasswordHasher<string> passwordHasher,
  IMemoryCache memoryCache,
  IOptionsMonitor<BootstrapOptions> bootstrapOptions,
  ILogger<ServiceAccountManager> logger) : IServiceAccountManager
{
  private const string InvalidApiKeyFormatMessage = "Invalid service account API key format.";
  private const string InvalidCredentialMessage = "Invalid service account credential.";
  private const int MinimumSecretLength = 32;

  private static readonly TimeSpan _cacheExpiration = TimeSpan.FromSeconds(30);

  public async Task<HttpResult<CreateServiceAccountCredentialResult>> AddCredentialForServer(
    Guid serviceAccountId,
    string name,
    DateTimeOffset? expiresAt,
    Guid actorPrincipalId,
    CancellationToken cancellationToken)
  {
    if (string.IsNullOrWhiteSpace(name))
    {
      return HttpResult.Fail<CreateServiceAccountCredentialResult>(HttpResultErrorCode.BadRequest, "Credential name is required.");
    }

    if (!ValidateExpiration(expiresAt, out var expirationError))
    {
      return HttpResult.Fail<CreateServiceAccountCredentialResult>(HttpResultErrorCode.BadRequest, expirationError);
    }

    var account = await appDb.ServiceAccounts
      .Include(x => x.Credentials)
      .FirstOrDefaultAsync(x => x.Id == serviceAccountId && x.Kind == ServiceAccountKind.Server, cancellationToken);

    if (account is null)
    {
      return HttpResult.Fail<CreateServiceAccountCredentialResult>(HttpResultErrorCode.NotFound, "Server service account not found.");
    }

    if (!account.IsEnabled)
    {
      return HttpResult.Fail<CreateServiceAccountCredentialResult>(HttpResultErrorCode.Forbidden, "Service account is disabled.");
    }

    var plainTextSecret = RandomGenerator.CreateApiKey();
    var hashedSecret = passwordHasher.HashPassword(string.Empty, plainTextSecret);

    var credential = new ServiceAccountCredential
    {
      Name = name,
      HashedSecret = hashedSecret,
      ExpiresAt = expiresAt
    };
    account.Credentials.Add(credential);

    await appDb.SaveChangesAsync(cancellationToken);

    appDb.AuthorizationChangeLogs.Add(AuthorizationChangeLogFactory.Create(
      AuthorizationChangeLogActions.ServiceAccountCredentialCreated,
      AuthorizationChangeLogActorTypes.User,
      actorPrincipalId,
      AuthorizationChangeLogTargetTypes.ServiceAccountCredential,
      credential.Id,
      null,
      after: new ServiceAccountCredentialSnapshot(name, serviceAccountId)));

    await appDb.SaveChangesAsync(cancellationToken);

    var apiKey = FormatApiKey(credential.Id, plainTextSecret);
    return HttpResult.Ok(new CreateServiceAccountCredentialResult(MapCredentialToResult(credential), apiKey));
  }

  public async Task<HttpResult<CreateServiceAccountCredentialResult>> AddCredentialForTenant(
    Guid serviceAccountId,
    Guid tenantId,
    string name,
    DateTimeOffset? expiresAt,
    Guid actorPrincipalId,
    CancellationToken cancellationToken)
  {
    if (string.IsNullOrWhiteSpace(name))
    {
      return HttpResult.Fail<CreateServiceAccountCredentialResult>(HttpResultErrorCode.BadRequest, "Credential name is required.");
    }

    if (!ValidateExpiration(expiresAt, out var expirationError))
    {
      return HttpResult.Fail<CreateServiceAccountCredentialResult>(HttpResultErrorCode.BadRequest, expirationError);
    }

    var account = await appDb.ServiceAccounts
      .Include(x => x.Credentials)
      .FirstOrDefaultAsync(x => x.Id == serviceAccountId && x.Kind == ServiceAccountKind.Tenant && x.TenantId == tenantId, cancellationToken);

    if (account is null)
    {
      return HttpResult.Fail<CreateServiceAccountCredentialResult>(HttpResultErrorCode.NotFound, "Service account not found.");
    }

    if (!account.IsEnabled)
    {
      return HttpResult.Fail<CreateServiceAccountCredentialResult>(HttpResultErrorCode.Forbidden, "Service account is disabled.");
    }

    var plainTextSecret = RandomGenerator.CreateApiKey();
    var hashedSecret = passwordHasher.HashPassword(string.Empty, plainTextSecret);

    var credential = new ServiceAccountCredential
    {
      Name = name,
      HashedSecret = hashedSecret,
      ExpiresAt = expiresAt
    };
    account.Credentials.Add(credential);

    await appDb.SaveChangesAsync(cancellationToken);

    appDb.AuthorizationChangeLogs.Add(AuthorizationChangeLogFactory.Create(
      AuthorizationChangeLogActions.ServiceAccountCredentialCreated,
      AuthorizationChangeLogActorTypes.User,
      actorPrincipalId,
      AuthorizationChangeLogTargetTypes.ServiceAccountCredential,
      credential.Id,
      tenantId,
      after: new ServiceAccountCredentialSnapshot(name, serviceAccountId)));

    await appDb.SaveChangesAsync(cancellationToken);

    var apiKey = FormatApiKey(credential.Id, plainTextSecret);
    return HttpResult.Ok(new CreateServiceAccountCredentialResult(MapCredentialToResult(credential), apiKey));
  }

  public async Task<HttpResult> BootstrapServerServiceAccount(
    CancellationToken cancellationToken)
  {
    var name = bootstrapOptions.CurrentValue.ServerServiceAccountName;
    var tokenId = bootstrapOptions.CurrentValue.ServerServiceAccountTokenId;
    var secret = bootstrapOptions.CurrentValue.ServerServiceAccountTokenSecret;
    var description = bootstrapOptions.CurrentValue.ServerServiceAccountDescription;
    var accountId = bootstrapOptions.CurrentValue.ServerServiceAccountId;

    var nameSet = !string.IsNullOrWhiteSpace(name);
    var tokenIdSet = tokenId.HasValue;
    var secretSet = !string.IsNullOrWhiteSpace(secret);

    if (!nameSet && !tokenIdSet && !secretSet)
    {
      logger.LogInformation("Bootstrap server service account skipped: not configured.");
      return HttpResult.Ok();
    }

    // Any subset configured is a partial configuration error.
    if (!nameSet || !tokenIdSet || !secretSet)
    {
      logger.LogError(
        "Bootstrap server service account configuration incomplete. Name configured: {NameIsSet}, " +
        "TokenId configured: {TokenIdIsSet}, Secret configured: {SecretIsSet}. All three must be set.",
        nameSet,
        tokenIdSet,
        secretSet);
      throw new InvalidOperationException(
        "Bootstrap server service account configuration is incomplete: " +
        "ServerServiceAccountName, ServerServiceAccountTokenId, and ServerServiceAccountTokenSecret must all be configured.");
    }

    Guard.IsNotNull(name);
    Guard.IsNotNull(tokenId);
    Guard.IsNotNull(secret);

    var credentialId = tokenId.Value;

    if (secret.Length < MinimumSecretLength)
    {
      logger.LogError("Bootstrap server service account creation failed: ServerServiceAccountTokenSecret must be at least {Length} characters.", MinimumSecretLength);
      throw new InvalidOperationException($"Bootstrap server service account creation failed: ServerServiceAccountTokenSecret must be at least {MinimumSecretLength} characters.");
    }

    var alreadyExists = await appDb.ServiceAccounts
      .AnyAsync(x => x.Kind == ServiceAccountKind.Server && x.Name == name, cancellationToken);

    if (alreadyExists)
    {
      logger.LogInformation("Bootstrap server service account skipped: account '{Name}' already exists.", name);
      return HttpResult.Ok();
    }

    var account = new ServiceAccount
    {
      Kind = ServiceAccountKind.Server,
      TenantId = null,
      Name = name,
      Description = description,
      IsEnabled = true
    };

    if (accountId.HasValue)
    {
      account.Id = accountId.Value;
    }

    var hashedSecret = passwordHasher.HashPassword(string.Empty, secret);
    var credential = new ServiceAccountCredential
    {
      Id = credentialId,
      Name = "Bootstrap Credential",
      HashedSecret = hashedSecret
    };
    account.Credentials.Add(credential);

    appDb.ServiceAccounts.Add(account);
    await appDb.SaveChangesAsync(cancellationToken);

    // Log by credential id only, never the secret.
    logger.LogInformation(
      "Bootstrap server service account '{Name}' created with credential id {CredentialId}.",
      name,
      credential.Id);
    return HttpResult.Ok();
  }

  public async Task<HttpResult<ServiceAccountResult>> CreateForServer(
    string name,
    string? description,
    CancellationToken cancellationToken)
  {
    if (string.IsNullOrWhiteSpace(name))
    {
      return HttpResult.Fail<ServiceAccountResult>(HttpResultErrorCode.BadRequest, "Name is required.");
    }

    var nameConflict = await appDb.ServiceAccounts
      .AnyAsync(x => x.Kind == ServiceAccountKind.Server && x.Name == name, cancellationToken);
    if (nameConflict)
    {
      return HttpResult.Fail<ServiceAccountResult>(HttpResultErrorCode.Conflict, "A server service account with that name already exists.");
    }

    var account = new ServiceAccount
    {
      Kind = ServiceAccountKind.Server,
      TenantId = null,
      Name = name,
      Description = description,
      IsEnabled = true
    };

    appDb.ServiceAccounts.Add(account);

    var saveResult = await appDb.SaveChangesOrConfirmConflictAsync<ServiceAccount>(
      x => x.Kind == ServiceAccountKind.Server && x.Name == name,
      cancellationToken);

    if (saveResult == SaveChangesResult.ConflictDetected)
    {
      return HttpResult.Fail<ServiceAccountResult>(HttpResultErrorCode.Conflict, "A server service account with that name already exists.");
    }

    return HttpResult.Ok(MapToResult(account));
  }

  public async Task<HttpResult<ServiceAccountResult>> CreateForTenant(
    string name,
    string? description,
    Guid tenantId,
    Guid actorPrincipalId,
    CancellationToken cancellationToken)
  {
    if (string.IsNullOrWhiteSpace(name))
    {
      return HttpResult.Fail<ServiceAccountResult>(HttpResultErrorCode.BadRequest, "Name is required.");
    }

    var nameConflict = await appDb.ServiceAccounts
      .AnyAsync(x => x.Kind == ServiceAccountKind.Tenant && x.TenantId == tenantId && x.Name == name, cancellationToken);
    if (nameConflict)
    {
      return HttpResult.Fail<ServiceAccountResult>(HttpResultErrorCode.Conflict, "A service account with that name already exists in this tenant.");
    }

    var account = new ServiceAccount
    {
      Kind = ServiceAccountKind.Tenant,
      TenantId = tenantId,
      Name = name,
      Description = description,
      IsEnabled = true
    };

    appDb.ServiceAccounts.Add(account);

    var saveResult = await appDb.SaveChangesOrConfirmConflictAsync<ServiceAccount>(
      x => x.Kind == ServiceAccountKind.Tenant && x.TenantId == tenantId && x.Name == name,
      cancellationToken);

    if (saveResult == SaveChangesResult.ConflictDetected)
    {
      return HttpResult.Fail<ServiceAccountResult>(HttpResultErrorCode.Conflict, "A service account with that name already exists in this tenant.");
    }

    appDb.AuthorizationChangeLogs.Add(AuthorizationChangeLogFactory.Create(
      AuthorizationChangeLogActions.ServiceAccountCreated,
      AuthorizationChangeLogActorTypes.User,
      actorPrincipalId,
      AuthorizationChangeLogTargetTypes.ServiceAccount,
      account.Id,
      tenantId,
      after: new ServiceAccountSnapshot(name, ServiceAccountKind.Tenant, description, true)));

    await appDb.SaveChangesAsync(cancellationToken);

    return HttpResult.Ok(MapToResult(account));
  }

  public async Task<HttpResult> DeleteForServer(Guid serviceAccountId, Guid requestingPrincipalId, CancellationToken cancellationToken)
  {
    if (serviceAccountId.Equals(requestingPrincipalId))
    {
      return HttpResult.Fail(HttpResultErrorCode.Forbidden, "A service account cannot delete itself.");
    }

    var account = await appDb.ServiceAccounts
      .FirstOrDefaultAsync(x => x.Id == serviceAccountId && x.Kind == ServiceAccountKind.Server, cancellationToken);

    if (account is null)
    {
      return HttpResult.Fail(HttpResultErrorCode.NotFound, "Server service account not found.");
    }

    await EvictAccountFromCache(serviceAccountId, cancellationToken);

    // Cascade: remove PermissionAssignment rows where this service account is the principal.
    var principalAssignments = await appDb.PermissionAssignments
      .IgnoreQueryFilters()
      .Where(x => x.PrincipalKind == PermissionPrincipalKind.ServiceAccount && x.PrincipalId == serviceAccountId)
      .ToListAsync(cancellationToken);

    appDb.PermissionAssignments.RemoveRange(principalAssignments);

    appDb.AuthorizationChangeLogs.Add(AuthorizationChangeLogFactory.Create(
      AuthorizationChangeLogActions.ServiceAccountDeleted,
      AuthorizationChangeLogActorTypes.User,
      requestingPrincipalId,
      AuthorizationChangeLogTargetTypes.ServiceAccount,
      serviceAccountId,
      null,
      before: new ServiceAccountSnapshot(account.Name, ServiceAccountKind.Server, account.Description, account.IsEnabled)));

    appDb.ServiceAccounts.Remove(account);
    await appDb.SaveChangesAsync(cancellationToken);

    return HttpResult.Ok();
  }

  public async Task<HttpResult> DeleteForTenant(
    Guid serviceAccountId,
    Guid tenantId,
    Guid requestingPrincipalId,
    CancellationToken cancellationToken)
  {
    if (serviceAccountId.Equals(requestingPrincipalId))
    {
      return HttpResult.Fail(HttpResultErrorCode.Forbidden, "A service account cannot delete itself.");
    }

    var account = await appDb.ServiceAccounts
      .FirstOrDefaultAsync(x => x.Id == serviceAccountId && x.Kind == ServiceAccountKind.Tenant && x.TenantId == tenantId, cancellationToken);

    if (account is null)
    {
      return HttpResult.Fail(HttpResultErrorCode.NotFound, "Service account not found.");
    }

    await EvictAccountFromCache(serviceAccountId, cancellationToken);

    // Cascade: remove PermissionAssignment rows where this service account is the principal.
    var principalAssignments = await appDb.PermissionAssignments
      .IgnoreQueryFilters()
      .Where(x => x.PrincipalKind == PermissionPrincipalKind.ServiceAccount && x.PrincipalId == serviceAccountId)
      .ToListAsync(cancellationToken);

    appDb.PermissionAssignments.RemoveRange(principalAssignments);

    appDb.AuthorizationChangeLogs.Add(AuthorizationChangeLogFactory.Create(
      AuthorizationChangeLogActions.ServiceAccountDeleted,
      AuthorizationChangeLogActorTypes.User,
      requestingPrincipalId,
      AuthorizationChangeLogTargetTypes.ServiceAccount,
      serviceAccountId,
      tenantId,
      before: new ServiceAccountSnapshot(account.Name, ServiceAccountKind.Tenant, account.Description, account.IsEnabled)));

    appDb.ServiceAccounts.Remove(account);
    await appDb.SaveChangesAsync(cancellationToken);

    return HttpResult.Ok();
  }

  public async Task<IReadOnlyList<ServiceAccountResult>> GetAllForServer(CancellationToken cancellationToken)
  {
    var accounts = await appDb.ServiceAccounts
      .Where(x => x.Kind == ServiceAccountKind.Server)
      .Include(x => x.Credentials)
      .AsNoTracking()
      .OrderBy(x => x.Name)
      .ToListAsync(cancellationToken);

    return [.. accounts.Select(MapToResult)];
  }

  public async Task<IReadOnlyList<ServiceAccountResult>> GetAllForTenant(Guid tenantId, CancellationToken cancellationToken)
  {
    var accounts = await appDb.ServiceAccounts
      .Where(x => x.Kind == ServiceAccountKind.Tenant && x.TenantId == tenantId)
      .Include(x => x.Credentials)
      .AsNoTracking()
      .OrderBy(x => x.Name)
      .ToListAsync(cancellationToken);

    return [.. accounts.Select(MapToResult)];
  }

  public async Task<HttpResult<ServiceAccountResult>> GetForServer(
    Guid serviceAccountId,
    CancellationToken cancellationToken)
  {
    var account = await appDb.ServiceAccounts
      .Include(x => x.Credentials)
      .FirstOrDefaultAsync(x => x.Id == serviceAccountId && x.Kind == ServiceAccountKind.Server, cancellationToken);

    if (account is null)
    {
      return HttpResult.Fail<ServiceAccountResult>(HttpResultErrorCode.NotFound, "Server service account not found.");
    }

    return HttpResult.Ok(MapToResult(account));
  }

  public async Task<HttpResult<ServiceAccountResult>> GetForTenant(
    Guid serviceAccountId,
    Guid tenantId,
    CancellationToken cancellationToken)
  {
    var account = await appDb.ServiceAccounts
      .Include(x => x.Credentials)
      .FirstOrDefaultAsync(x => x.Id == serviceAccountId && x.Kind == ServiceAccountKind.Tenant && x.TenantId == tenantId, cancellationToken);

    if (account is null)
    {
      return HttpResult.Fail<ServiceAccountResult>(HttpResultErrorCode.NotFound, "Service account not found.");
    }

    return HttpResult.Ok(MapToResult(account));
  }

  public async Task<HttpResult> RevokeCredential(
    Guid serviceAccountId,
    Guid credentialId,
    Guid actorPrincipalId,
    CancellationToken cancellationToken)
  {
    var credential = await appDb.ServiceAccountCredentials
      .FirstOrDefaultAsync(
        x => x.Id == credentialId && x.ServiceAccountId == serviceAccountId,
        cancellationToken);

    if (credential is null)
    {
      return HttpResult.Fail(HttpResultErrorCode.NotFound, "Credential not found.");
    }

    if (credential.RevokedAt is not null)
    {
      return HttpResult.Ok();
    }

    credential.RevokedAt = timeProvider.GetUtcNow();

    appDb.AuthorizationChangeLogs.Add(AuthorizationChangeLogFactory.Create(
      AuthorizationChangeLogActions.ServiceAccountCredentialRevoked,
      AuthorizationChangeLogActorTypes.User,
      actorPrincipalId,
      AuthorizationChangeLogTargetTypes.ServiceAccountCredential,
      credentialId,
      null,
      before: new ServiceAccountCredentialSnapshot(credential.Name, serviceAccountId)));

    await appDb.SaveChangesAsync(cancellationToken);

    EvictCredentialFromCache(credentialId);
    return HttpResult.Ok();
  }

  public async Task<HttpResult> RevokeCredentialForTenant(
    Guid serviceAccountId,
    Guid credentialId,
    Guid tenantId,
    Guid actorPrincipalId,
    CancellationToken cancellationToken)
  {
    var credential = await appDb.ServiceAccountCredentials
      .Include(x => x.ServiceAccount)
      .FirstOrDefaultAsync(
        x => x.Id == credentialId &&
             x.ServiceAccountId == serviceAccountId &&
             x.ServiceAccount!.Kind == ServiceAccountKind.Tenant &&
             x.ServiceAccount.TenantId == tenantId,
        cancellationToken);

    if (credential is null)
    {
      return HttpResult.Fail(HttpResultErrorCode.NotFound, "Credential not found.");
    }

    if (credential.RevokedAt is not null)
    {
      return HttpResult.Ok();
    }

    credential.RevokedAt = timeProvider.GetUtcNow();

    appDb.AuthorizationChangeLogs.Add(AuthorizationChangeLogFactory.Create(
      AuthorizationChangeLogActions.ServiceAccountCredentialRevoked,
      AuthorizationChangeLogActorTypes.User,
      actorPrincipalId,
      AuthorizationChangeLogTargetTypes.ServiceAccountCredential,
      credentialId,
      tenantId,
      before: new ServiceAccountCredentialSnapshot(credential.Name, serviceAccountId)));

    await appDb.SaveChangesAsync(cancellationToken);

    EvictCredentialFromCache(credentialId);
    return HttpResult.Ok();
  }

  public async Task<HttpResult<ServiceAccountResult>> UpdateForServer(
    Guid serviceAccountId,
    string name,
    string? description,
    bool isEnabled,
    Guid actorPrincipalId,
    CancellationToken cancellationToken)
  {
    if (string.IsNullOrWhiteSpace(name))
    {
      return HttpResult.Fail<ServiceAccountResult>(HttpResultErrorCode.BadRequest, "Name is required.");
    }

    var account = await appDb.ServiceAccounts
      .Include(x => x.Credentials)
      .FirstOrDefaultAsync(x => x.Id == serviceAccountId && x.Kind == ServiceAccountKind.Server, cancellationToken);

    if (account is null)
    {
      return HttpResult.Fail<ServiceAccountResult>(HttpResultErrorCode.NotFound, "Server service account not found.");
    }

    var before = new ServiceAccountSnapshot(account.Name, ServiceAccountKind.Server, account.Description, account.IsEnabled);

    var isEnabledChanged = before.IsEnabled != isEnabled;

    account.Name = name;
    account.Description = description;
    account.IsEnabled = isEnabled;

    appDb.AuthorizationChangeLogs.Add(AuthorizationChangeLogFactory.Create(
      AuthorizationChangeLogActions.ServiceAccountUpdated,
      AuthorizationChangeLogActorTypes.User,
      actorPrincipalId,
      AuthorizationChangeLogTargetTypes.ServiceAccount,
      serviceAccountId,
      null,
      before: before,
      after: new ServiceAccountSnapshot(name, ServiceAccountKind.Server, description, isEnabled)));

    await appDb.SaveChangesAsync(cancellationToken);

    if (isEnabledChanged)
    {
      await EvictAccountFromCache(serviceAccountId, cancellationToken);
    }

    return HttpResult.Ok(MapToResult(account));
  }

  public async Task<HttpResult<ServiceAccountResult>> UpdateForTenant(
    Guid serviceAccountId,
    Guid tenantId,
    string name,
    string? description,
    bool isEnabled,
    Guid actorPrincipalId,
    CancellationToken cancellationToken)
  {
    if (string.IsNullOrWhiteSpace(name))
    {
      return HttpResult.Fail<ServiceAccountResult>(HttpResultErrorCode.BadRequest, "Name is required.");
    }

    var account = await appDb.ServiceAccounts
      .Include(x => x.Credentials)
      .FirstOrDefaultAsync(x => x.Id == serviceAccountId && x.Kind == ServiceAccountKind.Tenant && x.TenantId == tenantId, cancellationToken);

    if (account is null)
    {
      return HttpResult.Fail<ServiceAccountResult>(HttpResultErrorCode.NotFound, "Service account not found.");
    }

    var before = new ServiceAccountSnapshot(account.Name, ServiceAccountKind.Tenant, account.Description, account.IsEnabled);

    var isEnabledChanged = before.IsEnabled != isEnabled;

    account.Name = name;
    account.Description = description;
    account.IsEnabled = isEnabled;

    appDb.AuthorizationChangeLogs.Add(AuthorizationChangeLogFactory.Create(
      AuthorizationChangeLogActions.ServiceAccountUpdated,
      AuthorizationChangeLogActorTypes.User,
      actorPrincipalId,
      AuthorizationChangeLogTargetTypes.ServiceAccount,
      serviceAccountId,
      tenantId,
      before: before,
      after: new ServiceAccountSnapshot(name, ServiceAccountKind.Tenant, description, isEnabled)));

    await appDb.SaveChangesAsync(cancellationToken);

    if (isEnabledChanged)
    {
      await EvictAccountFromCache(serviceAccountId, cancellationToken);
    }

    return HttpResult.Ok(MapToResult(account));
  }

  public async Task<HttpResult<ServiceAccountCredentialValidationResult>> ValidateCredential(
    string apiKey,
    CancellationToken cancellationToken)
  {
    var parts = apiKey.Split(':', 2);
    if (parts.Length != 2)
    {
      return HttpResult.Fail<ServiceAccountCredentialValidationResult>(HttpResultErrorCode.BadRequest, InvalidApiKeyFormatMessage);
    }

    // The header id is the credential Guid rendered via Convert.ToHexString on the
    // Guid's byte array. Reconstruct the Guid from the hex bytes rather than Guid.TryParse.
    Guid credentialId;
    try
    {
      var idBytes = Convert.FromHexString(parts[0]);
      credentialId = new Guid(idBytes);
    }
    catch
    {
      return HttpResult.Fail<ServiceAccountCredentialValidationResult>(HttpResultErrorCode.BadRequest, InvalidApiKeyFormatMessage);
    }

    if (credentialId == Guid.Empty)
    {
      return HttpResult.Fail<ServiceAccountCredentialValidationResult>(HttpResultErrorCode.BadRequest, InvalidApiKeyFormatMessage);
    }

    if (memoryCache.TryGetValue<ServiceAccountCredentialValidationResult>(credentialId, out var cachedResult) && cachedResult is not null)
    {
      var now = timeProvider.GetUtcNow();

      // A credential whose ExpiresAt falls inside the cache window would otherwise keep
      // authenticating for up to the remaining TTL. Re-check and, if expired, evict and
      // fall through to a fresh validation that will reject it.
      if (cachedResult.Credential.ExpiresAt is not null && cachedResult.Credential.ExpiresAt <= now)
      {
        EvictCredentialFromCache(credentialId);
      }
      else
      {
        cachedResult.Credential.LastUsedAt = now;
        await PersistLastUsedAt(credentialId, now, cancellationToken);

        return HttpResult.Ok(cachedResult);
      }
    }

    var credential = await appDb.ServiceAccountCredentials
      .IgnoreQueryFilters()
      .Include(x => x.ServiceAccount)
      .FirstOrDefaultAsync(x => x.Id == credentialId, cancellationToken);

    if (credential is null)
    {
      return HttpResult.Fail<ServiceAccountCredentialValidationResult>(HttpResultErrorCode.Unauthorized, InvalidCredentialMessage);
    }

    var account = credential.ServiceAccount;
    if (account is null || !account.IsEnabled)
    {
      return HttpResult.Fail<ServiceAccountCredentialValidationResult>(HttpResultErrorCode.Forbidden, "Service account is not available.");
    }

    if (credential.RevokedAt is not null)
    {
      return HttpResult.Fail<ServiceAccountCredentialValidationResult>(HttpResultErrorCode.Unauthorized, "Service account credential has been revoked.");
    }

    if (credential.ExpiresAt is not null && credential.ExpiresAt <= timeProvider.GetUtcNow())
    {
      return HttpResult.Fail<ServiceAccountCredentialValidationResult>(HttpResultErrorCode.Unauthorized, "Service account credential has expired.");
    }

    var verification = passwordHasher.VerifyHashedPassword(string.Empty, credential.HashedSecret, parts[1]);
    if (verification == PasswordVerificationResult.Failed)
    {
      return HttpResult.Fail<ServiceAccountCredentialValidationResult>(HttpResultErrorCode.Unauthorized, InvalidCredentialMessage);
    }

    if (verification == PasswordVerificationResult.SuccessRehashNeeded)
    {
      credential.HashedSecret = passwordHasher.HashPassword(string.Empty, parts[1]);
    }

    credential.LastUsedAt = timeProvider.GetUtcNow();
    await appDb.SaveChangesAsync(cancellationToken);

    appDb.Entry(account).State = EntityState.Detached;
    appDb.Entry(credential).State = EntityState.Detached;

    var validationResult = new ServiceAccountCredentialValidationResult(account, credential);
    memoryCache.Set(credentialId, validationResult, _cacheExpiration);

    return HttpResult.Ok(validationResult);
  }

  private static string FormatApiKey(Guid credentialId, string plainTextSecret)
  {
    var hexId = Convert.ToHexString(credentialId.ToByteArray());
    return $"{hexId}:{plainTextSecret}";
  }

  private static ServiceAccountCredentialResult MapCredentialToResult(ServiceAccountCredential credential)
  {
    return new ServiceAccountCredentialResult(
      credential.Id,
      credential.Name,
      credential.CreatedAt,
      credential.ExpiresAt,
      credential.RevokedAt,
      credential.LastUsedAt);
  }

  private static ServiceAccountResult MapToResult(ServiceAccount account)
  {
    return new ServiceAccountResult(
      account.Id,
      account.Name,
      account.Description,
      account.Kind,
      account.IsEnabled,
      account.CreatedAt,
      account.Credentials
        .OrderBy(c => c.CreatedAt)
        .ThenBy(c => c.Id)
        .Select(MapCredentialToResult)
        .ToList());
  }

  private async Task EvictAccountFromCache(Guid serviceAccountId, CancellationToken cancellationToken)
  {
    try
    {
      var account = await appDb.ServiceAccounts
        .AsNoTracking()
        .Include(x => x.Credentials)
        .FirstOrDefaultAsync(x => x.Id == serviceAccountId, cancellationToken);
        
      if (account != null)
      {
        foreach (var cred in account.Credentials)
        {
          memoryCache.Remove(cred.Id);
        }
      }
    }
    catch (Exception ex) when (ex is not OperationCanceledException)
    {
      logger.LogWarning(ex, "Failed to evict cached credential validation results for account {AccountId}.", serviceAccountId);
    }
  }

  private void EvictCredentialFromCache(Guid credentialId)
  {
    memoryCache.Remove(credentialId);
  }

  private async Task PersistLastUsedAt(Guid credentialId, DateTimeOffset now, CancellationToken cancellationToken)
  {
    if (appDb.Database.IsRelational())
    {
      await appDb.ServiceAccountCredentials
        .Where(x => x.Id == credentialId)
        .ExecuteUpdateAsync(x => x.SetProperty(p => p.LastUsedAt, now), cancellationToken);
      return;
    }

    // The EF Core in-memory provider (used by the test suite) does not support
    // ExecuteUpdate. Fall back to a tracked update so service-account auth
    // continues to persist LastUsedAt in tests.
    var credential = await appDb.ServiceAccountCredentials
      .FirstOrDefaultAsync(x => x.Id == credentialId, cancellationToken);
    if (credential is null)
    {
      return;
    }
    credential.LastUsedAt = now;
    await appDb.SaveChangesAsync(cancellationToken);
  }

  private bool ValidateExpiration(DateTimeOffset? expiresAt, out string error)
  {
    error = string.Empty;
    if (expiresAt is null)
    {
      return true;
    }

    if (expiresAt <= timeProvider.GetUtcNow())
    {
      error = "Credential expiration must be in the future.";
      return false;
    }

    return true;
  }
}
