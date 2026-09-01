using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.Extensions.Caching.Memory;
using ControlR.Web.Server.Constants;

namespace ControlR.Web.Server.Authn;

public class PersonalAccessTokenAuthenticationHandler(
  UrlEncoder encoder,
  UserManager<AppUser> userManager,
  ILoggerFactory logger,
  IPersonalAccessTokenManager personalAccessTokenManager,
  IMemoryCache memoryCache,
  IOptionsMonitor<PersonalAccessTokenAuthenticationSchemeOptions> options) : AuthenticationHandler<PersonalAccessTokenAuthenticationSchemeOptions>(options, logger, encoder)
{
  private const int MaxFailures = 5;

  private static readonly TimeSpan _failureWindow = TimeSpan.FromMinutes(5);

  private readonly IMemoryCache _failureCache = memoryCache;
  private readonly IPersonalAccessTokenManager _personalAccessTokenManager = personalAccessTokenManager;
  private readonly UserManager<AppUser> _userManager = userManager;

  protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
  {
    if (!Request.Headers.TryGetValue(Options.HeaderName, out var authHeaderValues))
    {
      return AuthenticateResult.NoResult();
    }

    var authHeader = authHeaderValues.FirstOrDefault();
    if (string.IsNullOrWhiteSpace(authHeader))
    {
      return AuthenticateResult.NoResult();
    }

    var providedPat = authHeader.Trim();
    if (string.IsNullOrWhiteSpace(providedPat))
    {
      return AuthenticateResult.NoResult();
    }

    // Two-axis throttling: independent limits per source IP and per token.
    // Combined (IP, token) keys would let an attacker rotate token IDs
    // from one IP to bypass the limit; independent keys per axis let each axis
    // catch its own attack pattern.
    var remoteIp = Context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    var tokenIdPrefix = providedPat.Split(':', 2).FirstOrDefault();
    // Normalize the token prefix to a bounded key space: only a valid GUID (the token ID)
    // becomes a distinct cache key; malformed/attacker-controlled prefixes collapse to a
    // single fixed key so they cannot plant unbounded cache entries.
    var tokenKeyPart = Guid.TryParse(tokenIdPrefix, out var tokenId)
      ? tokenId.ToString()
      : "invalid";
    var ipFailureKey = CacheKeys.GetPersonalAccessTokenAuthFailureByIp(remoteIp);
    var tokenFailureKey = CacheKeys.GetPersonalAccessTokenAuthFailureByToken(tokenKeyPart);

    if (_failureCache.TryGetValue<int>(ipFailureKey, out var ipFailures) && ipFailures >= MaxFailures)
    {
      return AuthenticateResult.Fail("Too many failed token attempts from this source. Try again later.");
    }

    if (_failureCache.TryGetValue<int>(tokenFailureKey, out var tokenFailures) && tokenFailures >= MaxFailures)
    {
      return AuthenticateResult.Fail("Too many failed attempts for this token. Try again later.");
    }

    var validationResult = await _personalAccessTokenManager.ValidateToken(providedPat);
    if (!validationResult.IsSuccess || !validationResult.Value.IsValid)
    {
      _failureCache.Set(ipFailureKey, ipFailures + 1, _failureWindow);
      _failureCache.Set(tokenFailureKey, tokenFailures + 1, _failureWindow);
      return AuthenticateResult.Fail("Invalid personal access token");
    }

    var result = validationResult.Value;

    // By ID, like the other authentication handlers.
    var user = await _userManager.FindByIdAsync(result.UserId.Value.ToString());
    if (user is null)
    {
      return AuthenticateResult.Fail("User not found for personal access token");
    }

    // Check lockout status
    if (await _userManager.IsLockedOutAsync(user))
    {
      return AuthenticateResult.Fail("User account is locked");
    }

    _failureCache.Remove(ipFailureKey);
    _failureCache.Remove(tokenFailureKey);

    var claims = new List<Claim>
    {
      new(UserClaimTypes.UserId, user.Id.ToString()),
      new(UserClaimTypes.TenantId, user.TenantId.ToString()),
      new(ClaimTypes.NameIdentifier, user.Id.ToString()),
      new(ClaimTypes.Name, user.UserName ?? "User"),
      new(UserClaimTypes.AuthenticationMethod, PrincipalClaimValues.PersonalAccessTokenMethod),
      new(PrincipalClaimTypes.PrincipalType, PrincipalClaimValues.User),
      new(PrincipalClaimTypes.PrincipalId, user.Id.ToString()),
      new(PrincipalClaimTypes.CredentialId, result.TokenId.Value.ToString()),
      new(PrincipalClaimTypes.CredentialType, PrincipalClaimValues.PersonalAccessTokenCredentialType),
    };

    if (!string.IsNullOrWhiteSpace(user.Email))
    {
      claims.Add(new Claim(ClaimTypes.Email, user.Email));
    }

    var identity = new ClaimsIdentity(claims, Scheme.Name);
    var principal = new ClaimsPrincipal(identity);
    var ticket = new AuthenticationTicket(principal, Scheme.Name);

    return AuthenticateResult.Success(ticket);
  }
}
