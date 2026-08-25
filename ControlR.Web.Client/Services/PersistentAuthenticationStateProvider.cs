using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;

namespace ControlR.Web.Client.Services;

// Reads authentication state persisted by the server at render time. Fixed for the WASM
// lifetime, so log in/out requires a full page reload.
internal class PersistentAuthenticationStateProvider : AuthenticationStateProvider
{
  private static readonly Task<AuthenticationState> _defaultUnauthenticatedTask =
    Task.FromResult(new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity())));

  private readonly Task<AuthenticationState> _authenticationStateTask = _defaultUnauthenticatedTask;

  public PersistentAuthenticationStateProvider(IPersistentStateAccessor persistentState)
  {
    var userInfo = persistentState.UserInfo;

    if (userInfo is null)
    {
      return;
    }

    var userClaims = userInfo.Claims.Select(x => new Claim(x.Type, x.Value));

    Claim[] claims =
    [
      new(ClaimTypes.NameIdentifier, userInfo.UserId),
      new(ClaimTypes.Name, userInfo.Email),
      new(ClaimTypes.Email, userInfo.Email),
      ..userClaims
    ];

    var identity = new ClaimsIdentity(claims, nameof(PersistentAuthenticationStateProvider));

    _authenticationStateTask = Task.FromResult(new AuthenticationState(new ClaimsPrincipal(identity)));
  }

  public override Task<AuthenticationState> GetAuthenticationStateAsync()
  {
    return _authenticationStateTask;
  }
}