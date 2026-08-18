using System.Security.Claims;

namespace ControlR.Web.Server.Authn;

/// <summary>
/// Extends the default Identity claims principal factory to emit the canonical
/// <c>controlr:principal:type</c> and <c>controlr:principal:id</c> claims on every
/// cookie and interactive-bearer principal. These claims are the canonical identity
/// source for the permission evaluator.
/// </summary>
public class AppUserClaimsPrincipalFactory(
  UserManager<AppUser> userManager,
  IOptions<IdentityOptions> optionsAccessor)
  : UserClaimsPrincipalFactory<AppUser>(userManager, optionsAccessor)
{
  protected override async Task<ClaimsIdentity> GenerateClaimsAsync(AppUser user)
  {
    var identity = await base.GenerateClaimsAsync(user);
    identity.AddClaim(new Claim(PrincipalClaimTypes.PrincipalType, PrincipalClaimValues.User));
    identity.AddClaim(new Claim(PrincipalClaimTypes.PrincipalId, user.Id.ToString()));
    return identity;
  }
}
