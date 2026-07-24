using System.Security.Claims;

namespace ControlR.Web.Server.Authn;

public class AppUserClaimsPrincipalFactory(
  UserManager<AppUser> userManager,
  RoleManager<AppRole> roleManager,
  IOptions<IdentityOptions> optionsAccessor)
  : UserClaimsPrincipalFactory<AppUser, AppRole>(userManager, roleManager, optionsAccessor)
{
  protected override async Task<ClaimsIdentity> GenerateClaimsAsync(AppUser user)
  {
    var identity = await base.GenerateClaimsAsync(user);
    identity.AddClaim(new Claim(PrincipalClaimTypes.PrincipalType, PrincipalClaimTypes.User));
    identity.AddClaim(new Claim(PrincipalClaimTypes.PrincipalId, user.Id.ToString()));
    return identity;
  }
}
