namespace ControlR.Web.Client.Startup;

public static class ClientAuthorizationExtensions
{
  public static IServiceCollection AddControlrClientAuthorization(this IServiceCollection services)
  {
    services.AddAuthorizationCore(options =>
    {
      foreach (var (policyName, definition) in PermissionPolicies.ClientDefinitions)
      {
        options.AddPolicy(policyName, policy => policy
          .RequireAuthenticatedUser()
          .RequireClaim(PermissionPolicies.ClientPolicyClaimType, policyName));
      }
    });

    return services;
  }
}
