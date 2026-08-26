using ControlR.Libraries.Api.Contracts.Authz;
using ControlR.Web.Client.Startup;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace ControlR.Web.Client.Tests;

public class ClientAuthorizationRegistrationTests
{
  [Fact]
  public async Task ClientAuthorization_DoesNotRegisterResourceSpecificPolicies()
  {
    var services = new ServiceCollection();
    services.AddControlrClientAuthorization();
    services.AddLogging();

    using var provider = services.BuildServiceProvider();
    var policyProvider = provider.GetRequiredService<IAuthorizationPolicyProvider>();

    Assert.Null(await policyProvider.GetPolicyAsync(PolicyNames.RequireDeviceGroupAssignDevices));
    Assert.Null(await policyProvider.GetPolicyAsync(PolicyNames.RequireUserGroupAssignUsers));
  }

  [Fact]
  public async Task ClientAuthorization_RegistersExactlyClientDefinitions()
  {
    var services = new ServiceCollection();
    services.AddControlrClientAuthorization();
    services.AddLogging();

    using var provider = services.BuildServiceProvider();
    var policyProvider = provider.GetRequiredService<IAuthorizationPolicyProvider>();

    foreach (var (policyName, _) in PermissionPolicies.ClientDefinitions)
    {
      var policy = await policyProvider.GetPolicyAsync(policyName);
      Assert.NotNull(policy);

      var requirement = Assert.Single(policy.Requirements.OfType<ClaimsAuthorizationRequirement>());
      Assert.Equal(
        PermissionPolicies.ClientPolicyClaimType,
        requirement.ClaimType);
      Assert.Equal(policyName, Assert.Single(requirement.AllowedValues!));
    }
  }
}
