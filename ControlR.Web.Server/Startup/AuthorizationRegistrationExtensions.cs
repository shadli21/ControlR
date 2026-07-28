using ControlR.Web.Server.Authn;
using ControlR.Web.Server.Authz;
using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Components.Account;
using ControlR.Web.Server.Services.Authorization;
using ControlR.Web.Server.Services.DeviceManagement;
using Microsoft.AspNetCore.Components.Authorization;

namespace ControlR.Web.Server.Startup;

public static class AuthorizationRegistrationExtensions
{
  public static void AddControlrAuthorization(this IHostApplicationBuilder hostBuilder)
  {
    hostBuilder.Services.AddCascadingAuthenticationState();
    hostBuilder.Services.AddScoped<IdentityRedirectManager>();
    hostBuilder.Services.AddScoped<AuthenticationStateProvider, IdentityRevalidatingAuthenticationStateProvider>();

    hostBuilder.Services.ConfigureApplicationCookie(options =>
    {
      options.Events.OnRedirectToLogin = context =>
      {
        // For API requests, return 401 instead of redirecting
        if (context.Request.Path.StartsWithSegments("/api"))
        {
          context.Response.StatusCode = StatusCodes.Status401Unauthorized;
          return Task.CompletedTask;
        }

        // For UI requests, redirect to the login page
        context.Response.Redirect(context.RedirectUri);
        return Task.CompletedTask;
      };

      options.Events.OnRedirectToAccessDenied = context =>
      {
        // For API requests, return 403 instead of redirecting
        if (context.Request.Path.StartsWithSegments("/api"))
        {
          context.Response.StatusCode = StatusCodes.Status403Forbidden;
          return Task.CompletedTask;
        }

        // For UI requests, redirect to the access-denied page
        context.Response.Redirect(context.RedirectUri);
        return Task.CompletedTask;
      };
    });

    var authorizationBuilder = hostBuilder.Services
      .AddAuthorizationBuilder()
      .SetDefaultPolicy(new AuthorizationPolicyBuilder()
        .AddAuthenticationSchemes(CustomSchemes.Dynamic)
        .RequireAuthenticatedUser()
        .Build())
      .AddPolicy(RequireServerServiceAccountPolicy.PolicyName, RequireServerServiceAccountPolicy.Create())
      .AddPolicy(CombinedAuthorizationPolicies.RequireServerOrTenantAdminPolicy, CombinedAuthorizationPolicies.CreateServerOrTenantAdmin())
      .AddPolicy(CombinedAuthorizationPolicies.RequireServerOrTenantAdminOrInstallerKeyManagerPolicy, CombinedAuthorizationPolicies.CreateServerOrTenantAdminOrInstallerKeyManager())
      .AddPolicy(DeviceAccessByDeviceResourcePolicy.PolicyName, DeviceAccessByDeviceResourcePolicy.Create());

    foreach (var (policyName, permissionName) in PermissionPolicies.PolicyToPermission)
    {
      authorizationBuilder.AddPolicy(policyName, policy => policy
        .AddAuthenticationSchemes(CustomSchemes.Dynamic)
        .RequireAuthenticatedUser()
        .RequirePermission(permissionName));
    }

    hostBuilder.Services.AddScoped<IAuthorizationHandler, ServiceProviderRequirementHandler>();
    hostBuilder.Services.AddScoped<IAuthorizationHandler, ServiceProviderAsyncRequirementHandler>();
    hostBuilder.Services.AddScoped<IAuthorizationHandler, PermissionRequirementHandler>();
    hostBuilder.Services.AddScoped<IDeviceAccessScopeResolver, PermissionDeviceScopeResolver>();
    hostBuilder.Services.AddScoped<IPermissionRuleResolver, PermissionRuleResolver>();
    hostBuilder.Services.AddScoped<IPermissionEvaluator, PermissionEvaluator>();
    hostBuilder.Services.AddSingleton<IRoleBundleResolver, RoleBundleResolver>();
  }
}