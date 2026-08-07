using ControlR.Libraries.Api.Contracts.Constants;
using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Options;

namespace ControlR.Web.Server.Tests.V1;

public class V1DtoLimitsTests
{
  [Fact]
  public void LogonTokenGrantCleanupCutoff_Exceeds_MaxTokenLifetime()
  {
    // Orphaned-grant cleanup must not remove grants while a token (or the cookie session that
    // outlives it) can still be active, so the default cutoff must comfortably exceed the maximum
    // token lifetime. This guards the invariant documented on AppOptions.LogonTokenGrantCleanupAfterDays.
    var cutoffDays = new AppOptions().LogonTokenGrantCleanupAfterDays;
    var maxLifetimeDays = (double)DtoLimits.ExpirationMinutesMax / 1440;
    Assert.True(
      cutoffDays >= maxLifetimeDays * 2,
      $"Default grant cleanup cutoff ({cutoffDays} days) must comfortably exceed the max logon token lifetime ({maxLifetimeDays} days). " +
      $"Raise AppOptions.{nameof(AppOptions.LogonTokenGrantCleanupAfterDays)} or lower {nameof(DtoLimits.ExpirationMinutesMax)}.");
  }

  [Fact]
  public void LogonTokenPermissionsLimit_IsAtLeast_CatalogPermissionCount()
  {
    // Ensure that the logon token request limit is at least as large as the number of permissions in the catalog.
    Assert.True(
      PermissionCatalog.All.Count <= DtoLimits.PermissionsMaxLength,
      $"PermissionCatalog has {PermissionCatalog.All.Count} permissions, exceeding the logon token request limit of {DtoLimits.PermissionsMaxLength}. Increase {nameof(DtoLimits.PermissionsMaxLength)} before adding more permissions.");
  }
}
