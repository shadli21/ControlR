using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace ControlR.Web.Server.Data.Configuration;

// Carries the caller's tenant and user id into AppDb so the per-entity HasQueryFilter
// predicates in OnModelCreating can scope reads and writes to that user's own resources.
public class ClaimsDbContextOptionsExtension(ClaimsDbContextOptions options) : IDbContextOptionsExtension
{
  private readonly ClaimsDbContextOptions _options = options;

  public DbContextOptionsExtensionInfo Info => new ExtensionInfo(this);

  public ClaimsDbContextOptions Options => _options;

  // Key the model cache by this extension's tenant/user id so each claims variant gets
  // its own model with the right filter predicates. EF registers this service as Singleton.
  public void ApplyServices(IServiceCollection services)
  {
    services.Replace(ServiceDescriptor.Singleton<IModelCacheKeyFactory, ClaimsModelCacheKeyFactory>());
  }

  public void Validate(IDbContextOptions options) { }

  private sealed class ExtensionInfo(ClaimsDbContextOptionsExtension extension) : DbContextOptionsExtensionInfo(extension)
  {
    private readonly ClaimsDbContextOptionsExtension _extension = extension;

    private string? _logFragment;

    public override bool IsDatabaseProvider => false;
    public override string LogFragment
    {
      get
      {
        _logFragment ??= $"TenantId={_extension.Options.TenantId}";
        return _logFragment;
      }
    }

    // Collapse every claims variant onto one shared internal service provider so EF does
    // not build a new provider per tenant/user (ManyServiceProvidersCreatedWarning). Per-
    // variant models are still distinct because ClaimsModelCacheKeyFactory keys the cache
    // by claims.
    public override int GetServiceProviderHashCode() => 0;

    public override void PopulateDebugInfo(IDictionary<string, string> debugInfo)
    {
      if (Extension is not ClaimsDbContextOptionsExtension extension) return;
      debugInfo["Tenant:Id"] = $"{extension.Options.TenantId}";
      debugInfo["User:Id"] = $"{extension.Options.UserId}";
    }

    public override bool ShouldUseSameServiceProvider(DbContextOptionsExtensionInfo other)
    {
      return other is ExtensionInfo;
    }
  }
}
