using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace ControlR.Web.Server.Data.Configuration;

public class ClaimsDbContextOptionsExtension(ClaimsDbContextOptions options) : IDbContextOptionsExtension
{
  private readonly ClaimsDbContextOptions _options = options;

  public DbContextOptionsExtensionInfo Info => new ExtensionInfo(this);

  public ClaimsDbContextOptions Options => _options;

  public void ApplyServices(IServiceCollection services)
  {
    // All claims variants share one internal EF service provider (see
    // ExtensionInfo.ShouldUseSameServiceProvider), so the in-memory provider's store and the
    // model cache live in a single provider. The model still varies per tenant/user because
    // ClaimsModelCacheKeyFactory keys it by this extension's claims — this keeps each
    // context's query filters correctly scoped even though they share a service provider.
    services.Replace(ServiceDescriptor.Scoped<IModelCacheKeyFactory, ClaimsModelCacheKeyFactory>());
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

    // The internal service provider is identical for every claims variant because this
    // extension registers no provider-specific services. Returning a constant keeps a single
    // shared provider (and therefore a single shared in-memory store + model cache). This is
    // required for the in-memory test harness: EF Core's in-memory provider scopes its store
    // to the internal service provider, so varying the provider by claims would isolate each
    // tenant's contexts into separate stores that cannot see data seeded by another scope.
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

/// <summary>
/// Keys the EF model by the claims configured on the context so each tenant/user variant gets
/// its own query-filtered model even though all variants share one service provider (and thus
/// one in-memory store and model cache).
/// </summary>
internal sealed class ClaimsModelCacheKeyFactory : IModelCacheKeyFactory
{
  public object Create(DbContext context, bool designTime = false)
  {
    var appDb = context as AppDb;
    return new ClaimsModelCacheKey(
      context.GetType(),
      designTime,
      appDb?.TenantId,
      appDb?.UserId);
  }

  private sealed record ClaimsModelCacheKey(
    Type ContextType,
    bool DesignTime,
    Guid? TenantId,
    Guid? UserId);
}
