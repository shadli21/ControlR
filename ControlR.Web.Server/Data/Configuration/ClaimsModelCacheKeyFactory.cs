using Microsoft.EntityFrameworkCore.Infrastructure;

namespace ControlR.Web.Server.Data.Configuration;
/// <summary>
/// Keys the EF model by the claims configured on the context so each tenant/user variant gets
/// its own query-filtered model even though all variants share one service provider (and thus
/// one in-memory store and model cache).
/// </summary>
internal sealed class ClaimsModelCacheKeyFactory : IModelCacheKeyFactory
{
  public object Create(DbContext context, bool designTime = false)
  {
    if (context is not AppDb appDb)
    {
      throw new InvalidOperationException(
        $"ClaimsModelCacheKeyFactory can only be used with {nameof(AppDb)}.");
    }

    return new ClaimsModelCacheKey(
      context.GetType(),
      designTime,
      appDb.TenantId,
      appDb.UserId);
  }

  private sealed record ClaimsModelCacheKey(
    Type ContextType,
    bool DesignTime,
    Guid? TenantId,
    Guid? UserId);
}
