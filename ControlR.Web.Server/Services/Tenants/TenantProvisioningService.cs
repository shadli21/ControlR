using ControlR.Web.Server.Primitives;

namespace ControlR.Web.Server.Services.Tenants;

public interface ITenantProvisioningService
{
  Task<HttpResult<TenantResult>> CreateTenant(string name, CancellationToken cancellationToken);
  Task<HttpResult> DeleteTenant(Guid id, CancellationToken cancellationToken);
  Task<HttpResult<TenantResult>> GetTenant(Guid id, CancellationToken cancellationToken);
  Task<HttpResult<TenantResult>> UpdateTenant(Guid id, string name, CancellationToken cancellationToken);
}

public class TenantProvisioningService(
  IDbContextFactory<AppDb> dbContextFactory,
  ILogger<TenantProvisioningService> logger) : ITenantProvisioningService
{
  public async Task<HttpResult<TenantResult>> CreateTenant(string name, CancellationToken cancellationToken)
  {
    if (string.IsNullOrWhiteSpace(name))
    {
      return HttpResult.Fail<TenantResult>(HttpResultErrorCode.BadRequest, "Tenant name is required.");
    }

    try
    {
      await using var appDb = await dbContextFactory.CreateDbContextAsync(cancellationToken);

      var tenant = new Tenant
      {
        Name = name
      };

      appDb.Tenants.Add(tenant);
      await appDb.SaveChangesAsync(cancellationToken);

      return HttpResult.Ok(ToResult(tenant));
    }
    catch (Exception ex)
    {
      logger.LogError(ex, "Failed to provision tenant {TenantName}.", name);
      return HttpResult.Fail<TenantResult>(ex, HttpResultErrorCode.InternalServerError, "Failed to provision tenant.");
    }
  }

  public async Task<HttpResult> DeleteTenant(Guid id, CancellationToken cancellationToken)
  {
    try
    {
      await using var appDb = await dbContextFactory.CreateDbContextAsync(cancellationToken);

      var tenant = await appDb.Tenants.FirstOrDefaultAsync(x => x.Id == id, cancellationToken);
      if (tenant is null)
      {
        return HttpResult.Fail(HttpResultErrorCode.NotFound, "Tenant not found.");
      }

      await appDb.PermissionAssignments
        .Where(x => x.OwningTenantId == id)
        .ExecuteDeleteAsync(cancellationToken);

      await appDb.AuthorizationChangeLogs
        .Where(x => x.OwningTenantId == id)
        .ExecuteDeleteAsync(cancellationToken);

      appDb.Tenants.Remove(tenant);
      await appDb.SaveChangesAsync(cancellationToken);

      return HttpResult.Ok();
    }
    catch (Exception ex)
    {
      logger.LogError(ex, "Failed to delete tenant {TenantId}.", id);
      return HttpResult.Fail(ex, HttpResultErrorCode.InternalServerError, "Failed to delete tenant.");
    }
  }

  public async Task<HttpResult<TenantResult>> GetTenant(Guid id, CancellationToken cancellationToken)
  {
    await using var appDb = await dbContextFactory.CreateDbContextAsync(cancellationToken);

    var tenant = await appDb.Tenants
      .AsNoTracking()
      .FirstOrDefaultAsync(x => x.Id == id, cancellationToken);

    if (tenant is null)
    {
      return HttpResult.Fail<TenantResult>(HttpResultErrorCode.NotFound, "Tenant not found.");
    }

    return HttpResult.Ok(ToResult(tenant));
  }

  public async Task<HttpResult<TenantResult>> UpdateTenant(
    Guid id,
    string name,
    CancellationToken cancellationToken)
  {
    if (string.IsNullOrWhiteSpace(name))
    {
      return HttpResult.Fail<TenantResult>(HttpResultErrorCode.BadRequest, "Tenant name is required.");
    }

    try
    {
      await using var appDb = await dbContextFactory.CreateDbContextAsync(cancellationToken);

      var tenant = await appDb.Tenants.FirstOrDefaultAsync(x => x.Id == id, cancellationToken);
      if (tenant is null)
      {
        return HttpResult.Fail<TenantResult>(HttpResultErrorCode.NotFound, "Tenant not found.");
      }

      tenant.Name = name;
      await appDb.SaveChangesAsync(cancellationToken);

      return HttpResult.Ok(ToResult(tenant));
    }
    catch (Exception ex)
    {
      logger.LogError(ex, "Failed to update tenant {TenantId}.", id);
      return HttpResult.Fail<TenantResult>(ex, HttpResultErrorCode.InternalServerError, "Failed to update tenant.");
    }
  }

  private static TenantResult ToResult(Tenant tenant)
  {
    return new TenantResult(
      tenant.Id,
      tenant.Name ?? string.Empty);
  }
}
