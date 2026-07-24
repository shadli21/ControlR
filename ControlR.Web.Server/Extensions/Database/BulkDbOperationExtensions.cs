namespace ControlR.Web.Server.Extensions.Database;

public static class BulkDbOperationExtensions
{
  public static async Task<int> ExecuteDeleteCompatAsync<T>(
    this IQueryable<T> query,
    DbContext dbContext,
    CancellationToken cancellationToken = default) where T : class
  {
    if (dbContext.Database.IsRelational())
    {
      return await query.ExecuteDeleteAsync(cancellationToken);
    }

    var entities = await query.ToListAsync(cancellationToken);
    if (entities.Count == 0)
    {
      return 0;
    }

    dbContext.Set<T>().RemoveRange(entities);
    await dbContext.SaveChangesAsync(cancellationToken);
    return entities.Count;
  }

  public static async Task<int> ExecuteUpdateCompatAsync<T>(
    this IQueryable<T> query,
    DbContext dbContext,
    Func<IQueryable<T>, Task<int>> relationalUpdate,
    Action<T> inMemoryMutation,
    CancellationToken cancellationToken = default) where T : class
  {
    if (dbContext.Database.IsRelational())
    {
      return await relationalUpdate(query);
    }

    var entities = await query.ToListAsync(cancellationToken);
    if (entities.Count == 0)
    {
      return 0;
    }

    foreach (var entity in entities)
    {
      inMemoryMutation(entity);
    }

    await dbContext.SaveChangesAsync(cancellationToken);
    return entities.Count;
  }
}
