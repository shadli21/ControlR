namespace ControlR.Web.Server.Extensions.Database;

/// <summary>
/// Compatibility wrappers around EF Core bulk operations (<c>ExecuteDeleteAsync</c>,
/// <c>ExecuteUpdateAsync</c>) that fall back to load-and-mutate semantics when the
/// provider does not support relational bulk operations (e.g. EF InMemory in tests).
/// </summary>
public static class BulkDbOperationExtensions
{
  /// <summary>
  /// Executes a bulk delete, or falls back to load + RemoveRange + SaveChanges
  /// for non-relational providers.
  /// </summary>
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

  /// <summary>
  /// Executes a bulk update, or falls back to load + per-entity mutation + SaveChanges
  /// for non-relational providers.
  /// </summary>
  /// <param name="query">The query selecting entities to update.</param>
  /// <param name="dbContext">The owning DbContext (used to detect provider capabilities).</param>
  /// <param name="relationalUpdate">The relational bulk update delegate (e.g. ExecuteUpdateAsync call).</param>
  /// <param name="inMemoryMutation">Per-entity mutation applied when running against a non-relational provider.</param>
  /// <param name="cancellationToken">Cancellation token.</param>
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
